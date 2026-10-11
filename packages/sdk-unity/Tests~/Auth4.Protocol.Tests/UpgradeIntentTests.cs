using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using static Auth4.Protocol.Tests.Fixtures;

namespace Auth4.Protocol.Tests
{
    /// <summary>AUTH4D-68: UpgradeGuestAsync over the AUTH4D-67 upgrade-intent API.</summary>
    public sealed class UpgradeIntentTests
    {
        private const string Handle = "gui_IntentHandle00000000000000000000001";
        private const string PollSecret = "gps_PollSecret0000000000000000000000000000000001";
        private static readonly string IntentPath = "/t/" + TenantId + "/guest/upgrade-intent";
        private static readonly string TokenPath = IntentPath + "/token";
        private static readonly string UpgradeUri =
            Origin + "/login/upgrade?tenant_id=" + TenantId + "&client_id=" + ClientId + "&intent=" + Handle;

        private static string IntentCreated(int expiresIn = 600, string upgradeUri = null)
        {
            return "{\"intent\":\"" + Handle + "\",\"poll_secret\":\"" + PollSecret + "\"," +
                   "\"upgrade_uri\":\"" + (upgradeUri ?? UpgradeUri) + "\",\"expires_in\":" + expiresIn + ",\"interval\":5}";
        }

        private static string Upgraded(string userId = GuestUserId, string provider = "discord")
        {
            return TokenJson(
                "upgraded-access",
                "upgraded-refresh",
                "ses_Upgraded000000000001",
                "\"user_id\":\"" + userId + "\",\"identity\":{\"identity_id\":\"idn_Linked0000000000001\",\"provider\":\"" + provider + "\"}");
        }

        private static string Pending(int interval = 5)
        {
            return "{\"error\":\"authorization_pending\",\"interval\":" + interval + "}";
        }

        /// <summary>Guest creation, intent creation and a scripted sequence of poll responses.</summary>
        private static FakeTransport IntentServer(params Func<Auth4HttpResponse>[] polls)
        {
            var queue = new Queue<Func<Auth4HttpResponse>>(polls);
            return IntentServerWith(() => FakeTransport.Json(200, IntentCreated()), () => queue.Dequeue()());
        }

        private static FakeTransport IntentServerWith(Func<Auth4HttpResponse> create, Func<Auth4HttpResponse> poll)
        {
            return new FakeTransport(request =>
            {
                if (request.Path == "/t/" + TenantId + "/guest")
                {
                    return FakeTransport.Json(200, GuestCreated());
                }

                if (request.Path == IntentPath)
                {
                    return create();
                }

                if (request.Path == TokenPath)
                {
                    return poll();
                }

                if (request.Path == "/oauth/revoke")
                {
                    return FakeTransport.Json(200, string.Empty);
                }

                return FakeTransport.Json(404, Error("not_found"));
            });
        }

        private static Auth4Client Client(
            FakeTransport transport,
            FakeClock clock,
            FakeBrowser browser,
            ISecureStorageAdapter storage = null)
        {
            return new Auth4Client(new Auth4ClientOptions
            {
                TenantId = TenantId,
                ClientId = ClientId,
                AuthOrigin = Origin,
                Transport = transport,
                Clock = clock,
                SecureStorage = storage,
                BrowserLauncher = browser,
            });
        }

        [Test]
        public async Task OpensBrowserPollsAtServerIntervalAndSwapsTokens()
        {
            var storage = new FakeSecureStorage();
            var transport = IntentServer(
                () => FakeTransport.Json(400, Pending()),
                () => FakeTransport.Json(400, "{\"error\":\"slow_down\",\"interval\":10}"),
                () => FakeTransport.Json(400, Pending(10)),
                () => FakeTransport.Json(200, Upgraded()));
            var clock = new FakeClock();
            var browser = new FakeBrowser();
            var client = Client(transport, clock, browser, storage);
            var guest = await client.SignInAsGuestAsync();
            var guestStored = storage.Values.Values.Single();
            var changes = new List<Auth4Session>();
            client.SessionChanged += changes.Add;
            var progress = new List<GuestUpgradeProgress>();

            var result = await client.UpgradeGuestAsync(progress.Add);

            var create = transport.To(IntentPath).Single();
            Assert.That(create.Headers["Authorization"], Is.EqualTo("Bearer " + Token("guest-access")));
            Assert.That(create.Body, Is.EqualTo("{\"client_id\":\"" + ClientId + "\"}"));
            Assert.That(browser.Opened.Select(uri => uri.AbsoluteUri), Is.EqualTo(new[] { UpgradeUri }));

            var polls = transport.To(TokenPath).ToList();
            Assert.That(polls, Has.Count.EqualTo(4));
            foreach (var poll in polls)
            {
                Assert.That(poll.Headers.ContainsKey("Authorization"), Is.False);
                Assert.That(poll.Uri.Query, Is.Empty);
                Assert.That(poll.Body, Does.Contain("\"intent\":\"" + Handle + "\""));
                Assert.That(poll.Body, Does.Contain("\"poll_secret\":\"" + PollSecret + "\""));
            }

            // The first poll waits one interval; slow_down moves to the server's interval.
            Assert.That(clock.Delays.Select(delay => delay.TotalSeconds), Is.EqualTo(new double[] { 5, 5, 10, 10 }));

            Assert.That(result.Session.UserId, Is.EqualTo(guest.UserId));
            Assert.That(result.Session.IsGuest, Is.False);
            Assert.That(result.Session.SessionId, Is.EqualTo("ses_Upgraded000000000001"));
            Assert.That(result.Identity.Provider, Is.EqualTo("discord"));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("upgraded-access")));

            // One swap: no signed-out gap, and storage holds only the upgraded refresh token.
            Assert.That(changes, Has.Count.EqualTo(1));
            Assert.That(changes[0].IsGuest, Is.False);
            var stored = storage.Values.Values.Single();
            Assert.That(stored, Is.Not.EqualTo(guestStored));
            Assert.That(stored, Does.Contain(Token("upgraded-refresh")));
            Assert.That(stored, Does.Not.Contain(Token("guest-refresh")));
            Assert.That(stored, Does.Contain("\"guest\":\"false\""));
            Assert.That(stored, Does.Contain(GuestUserId));
            Assert.That(stored, Does.Not.Contain(PollSecret));

            Assert.That(progress.First().Stage, Is.EqualTo(GuestUpgradeStage.OpeningBrowser));
            Assert.That(progress.First().UpgradeUri.AbsoluteUri, Is.EqualTo(UpgradeUri));
            Assert.That(progress.Last().Stage, Is.EqualTo(GuestUpgradeStage.Completed));
            Assert.That(progress.Count(item => item.Stage == GuestUpgradeStage.WaitingForPlayer), Is.EqualTo(4));
            Assert.That(transport.To("/oauth/revoke"), Is.Empty);
        }

        [Test]
        public async Task SlowDownWithoutIntervalAddsFiveSeconds()
        {
            var transport = IntentServer(
                () => FakeTransport.Json(429, Error("slow_down")),
                () => FakeTransport.Json(200, Upgraded()));
            var clock = new FakeClock();
            var client = Client(transport, clock, new FakeBrowser());
            await client.SignInAsGuestAsync();

            await client.UpgradeGuestAsync();

            Assert.That(clock.Delays.Select(delay => delay.TotalSeconds), Is.EqualTo(new double[] { 5, 10 }));
        }

        [Test]
        public async Task TransientPollFailuresBackOffAndRecover()
        {
            var transport = IntentServer(
                () => FakeTransport.Json(503, Error("temporarily_unavailable")),
                () => throw new System.IO.IOException("offline"),
                () => FakeTransport.Json(200, Upgraded()));
            var clock = new FakeClock();
            var client = Client(transport, clock, new FakeBrowser());
            await client.SignInAsGuestAsync();

            var result = await client.UpgradeGuestAsync();

            Assert.That(result.Session.IsGuest, Is.False);
            Assert.That(clock.Delays.Select(delay => delay.TotalSeconds), Is.EqualTo(new double[] { 5, 10, 20 }));
        }

        [TestCase("identity_in_use", 400, GuestUpgradeFailure.Conflict)]
        [TestCase("access_denied", 400, GuestUpgradeFailure.Denied)]
        [TestCase("expired_token", 400, GuestUpgradeFailure.Expired)]
        public async Task TerminalPollErrorsAreTypedAndKeepTheGuest(string error, int status, GuestUpgradeFailure reason)
        {
            var storage = new FakeSecureStorage();
            var transport = IntentServer(
                () => FakeTransport.Json(400, Pending()),
                () => FakeTransport.Json(status, Error(error)));
            var client = Client(transport, new FakeClock(), new FakeBrowser(), storage);
            await client.SignInAsGuestAsync();
            var guestStored = storage.Values.Values.Single();

            var failure = Assert.ThrowsAsync<Auth4GuestUpgradeException>(() => client.UpgradeGuestAsync());

            Assert.That(failure.Reason, Is.EqualTo(reason));
            Assert.That(failure.Error, Is.EqualTo(error));
            Assert.That(failure, Is.InstanceOf<Auth4Exception>());
            Assert.That(client.CurrentSession.IsGuest, Is.True);
            Assert.That(client.CurrentSession.UserId, Is.EqualTo(GuestUserId));
            Assert.That(storage.Values.Values.Single(), Is.EqualTo(guestStored));
            Assert.That(transport.To(TokenPath).Count(), Is.EqualTo(2));
        }

        [Test]
        public async Task StopsPollingAtTheIntentExpiry()
        {
            var transport = IntentServerWith(
                () => FakeTransport.Json(200, IntentCreated(expiresIn: 12)),
                () => FakeTransport.Json(400, Pending()));
            var client = Client(transport, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4GuestUpgradeException>(() => client.UpgradeGuestAsync());

            Assert.That(failure.Reason, Is.EqualTo(GuestUpgradeFailure.Expired));
            Assert.That(transport.To(TokenPath).Count(), Is.EqualTo(2));
            Assert.That(client.CurrentSession.IsGuest, Is.True);
        }

        [Test]
        public async Task CancellationIsTypedAndStopsPolling()
        {
            var transport = IntentServer(
                () => FakeTransport.Json(400, Pending()),
                () => FakeTransport.Json(400, Error("expired_token")));
            var clock = new FakeClock();
            var client = Client(transport, clock, new FakeBrowser());
            await client.SignInAsGuestAsync();
            using var cancellation = new CancellationTokenSource();
            clock.OnDelay = count =>
            {
                if (count == 2)
                {
                    cancellation.Cancel();
                }
            };

            var failure = Assert.ThrowsAsync<Auth4GuestUpgradeException>(
                () => client.UpgradeGuestAsync(null, cancellation.Token));

            Assert.That(failure.Reason, Is.EqualTo(GuestUpgradeFailure.Cancelled));
            Assert.That(failure.InnerException, Is.InstanceOf<OperationCanceledException>());
            Assert.That(transport.To(TokenPath).Count(), Is.EqualTo(1));
            Assert.That(client.CurrentSession.IsGuest, Is.True);

            // The client can start a new upgrade afterwards.
            clock.OnDelay = null;
            var next = Assert.ThrowsAsync<Auth4GuestUpgradeException>(() => client.UpgradeGuestAsync());
            Assert.That(next.Reason, Is.EqualTo(GuestUpgradeFailure.Expired));
            Assert.That(transport.To(IntentPath).Count(), Is.EqualTo(2));
        }

        [Test]
        public async Task WithoutASupportedBrowserNothingIsSent()
        {
            foreach (var browser in new[] { null, new FakeBrowser { IsSupported = false } })
            {
                var transport = IntentServer();
                var client = Client(transport, new FakeClock(), browser);
                await client.SignInAsGuestAsync();

                Assert.ThrowsAsync<PlatformNotSupportedException>(() => client.UpgradeGuestAsync());
                Assert.That(transport.To(IntentPath), Is.Empty);
                Assert.That(browser?.Opened ?? new List<Uri>(), Is.Empty);
            }
        }

        [Test]
        public async Task OnlyAGuestCanUpgrade()
        {
            var transport = IntentServer(() => FakeTransport.Json(200, Upgraded()));
            var client = Client(transport, new FakeClock(), new FakeBrowser());

            var signedOut = Assert.ThrowsAsync<Auth4Exception>(() => client.UpgradeGuestAsync());
            Assert.That(signedOut.Error, Is.EqualTo("login_required"));

            await client.SignInAsGuestAsync();
            await client.UpgradeGuestAsync();
            Assert.ThrowsAsync<InvalidOperationException>(() => client.UpgradeGuestAsync());
            Assert.That(transport.To(IntentPath).Count(), Is.EqualTo(1));
        }

        [Test]
        public async Task RejectsAnUpgradePageOnAnotherOrigin()
        {
            var transport = IntentServerWith(
                () => FakeTransport.Json(200, IntentCreated(upgradeUri: "https://evil.example.test/login/upgrade?intent=" + Handle)),
                () => FakeTransport.Json(400, Pending()));
            var browser = new FakeBrowser();
            var client = Client(transport, new FakeClock(), browser);
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4Exception>(() => client.UpgradeGuestAsync());

            Assert.That(failure.Error, Is.EqualTo("invalid_response"));
            Assert.That(browser.Opened, Is.Empty);
            Assert.That(transport.To(TokenPath), Is.Empty);
        }

        [Test]
        public async Task AnotherUserInTheResultIsRevokedAndCleared()
        {
            var transport = IntentServer(() => FakeTransport.Json(200, Upgraded(userId: "usr_SomeoneElse0000000001")));
            var client = Client(transport, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4Exception>(() => client.UpgradeGuestAsync());

            Assert.That(failure.Error, Is.EqualTo("invalid_response"));
            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(transport.To("/oauth/revoke").Single().Form["token"], Is.EqualTo(Token("upgraded-refresh")));
        }

        [Test]
        public async Task SignOutDuringTheUpgradeWins()
        {
            Auth4Client client = null;
            var transport = IntentServer(
                () => FakeTransport.Json(400, Pending()),
                () => FakeTransport.Json(200, Upgraded()));
            var clock = new FakeClock();
            client = Client(transport, clock, new FakeBrowser());
            await client.SignInAsGuestAsync();
            clock.OnDelay = count =>
            {
                if (count == 2)
                {
                    client.SignOutAsync().GetAwaiter().GetResult();
                }
            };

            Assert.ThrowsAsync<InvalidOperationException>(() => client.UpgradeGuestAsync());

            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(
                transport.To("/oauth/revoke").Select(request => request.Form["token"]),
                Is.EqualTo(new[] { Token("guest-refresh"), Token("upgraded-refresh") }));
        }

        [Test]
        public async Task ARevokedGuestRefreshDoesNotLoseTheUpgrade()
        {
            // The page completed (revoking the guest session) and the game refreshed before polling.
            var transport = new FakeTransport(request =>
            {
                switch (request.Path)
                {
                    case "/oauth/token":
                        return FakeTransport.Json(400, Error("invalid_grant"));
                    case "/oauth/revoke":
                        return FakeTransport.Json(200, string.Empty);
                }

                if (request.Path == IntentPath)
                {
                    return FakeTransport.Json(200, IntentCreated());
                }

                return request.Path == TokenPath
                    ? FakeTransport.Json(200, Upgraded())
                    : FakeTransport.Json(200, GuestCreated());
            });
            var clock = new FakeClock();
            var client = Client(transport, clock, new FakeBrowser());
            await client.SignInAsGuestAsync();
            clock.OnDelay = _ => Assert.ThrowsAsync<Auth4SessionExpiredException>(() => client.RefreshAsync());

            var result = await client.UpgradeGuestAsync();

            Assert.That(result.Session.UserId, Is.EqualTo(GuestUserId));
            Assert.That(client.CurrentSession.IsGuest, Is.False);
        }

        [Test]
        public async Task OneUpgradeAtATime()
        {
            Auth4Client client = null;
            Exception concurrent = null;
            var browser = new FakeBrowser
            {
                OnOpen = _ => concurrent = Assert.ThrowsAsync<InvalidOperationException>(() => client.UpgradeGuestAsync()),
            };
            client = Client(IntentServer(() => FakeTransport.Json(200, Upgraded())), new FakeClock(), browser);
            await client.SignInAsGuestAsync();

            await client.UpgradeGuestAsync();

            Assert.That(concurrent, Is.Not.Null);
        }

        [Test]
        public async Task OpensTheHostedPageWithTheChosenProviderFirst()
        {
            // Provider hints ask the page to offer the selected provider first.
            var browser = new FakeBrowser();
            var client = Client(IntentServer(() => FakeTransport.Json(200, Upgraded(provider: "steam"))), new FakeClock(), browser);
            await client.SignInAsGuestAsync();
            var progress = new List<GuestUpgradeProgress>();

            var result = await client.UpgradeGuestAsync(Auth4Provider.Steam, progress.Add);

            Assert.That(browser.Opened.Select(uri => uri.AbsoluteUri), Is.EqualTo(new[] { UpgradeUri + "&provider=steam" }));
            Assert.That(progress.First().UpgradeUri.AbsoluteUri, Is.EqualTo(UpgradeUri + "&provider=steam"));
            Assert.That(result.Identity.Provider, Is.EqualTo("steam"));
            Assert.That(result.Session.IsGuest, Is.False);

            var discordBrowser = new FakeBrowser();
            var discordClient = Client(IntentServer(() => FakeTransport.Json(200, Upgraded())), new FakeClock(), discordBrowser);
            await discordClient.SignInAsGuestAsync();
            await discordClient.UpgradeGuestAsync(Auth4Provider.Discord);
            Assert.That(discordBrowser.Opened.Single().AbsoluteUri, Is.EqualTo(UpgradeUri + "&provider=discord"));

            // AUTH4D-147: "Save progress with Epic Games".
            var epicBrowser = new FakeBrowser();
            var epicClient = Client(IntentServer(() => FakeTransport.Json(200, Upgraded(provider: "epic"))), new FakeClock(), epicBrowser);
            await epicClient.SignInAsGuestAsync();
            var epic = await epicClient.UpgradeGuestAsync(Auth4Provider.Epic);
            Assert.That(epicBrowser.Opened.Single().AbsoluteUri, Is.EqualTo(UpgradeUri + "&provider=epic"));
            Assert.That(epic.Identity.Provider, Is.EqualTo("epic"));

            foreach (var (provider, name) in new[]
            {
                (Auth4Provider.Google, "google"),
                (Auth4Provider.Apple, "apple"),
                (Auth4Provider.Microsoft, "microsoft"),
            })
            {
                var presetBrowser = new FakeBrowser();
                var presetClient = Client(IntentServer(() => FakeTransport.Json(200, Upgraded())), new FakeClock(), presetBrowser);
                await presetClient.SignInAsGuestAsync();
                await presetClient.UpgradeGuestAsync(provider);
                Assert.That(presetBrowser.Opened.Single().AbsoluteUri, Is.EqualTo(UpgradeUri + "&provider=" + name));
            }
        }

        [Test]
        public async Task RejectsAnUndefinedProviderBeforeCreatingAnIntent()
        {
            var browser = new FakeBrowser();
            var transport = IntentServer(() => FakeTransport.Json(200, Upgraded()));
            var client = Client(transport, new FakeClock(), browser);
            await client.SignInAsGuestAsync();

            Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.UpgradeGuestAsync((Auth4Provider)99));
            Assert.That(transport.To(IntentPath), Is.Empty);
            Assert.That(browser.Opened, Is.Empty);

            // The rejected call left no upgrade in flight.
            await client.UpgradeGuestAsync();
            Assert.That(browser.Opened.Single().AbsoluteUri, Is.EqualTo(UpgradeUri));
        }
    }

    internal sealed class FakeBrowser : IAuth4BrowserLauncher
    {
        public List<Uri> Opened { get; } = new List<Uri>();

        public bool IsSupported { get; set; } = true;

        public Action<Uri> OnOpen { get; set; }

        public void Open(Uri uri)
        {
            Opened.Add(uri);
            OnOpen?.Invoke(uri);
        }
    }
}
