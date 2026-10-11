using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using static Auth4.Protocol.Tests.Fixtures;

namespace Auth4.Protocol.Tests
{
    /// <summary>AUTH4D-69: UpgradeGuestAsync routed to the hosted window protocol in WebGL builds.</summary>
    public sealed class UpgradeWindowTests
    {
        private static readonly string WindowUri =
            Origin + "/login/upgrade?tenant_id=" + TenantId + "&client_id=" + ClientId;

        private static string Upgraded(string userId = GuestUserId, string provider = "email")
        {
            return TokenJson(
                "upgraded-access",
                "upgraded-refresh",
                "ses_Upgraded000000000001",
                "\"user_id\":\"" + userId + "\",\"identity\":{\"identity_id\":\"idn_Linked0000000000001\",\"provider\":\"" + provider + "\"}");
        }

        private static string Ready(string tenantId = TenantId, string clientId = ClientId)
        {
            return "{\"tenant_id\":\"" + tenantId + "\",\"client_id\":\"" + clientId + "\"}";
        }

        private static FakeTransport GuestServer()
        {
            return new FakeTransport(request =>
            {
                if (request.Path == "/t/" + TenantId + "/guest")
                {
                    return FakeTransport.Json(200, GuestCreated());
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
            FakeUpgradeWindow window,
            FakeBrowser browser = null,
            ISecureStorageAdapter storage = null)
        {
            return new Auth4Client(new Auth4ClientOptions
            {
                TenantId = TenantId,
                ClientId = ClientId,
                AuthOrigin = Origin,
                Transport = transport,
                Clock = new FakeClock(),
                SecureStorage = storage,
                BrowserLauncher = browser,
                UpgradeWindow = window,
            });
        }

        private static async Task<T> Within<T>(Task<T> task)
        {
            if (await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5))) != task)
            {
                Assert.Fail("The upgrade did not finish.");
            }

            return await task;
        }

        private static async Task<TException> ThrowsWithin<TException>(Task task)
            where TException : Exception
        {
            if (await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(5))) != task)
            {
                Assert.Fail("The upgrade did not finish.");
            }

            return Assert.ThrowsAsync<TException>(() => task);
        }

        [Test]
        public async Task OpensTheWindowSynchronouslyAndSwapsTokensOnCompletion()
        {
            var storage = new FakeSecureStorage();
            var transport = GuestServer();
            var window = new FakeUpgradeWindow();
            var browser = new FakeBrowser();
            var client = Client(transport, window, browser, storage);
            var guest = await client.SignInAsGuestAsync();
            var changes = new List<Auth4Session>();
            client.SessionChanged += changes.Add;
            var progress = new List<GuestUpgradeProgress>();

            var upgrade = client.UpgradeGuestAsync(progress.Add);

            // Opened before UpgradeGuestAsync first awaits, so a browser gesture still applies.
            Assert.That(window.Opened.Select(open => open.Uri.AbsoluteUri), Is.EqualTo(new[] { WindowUri }));
            Assert.That(window.Opened.Single().AuthOrigin, Is.EqualTo(Origin));
            Assert.That(browser.Opened, Is.Empty);
            Assert.That(transport.Requests.Select(request => request.Path), Has.None.Contains("upgrade-intent"));

            window.Send(Auth4UpgradeWindowEvent.Opened);
            window.Send(Auth4UpgradeWindowEvent.Ready, Ready());
            Assert.That(window.Tokens, Is.EqualTo(new[] { Token("guest-access") }));

            window.Send(Auth4UpgradeWindowEvent.Complete, Upgraded());
            var result = await Within(upgrade);

            Assert.That(result.Session.UserId, Is.EqualTo(guest.UserId));
            Assert.That(result.Session.IsGuest, Is.False);
            Assert.That(result.Session.SessionId, Is.EqualTo("ses_Upgraded000000000001"));
            Assert.That(result.Identity.Provider, Is.EqualTo("email"));
            Assert.That(result.Identity.IdentityId, Is.EqualTo("idn_Linked0000000000001"));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("upgraded-access")));
            Assert.That(changes, Has.Count.EqualTo(1));
            Assert.That(storage.Values.Values.Single(), Does.Contain(Token("upgraded-refresh")));
            Assert.That(
                progress.Select(item => item.Stage),
                Is.EqualTo(new[]
                {
                    GuestUpgradeStage.OpeningBrowser,
                    GuestUpgradeStage.WaitingForPlayer,
                    GuestUpgradeStage.Completed,
                }));
            Assert.That(progress.All(item => item.UpgradeUri.AbsoluteUri == WindowUri), Is.True);

            // The page keeps showing its outcome; the game only stops listening.
            Assert.That(window.Released, Is.True);
            Assert.That(window.Closed, Is.False);

            // No token reached a URL.
            foreach (var request in transport.Requests)
            {
                Assert.That(request.Uri.Query, Does.Not.Contain("access"));
            }
        }

        [Test]
        public async Task AnswersEachReadyWithAFreshTokenOnlyForItsOwnTenantAndClient()
        {
            var window = new FakeUpgradeWindow();
            var client = Client(GuestServer(), window);
            await client.SignInAsGuestAsync();
            var upgrade = client.UpgradeGuestAsync();

            window.Send(Auth4UpgradeWindowEvent.Ready, Ready(tenantId: "ten_OtherTenant000000001"));
            window.Send(Auth4UpgradeWindowEvent.Ready, Ready(clientId: "cli_OtherClient000000001"));
            window.Send(Auth4UpgradeWindowEvent.Ready, "not json");
            Assert.That(window.Tokens, Is.Empty);

            // The Discord round trip reloads the page, which asks again.
            window.Send(Auth4UpgradeWindowEvent.Ready, Ready());
            window.Send(Auth4UpgradeWindowEvent.Ready, Ready());
            Assert.That(window.Tokens, Is.EqualTo(new[] { Token("guest-access"), Token("guest-access") }));
            Assert.That(upgrade.IsCompleted, Is.False);

            window.Send(Auth4UpgradeWindowEvent.Complete, Upgraded(provider: "discord"));
            Assert.That((await Within(upgrade)).Identity.Provider, Is.EqualTo("discord"));
        }

        [Test]
        public async Task OpensTheWindowWithTheChosenProviderFirst()
        {
            // Provider hints work through the WebGL window and the native browser launcher.
            foreach (var (provider, name) in new[]
            {
                (Auth4Provider.Steam, "steam"),
                (Auth4Provider.Discord, "discord"),
                (Auth4Provider.Epic, "epic"),
                (Auth4Provider.Google, "google"),
                (Auth4Provider.Apple, "apple"),
                (Auth4Provider.Microsoft, "microsoft"),
            })
            {
                var window = new FakeUpgradeWindow();
                var client = Client(GuestServer(), window);
                await client.SignInAsGuestAsync();

                var upgrade = client.UpgradeGuestAsync(provider);

                Assert.That(window.Opened.Single().Uri.AbsoluteUri, Is.EqualTo(WindowUri + "&provider=" + name));
                window.Send(Auth4UpgradeWindowEvent.Ready, Ready());
                Assert.That(window.Opened.Single().Uri.AbsoluteUri, Does.Not.Contain(Token("guest-access")));
                window.Send(Auth4UpgradeWindowEvent.Complete, Upgraded(provider: name));
                Assert.That((await Within(upgrade)).Identity.Provider, Is.EqualTo(name));
            }
        }

        [Test]
        public async Task FallsBackToTheBrowserLauncherWhenTheWindowIsUnsupported()
        {
            var window = new FakeUpgradeWindow { IsSupported = false };
            var browser = new FakeBrowser();
            var transport = new FakeTransport(request =>
            {
                if (request.Path == "/t/" + TenantId + "/guest")
                {
                    return FakeTransport.Json(200, GuestCreated());
                }

                // The native path starts with an upgrade intent; failing it ends the test early.
                return FakeTransport.Json(503, Error("temporarily_unavailable"));
            });
            var client = Client(transport, window, browser);
            await client.SignInAsGuestAsync();

            Assert.ThrowsAsync<Auth4Exception>(() => client.UpgradeGuestAsync());
            Assert.That(transport.To("/t/" + TenantId + "/guest/upgrade-intent").Count(), Is.EqualTo(1));
            Assert.That(window.Opened, Is.Empty);
        }

        [Test]
        public async Task ThrowsPlatformNotSupportedWithoutAWindowOrLauncher()
        {
            var transport = GuestServer();
            var client = Client(transport, new FakeUpgradeWindow { IsSupported = false }, new FakeBrowser { IsSupported = false });
            await client.SignInAsGuestAsync();

            Assert.ThrowsAsync<PlatformNotSupportedException>(() => client.UpgradeGuestAsync());
        }

        [Test]
        public async Task OnlyAGuestCanUpgradeAndNothingOpensOtherwise()
        {
            var window = new FakeUpgradeWindow();
            var client = Client(GuestServer(), window);

            var signedOut = Assert.ThrowsAsync<Auth4Exception>(() => client.UpgradeGuestAsync());
            Assert.That(signedOut.Error, Is.EqualTo("login_required"));

            await client.SignInAsGuestAsync();
            var upgrade = client.UpgradeGuestAsync();
            window.Send(Auth4UpgradeWindowEvent.Complete, Upgraded());
            await Within(upgrade);

            Assert.ThrowsAsync<InvalidOperationException>(() => client.UpgradeGuestAsync());
            Assert.That(window.Opened, Has.Count.EqualTo(1));
        }

        [Test]
        public async Task RejectsASecondUpgradeWhileOneIsPending()
        {
            var window = new FakeUpgradeWindow();
            var client = Client(GuestServer(), window);
            await client.SignInAsGuestAsync();
            var upgrade = client.UpgradeGuestAsync();

            Assert.ThrowsAsync<InvalidOperationException>(() => client.UpgradeGuestAsync());
            Assert.That(window.Opened, Has.Count.EqualTo(1));

            window.Send(Auth4UpgradeWindowEvent.Closed);
            await ThrowsWithin<Auth4GuestUpgradeException>(upgrade);
        }

        [TestCase(Auth4UpgradeWindowEvent.Cancelled, null, GuestUpgradeFailure.Denied, "access_denied")]
        [TestCase(Auth4UpgradeWindowEvent.Closed, null, GuestUpgradeFailure.WindowClosed, "window_closed")]
        [TestCase(Auth4UpgradeWindowEvent.Failed, "invalid_session", GuestUpgradeFailure.SessionEnded, "invalid_session")]
        public async Task EndsOnFinalWindowMessagesAndKeepsTheGuest(
            Auth4UpgradeWindowEvent kind,
            string data,
            GuestUpgradeFailure reason,
            string error)
        {
            var window = new FakeUpgradeWindow();
            var client = Client(GuestServer(), window);
            await client.SignInAsGuestAsync();
            var upgrade = client.UpgradeGuestAsync();

            window.Send(kind, data);
            var failure = await ThrowsWithin<Auth4GuestUpgradeException>(upgrade);

            Assert.That(failure.Reason, Is.EqualTo(reason));
            Assert.That(failure.Error, Is.EqualTo(error));
            Assert.That(window.Released, Is.True);
            Assert.That(client.CurrentSession.IsGuest, Is.True);
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("guest-access")));

            // Later messages are ignored.
            window.Send(Auth4UpgradeWindowEvent.Complete, Upgraded());
            Assert.That(client.CurrentSession.IsGuest, Is.True);
        }

        [Test]
        public async Task ReportsABlockedPopupEvenBeforeOpenReturns()
        {
            var window = new FakeUpgradeWindow { OnOpen = send => send(Auth4UpgradeWindowEvent.Blocked, null) };
            var client = Client(GuestServer(), window);
            await client.SignInAsGuestAsync();

            var failure = await ThrowsWithin<Auth4GuestUpgradeException>(client.UpgradeGuestAsync());

            Assert.That(failure.Reason, Is.EqualTo(GuestUpgradeFailure.PopupBlocked));
            Assert.That(failure.Error, Is.EqualTo("popup_blocked"));
            Assert.That(window.Released, Is.True);
            Assert.That(client.CurrentSession.IsGuest, Is.True);
        }

        [Test]
        public async Task KeepsAnsweringAfterIdentityInUseAndInstallsALaterCompletion()
        {
            var window = new FakeUpgradeWindow();
            var client = Client(GuestServer(), window);
            await client.SignInAsGuestAsync();
            var changes = new List<Auth4Session>();
            client.SessionChanged += changes.Add;
            var upgrade = client.UpgradeGuestAsync();

            window.Send(Auth4UpgradeWindowEvent.Ready, Ready());
            window.Send(Auth4UpgradeWindowEvent.Failed, "identity_in_use");
            var conflict = await ThrowsWithin<Auth4GuestUpgradeException>(upgrade);
            Assert.That(conflict.Reason, Is.EqualTo(GuestUpgradeFailure.Conflict));
            Assert.That(client.CurrentSession.IsGuest, Is.True);
            Assert.That(window.Released, Is.False);

            // The player links a different credential in the same window.
            window.Send(Auth4UpgradeWindowEvent.Ready, Ready());
            Assert.That(window.Tokens, Has.Count.EqualTo(2));
            window.Send(Auth4UpgradeWindowEvent.Complete, Upgraded());

            Assert.That(changes, Has.Count.EqualTo(1));
            Assert.That(changes[0].IsGuest, Is.False);
            Assert.That(changes[0].UserId, Is.EqualTo(GuestUserId));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("upgraded-access")));
            Assert.That(window.Released, Is.True);
        }

        [Test]
        public async Task ANewUpgradeStopsAWindowLeftOpenAfterAConflict()
        {
            var first = new FakeUpgradeWindow();
            var client = Client(GuestServer(), first);
            await client.SignInAsGuestAsync();
            var upgrade = client.UpgradeGuestAsync();
            first.Send(Auth4UpgradeWindowEvent.Failed, "identity_in_use");
            await ThrowsWithin<Auth4GuestUpgradeException>(upgrade);

            var second = client.UpgradeGuestAsync();

            Assert.That(first.Handles[0].Released, Is.True);
            Assert.That(first.Opened, Has.Count.EqualTo(2));
            first.Send(Auth4UpgradeWindowEvent.Complete, Upgraded());
            Assert.That((await Within(second)).Session.IsGuest, Is.False);
        }

        [Test]
        public async Task SendsNoTokenAfterTheGuestSignsOut()
        {
            var window = new FakeUpgradeWindow();
            var transport = GuestServer();
            var client = Client(transport, window);
            await client.SignInAsGuestAsync();
            var upgrade = client.UpgradeGuestAsync();

            await client.SignOutAsync();
            window.Send(Auth4UpgradeWindowEvent.Ready, Ready());

            var failure = await ThrowsWithin<Auth4GuestUpgradeException>(upgrade);
            Assert.That(failure.Reason, Is.EqualTo(GuestUpgradeFailure.SessionEnded));
            Assert.That(window.Tokens, Is.Empty);
        }

        [Test]
        public async Task RejectsAResultForAnotherUserAndRevokesIt()
        {
            var window = new FakeUpgradeWindow();
            var transport = GuestServer();
            var client = Client(transport, window);
            await client.SignInAsGuestAsync();
            var upgrade = client.UpgradeGuestAsync();

            window.Send(Auth4UpgradeWindowEvent.Complete, Upgraded(userId: "usr_SomeoneElse000000001"));

            var failure = await ThrowsWithin<Auth4Exception>(upgrade);
            Assert.That(failure.Error, Is.EqualTo("invalid_response"));
            Assert.That(client.CurrentSession, Is.Null);
            var revoke = transport.To("/oauth/revoke").Single();
            Assert.That(revoke.Form["token"], Is.EqualTo(Token("upgraded-refresh")));
        }

        [Test]
        public async Task RejectsAMalformedResultWithoutTouchingTheGuest()
        {
            var window = new FakeUpgradeWindow();
            var client = Client(GuestServer(), window);
            await client.SignInAsGuestAsync();
            var upgrade = client.UpgradeGuestAsync();

            window.Send(Auth4UpgradeWindowEvent.Complete, "{\"user_id\":\"" + GuestUserId + "\"}");

            var failure = await ThrowsWithin<Auth4Exception>(upgrade);
            Assert.That(failure.Error, Is.EqualTo("invalid_response"));
            Assert.That(client.CurrentSession.IsGuest, Is.True);
        }

        [Test]
        public async Task CancellationClosesTheWindow()
        {
            var window = new FakeUpgradeWindow();
            var client = Client(GuestServer(), window);
            await client.SignInAsGuestAsync();
            using (var cancellation = new CancellationTokenSource())
            {
                var upgrade = client.UpgradeGuestAsync(null, cancellation.Token);
                cancellation.Cancel();

                var failure = await ThrowsWithin<Auth4GuestUpgradeException>(upgrade);
                Assert.That(failure.Reason, Is.EqualTo(GuestUpgradeFailure.Cancelled));
                Assert.That(window.Closed, Is.True);
            }
        }

        [Test]
        public void MessagesNeverPrintTheirPayload()
        {
            var message = new Auth4UpgradeWindowMessage(Auth4UpgradeWindowEvent.Complete, Upgraded());
            Assert.That(message.ToString(), Does.Not.Contain(Token("upgraded-access")));
        }
    }

    internal sealed class FakeUpgradeWindow : IAuth4UpgradeWindow
    {
        public bool IsSupported { get; set; } = true;

        public List<(Uri Uri, string AuthOrigin)> Opened { get; } = new List<(Uri, string)>();

        public List<FakeUpgradeWindowHandle> Handles { get; } = new List<FakeUpgradeWindowHandle>();

        /// <summary>Runs inside Open, before it returns, as a real bridge may.</summary>
        public Action<Action<Auth4UpgradeWindowEvent, string>> OnOpen { get; set; }

        private FakeUpgradeWindowHandle Current => Handles[Handles.Count - 1];

        public List<string> Tokens => Handles.SelectMany(handle => handle.Tokens).ToList();

        public bool Released => Current.Released;

        public bool Closed => Current.Closed;

        public IAuth4UpgradeWindowHandle Open(Uri upgradeUri, string authOrigin, Action<Auth4UpgradeWindowMessage> onMessage)
        {
            Opened.Add((upgradeUri, authOrigin));
            var handle = new FakeUpgradeWindowHandle(onMessage);
            Handles.Add(handle);
            OnOpen?.Invoke((kind, data) => handle.Deliver(kind, data));
            return handle;
        }

        /// <summary>Delivers a message from the latest window, as the bridge would after its origin check.</summary>
        public void Send(Auth4UpgradeWindowEvent kind, string data = null)
        {
            Current.Deliver(kind, data);
        }
    }

    internal sealed class FakeUpgradeWindowHandle : IAuth4UpgradeWindowHandle
    {
        private readonly Action<Auth4UpgradeWindowMessage> _onMessage;

        public FakeUpgradeWindowHandle(Action<Auth4UpgradeWindowMessage> onMessage)
        {
            _onMessage = onMessage;
        }

        public List<string> Tokens { get; } = new List<string>();

        public bool Released { get; private set; }

        public bool Closed { get; private set; }

        public void Deliver(Auth4UpgradeWindowEvent kind, string data)
        {
            // Like the bridge: nothing is delivered once the game stops listening.
            if (!Released && !Closed)
            {
                _onMessage(new Auth4UpgradeWindowMessage(kind, data));
            }
        }

        public void SendAccessToken(string accessToken)
        {
            Tokens.Add(accessToken);
        }

        public void Close()
        {
            Closed = true;
        }

        public void Dispose()
        {
            Released = true;
        }
    }
}
