using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using static Auth4.Protocol.Tests.Fixtures;

namespace Auth4.Protocol.Tests
{
    /// <summary>
    /// AUTH4D-276: ChangeEmailAsync over the account email intent API with action "change". The session
    /// comes from guest sign-in only to have one; what the account may do is decided by the (fake) server.
    /// </summary>
    public sealed class ChangeEmailTests
    {
        private const string Handle = "aei_ChangeEmailHandle00000000000000000001";
        private const string PollSecret = "aep_ChangeEmailSecret0000000000000000000000000001";
        private static readonly string IntentPath = "/t/" + TenantId + "/account/email/intent";
        private static readonly string TokenPath = IntentPath + "/token";
        private static readonly string PageUri =
            Origin + "/login/change-email?tenant_id=" + TenantId + "&client_id=" + ClientId + "&intent=" + Handle;

        private static string IntentCreated(string pageUri = null)
        {
            return "{\"intent\":\"" + Handle + "\",\"poll_secret\":\"" + PollSecret + "\"," +
                   "\"add_email_uri\":\"" + (pageUri ?? PageUri) + "\",\"expires_in\":600,\"interval\":5}";
        }

        private static string Changed(string userId = GuestUserId, bool withIdentity = true)
        {
            return TokenJson(
                "changed-access",
                "changed-refresh",
                "ses_EmailChanged00000001",
                "\"user_id\":\"" + userId + "\",\"email\":\"new@example.test\"" +
                (withIdentity
                    ? ",\"identity\":{\"identity_id\":\"idn_Email000000000000002\",\"provider\":\"email\"}"
                    : string.Empty));
        }

        private static FakeTransport Server(Func<Auth4HttpResponse> create, params Func<Auth4HttpResponse>[] polls)
        {
            var queue = new Queue<Func<Auth4HttpResponse>>(polls);
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
                    return queue.Dequeue()();
                }

                if (request.Path == "/oauth/revoke")
                {
                    return FakeTransport.Json(200, string.Empty);
                }

                return FakeTransport.Json(404, Error("not_found"));
            });
        }

        private static Auth4Client Client(FakeTransport transport, FakeClock clock, FakeBrowser browser, ISecureStorageAdapter storage = null)
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
        public async Task SendsTheChangeActionOpensTheChangePageAndSwapsInTheRefreshedSession()
        {
            var storage = new FakeSecureStorage();
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(400, "{\"error\":\"authorization_pending\",\"interval\":5}"),
                () => FakeTransport.Json(200, Changed()));
            var clock = new FakeClock();
            var browser = new FakeBrowser();
            var client = Client(transport, clock, browser, storage);
            await client.SignInAsGuestAsync();
            var changes = new List<Auth4Session>();
            client.SessionChanged += changes.Add;

            var result = await client.ChangeEmailAsync();

            var create = transport.To(IntentPath).Single();
            Assert.That(create.Headers["Authorization"], Is.EqualTo("Bearer " + Token("guest-access")));
            Assert.That(create.Body, Is.EqualTo("{\"client_id\":\"" + ClientId + "\",\"action\":\"change\"}"));
            Assert.That(browser.Opened.Select(uri => uri.AbsoluteUri), Is.EqualTo(new[] { PageUri }));
            foreach (var poll in transport.To(TokenPath))
            {
                Assert.That(poll.Headers.ContainsKey("Authorization"), Is.False);
                Assert.That(poll.Body, Does.Contain("\"poll_secret\":\"" + PollSecret + "\""));
            }

            Assert.That(result.Email, Is.EqualTo("new@example.test"));
            Assert.That(result.Identity.IdentityId, Is.EqualTo("idn_Email000000000000002"));
            Assert.That(result.Identity.Provider, Is.EqualTo("email"));
            Assert.That(result.Session.UserId, Is.EqualTo(GuestUserId));
            Assert.That(result.Session.SessionId, Is.EqualTo("ses_EmailChanged00000001"));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("changed-access")));
            Assert.That(changes, Has.Count.EqualTo(1));
            var stored = storage.Values.Values.Single();
            Assert.That(stored, Does.Contain(Token("changed-refresh")));
            Assert.That(stored, Does.Not.Contain(PollSecret));
        }

        [TestCase("guest_account", AddEmailFailure.GuestAccount)]
        [TestCase("email_not_added", AddEmailFailure.NotAdded)]
        [TestCase("email_sign_in_disabled", AddEmailFailure.EmailSignInDisabled)]
        public async Task RefusalsAtCreationAreTypedAndOpenNothing(string error, AddEmailFailure reason)
        {
            var browser = new FakeBrowser();
            var client = Client(Server(() => FakeTransport.Json(409, Error(error))), new FakeClock(), browser);
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4AddEmailException>(() => client.ChangeEmailAsync());

            Assert.That(failure.Reason, Is.EqualTo(reason));
            Assert.That(browser.Opened, Is.Empty);
        }

        [TestCase("access_denied", AddEmailFailure.Denied)]
        [TestCase("expired_token", AddEmailFailure.Expired)]
        public async Task TerminalPollErrorsAreTypedAndKeepTheSession(string error, AddEmailFailure reason)
        {
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(400, Error(error)));
            var client = Client(transport, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4AddEmailException>(() => client.ChangeEmailAsync());

            Assert.That(failure.Reason, Is.EqualTo(reason));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("guest-access")));
        }

        [TestCase("https://evil.example.test/login/change-email")]
        [TestCase(Origin + "/login/add-email")]
        [TestCase(Origin + "/login/remove-email")]
        public async Task RejectsAPageThatIsNotTheChangePageOnTheAuthOrigin(string pageUri)
        {
            var browser = new FakeBrowser();
            var client = Client(Server(() => FakeTransport.Json(200, IntentCreated(pageUri))), new FakeClock(), browser);
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4Exception>(() => client.ChangeEmailAsync());

            Assert.That(failure.Error, Is.EqualTo("invalid_response"));
            Assert.That(browser.Opened, Is.Empty);
        }

        [Test]
        public async Task RejectsAResultForAnotherUser()
        {
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(200, Changed("usr_SomeoneElse000000001")));
            var client = Client(transport, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();

            Assert.ThrowsAsync<Auth4Exception>(() => client.ChangeEmailAsync());
            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(
                transport.To("/oauth/revoke").Select(request => request.Form["token"]),
                Does.Contain(Token("changed-refresh")));
        }

        [Test]
        public async Task RejectsAResultWithoutTheNewEmailIdentity()
        {
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(200, Changed(withIdentity: false)));
            var client = Client(transport, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4Exception>(() => client.ChangeEmailAsync());

            Assert.That(failure.Error, Is.EqualTo("invalid_response"));
            Assert.That(transport.To("/oauth/revoke"), Is.Not.Empty);
        }

        [Test]
        public async Task SignOutDuringPollingWins()
        {
            Auth4Client client = null;
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(400, Error("authorization_pending")),
                () => FakeTransport.Json(200, Changed()));
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

            Assert.ThrowsAsync<InvalidOperationException>(() => client.ChangeEmailAsync());

            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(
                transport.To("/oauth/revoke").Select(request => request.Form["token"]),
                Is.EqualTo(new[] { Token("guest-refresh"), Token("changed-refresh") }));
        }

        [Test]
        public async Task CancellationIsTyped()
        {
            using var cancellation = new CancellationTokenSource();
            var clock = new FakeClock { OnDelay = _ => cancellation.Cancel() };
            var client = Client(Server(() => FakeTransport.Json(200, IntentCreated())), clock, new FakeBrowser());
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4AddEmailException>(() => client.ChangeEmailAsync(null, cancellation.Token));

            Assert.That(failure.Reason, Is.EqualTo(AddEmailFailure.Cancelled));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("guest-access")));
        }

        [Test]
        public async Task OnlyOneAccountEmailRequestOrUpgradeAtATime()
        {
            Auth4Client client = null;
            var concurrent = new List<Exception>();
            var browser = new FakeBrowser
            {
                OnOpen = _ =>
                {
                    concurrent.Add(Assert.ThrowsAsync<InvalidOperationException>(() => client.ChangeEmailAsync()));
                    concurrent.Add(Assert.ThrowsAsync<InvalidOperationException>(() => client.AddEmailAsync()));
                    concurrent.Add(Assert.ThrowsAsync<InvalidOperationException>(() => client.RemoveEmailAsync()));
                    concurrent.Add(Assert.ThrowsAsync<InvalidOperationException>(() => client.UpgradeGuestAsync()));
                },
            };
            client = Client(
                Server(() => FakeTransport.Json(200, IntentCreated()), () => FakeTransport.Json(200, Changed())),
                new FakeClock(),
                browser);
            await client.SignInAsGuestAsync();

            await client.ChangeEmailAsync();

            Assert.That(concurrent, Has.Count.EqualTo(4));
            Assert.That(concurrent, Has.All.Not.Null);
        }
    }
}
