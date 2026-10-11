using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NUnit.Framework;
using static Auth4.Protocol.Tests.Fixtures;

namespace Auth4.Protocol.Tests
{
    /// <summary>
    /// AUTH4D-149: AddEmailAsync over the add-email intent API. The session comes from guest sign-in
    /// only to have one; whether the account may add an address is decided by the (fake) server.
    /// </summary>
    public sealed class AddEmailTests
    {
        private const string Handle = "aei_AddEmailHandle000000000000000000001";
        private const string PollSecret = "aep_AddEmailSecret00000000000000000000000000001";
        private static readonly string IntentPath = "/t/" + TenantId + "/account/email/intent";
        private static readonly string TokenPath = IntentPath + "/token";
        private static readonly string PageUri =
            Origin + "/login/add-email?tenant_id=" + TenantId + "&client_id=" + ClientId + "&intent=" + Handle;

        private static string IntentCreated(string pageUri = null)
        {
            return "{\"intent\":\"" + Handle + "\",\"poll_secret\":\"" + PollSecret + "\"," +
                   "\"add_email_uri\":\"" + (pageUri ?? PageUri) + "\",\"expires_in\":600,\"interval\":5}";
        }

        private static string Added(string userId = GuestUserId)
        {
            return TokenJson(
                "email-access",
                "email-refresh",
                "ses_EmailAdded0000000001",
                "\"user_id\":\"" + userId + "\",\"email\":\"player@example.test\"," +
                "\"identity\":{\"identity_id\":\"idn_Email000000000000001\",\"provider\":\"email\"}");
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
        public async Task OpensThePagePollsAndSwapsInTheRefreshedSession()
        {
            var storage = new FakeSecureStorage();
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(400, "{\"error\":\"authorization_pending\",\"interval\":5}"),
                () => FakeTransport.Json(200, Added()));
            var clock = new FakeClock();
            var browser = new FakeBrowser();
            var client = Client(transport, clock, browser, storage);
            await client.SignInAsGuestAsync();
            var changes = new List<Auth4Session>();
            client.SessionChanged += changes.Add;

            var result = await client.AddEmailAsync();

            var create = transport.To(IntentPath).Single();
            Assert.That(create.Headers["Authorization"], Is.EqualTo("Bearer " + Token("guest-access")));
            Assert.That(create.Body, Is.EqualTo("{\"client_id\":\"" + ClientId + "\"}"));
            Assert.That(browser.Opened.Select(uri => uri.AbsoluteUri), Is.EqualTo(new[] { PageUri }));
            foreach (var poll in transport.To(TokenPath))
            {
                Assert.That(poll.Headers.ContainsKey("Authorization"), Is.False);
                Assert.That(poll.Body, Does.Contain("\"poll_secret\":\"" + PollSecret + "\""));
            }

            Assert.That(clock.Delays.Select(delay => delay.TotalSeconds), Is.EqualTo(new double[] { 5, 5 }));
            Assert.That(result.Email, Is.EqualTo("player@example.test"));
            Assert.That(result.Identity.Provider, Is.EqualTo("email"));
            Assert.That(result.Session.UserId, Is.EqualTo(GuestUserId));
            Assert.That(result.Session.SessionId, Is.EqualTo("ses_EmailAdded0000000001"));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("email-access")));
            Assert.That(changes, Has.Count.EqualTo(1));
            var stored = storage.Values.Values.Single();
            Assert.That(stored, Does.Contain(Token("email-refresh")));
            Assert.That(stored, Does.Not.Contain(PollSecret));
        }

        [TestCase("guest_account", AddEmailFailure.GuestAccount)]
        [TestCase("email_already_added", AddEmailFailure.AlreadyAdded)]
        [TestCase("email_sign_in_disabled", AddEmailFailure.EmailSignInDisabled)]
        public async Task RefusalsAtCreationAreTypedAndOpenNothing(string error, AddEmailFailure reason)
        {
            var browser = new FakeBrowser();
            var client = Client(Server(() => FakeTransport.Json(409, Error(error))), new FakeClock(), browser);
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4AddEmailException>(() => client.AddEmailAsync());

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

            var failure = Assert.ThrowsAsync<Auth4AddEmailException>(() => client.AddEmailAsync());

            Assert.That(failure.Reason, Is.EqualTo(reason));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("guest-access")));
        }

        [Test]
        public async Task RejectsAPageOffTheAuthOrigin()
        {
            var browser = new FakeBrowser();
            var client = Client(
                Server(() => FakeTransport.Json(200, IntentCreated("https://evil.example.test/login/add-email"))),
                new FakeClock(),
                browser);
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4Exception>(() => client.AddEmailAsync());

            Assert.That(failure.Error, Is.EqualTo("invalid_response"));
            Assert.That(browser.Opened, Is.Empty);
        }

        [Test]
        public async Task RejectsAResultForAnotherUser()
        {
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(200, Added("usr_SomeoneElse000000001")));
            var client = Client(transport, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();

            Assert.ThrowsAsync<Auth4Exception>(() => client.AddEmailAsync());
            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(transport.To("/oauth/revoke"), Is.Not.Empty);
        }
    }
}
