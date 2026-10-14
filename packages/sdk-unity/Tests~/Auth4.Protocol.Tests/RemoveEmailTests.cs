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
    /// AUTH4D-276: RemoveEmailAsync over the account email intent API with action "remove". A removal
    /// result carries only the refreshed tokens and the user id, never an identity.
    /// </summary>
    public sealed class RemoveEmailTests
    {
        private const string Handle = "aei_RemoveEmailHandle00000000000000000001";
        private const string PollSecret = "aep_RemoveEmailSecret0000000000000000000000000001";
        private static readonly string IntentPath = "/t/" + TenantId + "/account/email/intent";
        private static readonly string TokenPath = IntentPath + "/token";
        private static readonly string PageUri =
            Origin + "/login/remove-email?tenant_id=" + TenantId + "&client_id=" + ClientId + "&intent=" + Handle;

        private static string IntentCreated(string pageUri = null)
        {
            return "{\"intent\":\"" + Handle + "\",\"poll_secret\":\"" + PollSecret + "\"," +
                   "\"add_email_uri\":\"" + (pageUri ?? PageUri) + "\",\"expires_in\":600,\"interval\":5}";
        }

        private static string Removed(string userId = GuestUserId, bool withIdentity = false)
        {
            return TokenJson(
                "removed-access",
                "removed-refresh",
                "ses_EmailRemoved00000001",
                "\"user_id\":\"" + userId + "\"" +
                (withIdentity
                    ? ",\"identity\":{\"identity_id\":\"idn_Email000000000000003\",\"provider\":\"email\"}"
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
        public async Task SendsTheRemoveActionOpensTheRemovePageAndSwapsInTheRefreshedSession()
        {
            var storage = new FakeSecureStorage();
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(400, "{\"error\":\"authorization_pending\",\"interval\":5}"),
                () => FakeTransport.Json(200, Removed()));
            var clock = new FakeClock();
            var browser = new FakeBrowser();
            var client = Client(transport, clock, browser, storage);
            await client.SignInAsGuestAsync();
            var changes = new List<Auth4Session>();
            client.SessionChanged += changes.Add;

            var result = await client.RemoveEmailAsync();

            var create = transport.To(IntentPath).Single();
            Assert.That(create.Headers["Authorization"], Is.EqualTo("Bearer " + Token("guest-access")));
            Assert.That(create.Body, Is.EqualTo("{\"client_id\":\"" + ClientId + "\",\"action\":\"remove\"}"));
            Assert.That(browser.Opened.Select(uri => uri.AbsoluteUri), Is.EqualTo(new[] { PageUri }));
            Assert.That(result.Session.UserId, Is.EqualTo(GuestUserId));
            Assert.That(result.Session.SessionId, Is.EqualTo("ses_EmailRemoved00000001"));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("removed-access")));
            Assert.That(changes, Has.Count.EqualTo(1));
            var stored = storage.Values.Values.Single();
            Assert.That(stored, Does.Contain(Token("removed-refresh")));
            Assert.That(stored, Does.Not.Contain(PollSecret));
        }

        [TestCase("guest_account", AddEmailFailure.GuestAccount)]
        [TestCase("email_not_added", AddEmailFailure.NotAdded)]
        [TestCase("only_sign_in_method", AddEmailFailure.OnlySignInMethod)]
        public async Task RefusalsAtCreationAreTypedAndOpenNothing(string error, AddEmailFailure reason)
        {
            var browser = new FakeBrowser();
            var client = Client(Server(() => FakeTransport.Json(409, Error(error))), new FakeClock(), browser);
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4AddEmailException>(() => client.RemoveEmailAsync());

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

            var failure = Assert.ThrowsAsync<Auth4AddEmailException>(() => client.RemoveEmailAsync());

            Assert.That(failure.Reason, Is.EqualTo(reason));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("guest-access")));
        }

        [TestCase("https://evil.example.test/login/remove-email")]
        [TestCase(Origin + "/login/add-email")]
        [TestCase(Origin + "/login/change-email")]
        public async Task RejectsAPageThatIsNotTheRemovePageOnTheAuthOrigin(string pageUri)
        {
            var browser = new FakeBrowser();
            var client = Client(Server(() => FakeTransport.Json(200, IntentCreated(pageUri))), new FakeClock(), browser);
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4Exception>(() => client.RemoveEmailAsync());

            Assert.That(failure.Error, Is.EqualTo("invalid_response"));
            Assert.That(browser.Opened, Is.Empty);
        }

        [Test]
        public async Task RejectsAResultForAnotherUser()
        {
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(200, Removed("usr_SomeoneElse000000001")));
            var client = Client(transport, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();

            Assert.ThrowsAsync<Auth4Exception>(() => client.RemoveEmailAsync());
            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(
                transport.To("/oauth/revoke").Select(request => request.Form["token"]),
                Does.Contain(Token("removed-refresh")));
        }

        [Test]
        public async Task RejectsAResultThatStillCarriesAnIdentity()
        {
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(200, Removed(withIdentity: true)));
            var client = Client(transport, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4Exception>(() => client.RemoveEmailAsync());

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
                () => FakeTransport.Json(200, Removed()));
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

            Assert.ThrowsAsync<InvalidOperationException>(() => client.RemoveEmailAsync());

            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(
                transport.To("/oauth/revoke").Select(request => request.Form["token"]),
                Is.EqualTo(new[] { Token("guest-refresh"), Token("removed-refresh") }));
        }

        [Test]
        public async Task CancellationIsTyped()
        {
            using var cancellation = new CancellationTokenSource();
            var clock = new FakeClock { OnDelay = _ => cancellation.Cancel() };
            var client = Client(Server(() => FakeTransport.Json(200, IntentCreated())), clock, new FakeBrowser());
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4AddEmailException>(() => client.RemoveEmailAsync(null, cancellation.Token));

            Assert.That(failure.Reason, Is.EqualTo(AddEmailFailure.Cancelled));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("guest-access")));
        }

        [Test]
        public async Task OnlyOneAccountEmailRequestOrUpgradeAtATime()
        {
            Auth4Client client = null;
            Exception concurrent = null;
            var browser = new FakeBrowser
            {
                OnOpen = _ => concurrent = Assert.ThrowsAsync<InvalidOperationException>(() => client.RemoveEmailAsync()),
            };
            client = Client(
                Server(() => FakeTransport.Json(200, IntentCreated()), () => FakeTransport.Json(200, Removed())),
                new FakeClock(),
                browser);
            await client.SignInAsGuestAsync();

            await client.RemoveEmailAsync();

            Assert.That(concurrent, Is.Not.Null);
        }
    }
}
