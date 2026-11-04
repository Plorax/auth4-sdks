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
    /// AUTH4D-308: LinkAccountAsync and UnlinkAccountAsync over the account link intent API. A link
    /// result names the linked provider identity; an unlink result carries only the refreshed tokens.
    /// </summary>
    public sealed class LinkAccountTests
    {
        private const string Handle = "lai_LinkAccountHandle00000000000000000001";
        private const string PollSecret = "lap_LinkAccountSecret0000000000000000000000000001";
        private static readonly string IntentPath = "/t/" + TenantId + "/account/link/intent";
        private static readonly string TokenPath = IntentPath + "/token";
        private static readonly string PageUri =
            Origin + "/login/link-account?tenant_id=" + TenantId + "&client_id=" + ClientId + "&intent=" + Handle;

        private static string IntentCreated(string pageUri = null)
        {
            return "{\"intent\":\"" + Handle + "\",\"poll_secret\":\"" + PollSecret + "\"," +
                   "\"link_uri\":\"" + (pageUri ?? PageUri) + "\",\"expires_in\":600,\"interval\":5}";
        }

        private static string Linked(string provider = "steam", string userId = GuestUserId)
        {
            return TokenJson(
                "linked-access",
                "linked-refresh",
                "ses_AccountLinked0000001",
                "\"user_id\":\"" + userId + "\"" +
                (provider == null
                    ? string.Empty
                    : ",\"identity\":{\"identity_id\":\"idn_Steam000000000000001\",\"provider\":\"" + provider + "\"}"));
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
        public async Task LinksSteamOpensTheLinkPageAndSwapsInTheRefreshedSession()
        {
            var storage = new FakeSecureStorage();
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(400, "{\"error\":\"authorization_pending\",\"interval\":5}"),
                () => FakeTransport.Json(200, Linked()));
            var browser = new FakeBrowser();
            var client = Client(transport, new FakeClock(), browser, storage);
            await client.SignInAsGuestAsync();
            var changes = new List<Auth4Session>();
            client.SessionChanged += changes.Add;

            var result = await client.LinkAccountAsync(LinkableProvider.Steam);

            var create = transport.To(IntentPath).Single();
            Assert.That(create.Headers["Authorization"], Is.EqualTo("Bearer " + Token("guest-access")));
            Assert.That(
                create.Body,
                Is.EqualTo("{\"client_id\":\"" + ClientId + "\",\"provider\":\"steam\",\"action\":\"link\"}"));
            Assert.That(browser.Opened.Select(uri => uri.AbsoluteUri), Is.EqualTo(new[] { PageUri }));
            Assert.That(result.Session.UserId, Is.EqualTo(GuestUserId));
            Assert.That(result.Identity.Provider, Is.EqualTo("steam"));
            Assert.That(result.Identity.IdentityId, Is.EqualTo("idn_Steam000000000000001"));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("linked-access")));
            Assert.That(changes, Has.Count.EqualTo(1));
            var stored = storage.Values.Values.Single();
            Assert.That(stored, Does.Contain(Token("linked-refresh")));
            Assert.That(stored, Does.Not.Contain(PollSecret));
        }

        [Test]
        public async Task UnlinksDiscordWithTheUnlinkAction()
        {
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(200, Linked(provider: null)));
            var client = Client(transport, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();

            var result = await client.UnlinkAccountAsync(LinkableProvider.Discord);

            Assert.That(
                transport.To(IntentPath).Single().Body,
                Is.EqualTo("{\"client_id\":\"" + ClientId + "\",\"provider\":\"discord\",\"action\":\"unlink\"}"));
            Assert.That(result.Session.UserId, Is.EqualTo(GuestUserId));
        }

        [TestCase("guest_account", LinkAccountFailure.GuestAccount)]
        [TestCase("provider_already_linked", LinkAccountFailure.AlreadyLinked)]
        [TestCase("provider_not_linked", LinkAccountFailure.NotLinked)]
        [TestCase("provider_disabled", LinkAccountFailure.ProviderDisabled)]
        [TestCase("only_sign_in_method", LinkAccountFailure.OnlySignInMethod)]
        [TestCase("login_required", LinkAccountFailure.LoginRequired)]
        public async Task RefusalsAtCreationAreTypedAndOpenNothing(string error, LinkAccountFailure reason)
        {
            var browser = new FakeBrowser();
            var client = Client(Server(() => FakeTransport.Json(409, Error(error))), new FakeClock(), browser);
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4LinkAccountException>(() => client.LinkAccountAsync(LinkableProvider.Epic));

            Assert.That(failure.Reason, Is.EqualTo(reason));
            Assert.That(browser.Opened, Is.Empty);
        }

        [TestCase("access_denied", LinkAccountFailure.Denied)]
        [TestCase("expired_token", LinkAccountFailure.Expired)]
        public async Task TerminalPollErrorsAreTypedAndKeepTheSession(string error, LinkAccountFailure reason)
        {
            var transport = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(400, Error(error)));
            var client = Client(transport, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4LinkAccountException>(() => client.LinkAccountAsync(LinkableProvider.Steam));

            Assert.That(failure.Reason, Is.EqualTo(reason));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("guest-access")));
        }

        [TestCase("https://evil.example.test/login/link-account")]
        [TestCase(Origin + "/login/add-email")]
        public async Task RejectsAPageThatIsNotTheLinkPageOnTheAuthOrigin(string pageUri)
        {
            var browser = new FakeBrowser();
            var client = Client(Server(() => FakeTransport.Json(200, IntentCreated(pageUri))), new FakeClock(), browser);
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4Exception>(() => client.LinkAccountAsync(LinkableProvider.Steam));

            Assert.That(failure.Error, Is.EqualTo("invalid_response"));
            Assert.That(browser.Opened, Is.Empty);
        }

        [Test]
        public async Task RejectsAResultForAnotherUserOrAnotherProvider()
        {
            var otherUser = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(200, Linked(userId: "usr_SomeoneElse000000001")));
            var client = Client(otherUser, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();
            Assert.ThrowsAsync<Auth4Exception>(() => client.LinkAccountAsync(LinkableProvider.Steam));
            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(
                otherUser.To("/oauth/revoke").Select(request => request.Form["token"]),
                Does.Contain(Token("linked-refresh")));

            var otherProvider = Server(
                () => FakeTransport.Json(200, IntentCreated()),
                () => FakeTransport.Json(200, Linked(provider: "discord")));
            client = Client(otherProvider, new FakeClock(), new FakeBrowser());
            await client.SignInAsGuestAsync();
            var failure = Assert.ThrowsAsync<Auth4Exception>(() => client.LinkAccountAsync(LinkableProvider.Steam));
            Assert.That(failure.Error, Is.EqualTo("invalid_response"));
        }

        [Test]
        public async Task CancellationIsTyped()
        {
            using var cancellation = new CancellationTokenSource();
            var clock = new FakeClock { OnDelay = _ => cancellation.Cancel() };
            var client = Client(Server(() => FakeTransport.Json(200, IntentCreated())), clock, new FakeBrowser());
            await client.SignInAsGuestAsync();

            var failure = Assert.ThrowsAsync<Auth4LinkAccountException>(
                () => client.LinkAccountAsync(LinkableProvider.Steam, null, cancellation.Token));

            Assert.That(failure.Reason, Is.EqualTo(LinkAccountFailure.Cancelled));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("guest-access")));
        }

        [Test]
        public async Task OnlyOneAccountRequestOrUpgradeAtATime()
        {
            Auth4Client client = null;
            Exception concurrent = null;
            var browser = new FakeBrowser
            {
                OnOpen = _ => concurrent = Assert.ThrowsAsync<InvalidOperationException>(() => client.AddEmailAsync()),
            };
            client = Client(
                Server(() => FakeTransport.Json(200, IntentCreated()), () => FakeTransport.Json(200, Linked())),
                new FakeClock(),
                browser);
            await client.SignInAsGuestAsync();

            await client.LinkAccountAsync(LinkableProvider.Steam);

            Assert.That(concurrent, Is.Not.Null);
        }
    }
}
