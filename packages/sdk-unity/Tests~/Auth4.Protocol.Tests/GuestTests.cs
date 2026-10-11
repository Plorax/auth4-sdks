using System;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using NUnit.Framework;
using static Auth4.Protocol.Tests.Fixtures;

namespace Auth4.Protocol.Tests
{
    public sealed class GuestTests
    {
        private const string FlowCookieValue = "flow-cookie-secret-value-0001";
        private static readonly string GuestPath = "/t/" + TenantId + "/guest";

        private static string FlowId(RecordedRequest request)
        {
            return Regex.Match(request.Body, "\"browser_flow_id\":\"([^\"]+)\"").Groups[1].Value;
        }

        /// <summary>Simulates the guest, linking-intent, email-code and upgrade endpoints.</summary>
        private static FakeTransport UpgradeServer(Func<RecordedRequest, Auth4HttpResponse> upgrade = null)
        {
            return new FakeTransport(request =>
            {
                switch (request.Path.Replace("/t/" + TenantId, string.Empty))
                {
                    case "/guest":
                        return FakeTransport.Json(200, GuestCreated());
                    case "/guest/linking-intent":
                        return FakeTransport.Json(
                            200,
                            "{\"upgrade_proof\":{\"proof_id\":\"prf_LinkIntent0000000001\",\"expires_in\":300}}",
                            "__Host-auth4_flow_" + FlowId(request) + "=" + FlowCookieValue +
                            "; Path=/; Max-Age=600; Secure; HttpOnly; SameSite=Lax");
                    case "/email/verification/start":
                        return FakeTransport.Json(202, "{\"expires_in\":600,\"resend_after\":60}");
                    case "/email/verification/confirm":
                        return FakeTransport.Json(200, "{\"proof\":{\"proof_id\":\"prf_EmailProof000000001\",\"expires_in\":300}}");
                    case "/guest/upgrade":
                        return upgrade != null
                            ? upgrade(request)
                            : FakeTransport.Json(200, TokenJson(
                                "upgraded-access",
                                "upgraded-refresh",
                                "ses_Upgraded000000000001",
                                "\"user_id\":\"" + GuestUserId + "\",\"identity\":{\"identity_id\":\"idn_Email00000000000001\",\"provider\":\"email\"}"));
                    case "/oauth/revoke":
                        return FakeTransport.Json(200, string.Empty);
                    default:
                        return FakeTransport.Json(404, Error("not_found"));
                }
            });
        }

        [Test]
        public async Task GuestLoginCreatesInMemoryGuestSession()
        {
            var transport = UpgradeServer();
            var client = Client(transport, new FakeClock());

            var session = await client.SignInAsGuestAsync();

            var request = transport.Requests.Single();
            Assert.That(request.Uri.ToString(), Is.EqualTo(Origin + GuestPath));
            Assert.That(request.ContentType, Is.EqualTo("application/json"));
            Assert.That(request.Body, Does.Contain("\"client_id\":\"" + ClientId + "\""));
            Assert.That(FlowId(request), Does.Match("^flw_[A-Za-z0-9_-]{16,64}$"));
            Assert.That(request.Body, Does.Not.Contain("user_id"));
            Assert.That(session.IsGuest, Is.True);
            Assert.That(session.UserId, Is.EqualTo(GuestUserId));
            Assert.That(session.SessionId, Is.EqualTo("ses_GuestSession00000001"));
            Assert.That(session.IsRefreshPersistent, Is.False);
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("guest-access")));
        }

        [Test]
        public async Task GuestLoginNeverReplacesActiveSession()
        {
            var client = Client(UpgradeServer(), new FakeClock());
            await client.SignInAsGuestAsync();

            Assert.ThrowsAsync<InvalidOperationException>(() => client.SignInAsGuestAsync());
            Assert.That(client.CurrentSession.UserId, Is.EqualTo(GuestUserId));
        }

        [Test]
        public async Task EmailUpgradeKeepsGuestUserAndRotatesSession()
        {
            var storage = new FakeSecureStorage();
            var transport = UpgradeServer();
            var client = Client(transport, new FakeClock(), storage);
            await client.SignInAsGuestAsync();
            var guestStored = storage.Values.Values.Single();

            var flow = await client.BeginGuestUpgradeAsync();
            await client.StartEmailVerificationAsync(flow, "player@example.test");
            var proofId = await client.ConfirmEmailVerificationAsync(flow, "player@example.test", "123456");
            var result = await client.CompleteGuestUpgradeAsync(flow, proofId);

            var intent = transport.To(GuestPath + "/linking-intent").Single();
            Assert.That(intent.Headers["Authorization"], Is.EqualTo("Bearer " + Token("guest-access")));
            Assert.That(FlowId(intent), Is.EqualTo(flow.BrowserFlowId));

            foreach (var path in new[] { "/email/verification/start", "/email/verification/confirm" })
            {
                var emailRequest = transport.To("/t/" + TenantId + path).Single();
                Assert.That(emailRequest.Headers["Cookie"], Is.EqualTo("__Host-auth4_flow_" + flow.BrowserFlowId + "=" + FlowCookieValue));
                Assert.That(emailRequest.Headers["Origin"], Is.EqualTo(Origin));
                Assert.That(emailRequest.Headers.ContainsKey("Authorization"), Is.False);
                Assert.That(FlowId(emailRequest), Is.EqualTo(flow.BrowserFlowId));
            }

            var upgrade = transport.To(GuestPath + "/upgrade").Single();
            Assert.That(upgrade.Headers["Authorization"], Is.EqualTo("Bearer " + Token("guest-access")));
            Assert.That(upgrade.Headers["Cookie"], Does.EndWith("=" + FlowCookieValue));
            Assert.That(upgrade.Body, Does.Contain("\"proof_id\":\"prf_EmailProof000000001\""));

            Assert.That(result.Session.UserId, Is.EqualTo(GuestUserId));
            Assert.That(result.Session.IsGuest, Is.False);
            Assert.That(result.Session.SessionId, Is.EqualTo("ses_Upgraded000000000001"));
            Assert.That(result.Identity.Provider, Is.EqualTo("email"));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("upgraded-access")));
            var stored = storage.Values.Values.Single();
            Assert.That(stored, Is.Not.EqualTo(guestStored));
            Assert.That(stored, Does.Contain(Token("upgraded-refresh")));
            Assert.That(stored, Does.Contain("\"guest\":\"false\""));
            Assert.That(stored, Does.Contain(GuestUserId));
        }

        [Test]
        public async Task IdentityInUseLeavesGuestSessionIntact()
        {
            var client = Client(
                UpgradeServer(_ => FakeTransport.Json(409, "{\"error\":\"identity_in_use\"}")),
                new FakeClock());
            await client.SignInAsGuestAsync();
            var flow = await client.BeginGuestUpgradeAsync();

            var error = Assert.ThrowsAsync<Auth4Exception>(() => client.CompleteGuestUpgradeAsync(flow, "prf_EmailProof000000001"));

            Assert.That(error.Error, Is.EqualTo("identity_in_use"));
            Assert.That(error.StatusCode, Is.EqualTo(409));
            Assert.That(client.CurrentSession.IsGuest, Is.True);
            Assert.That(client.CurrentSession.UserId, Is.EqualTo(GuestUserId));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("guest-access")));
        }

        [Test]
        public async Task UpgradeThatChangesTheUserIsRejected()
        {
            var transport = UpgradeServer(_ => FakeTransport.Json(200, TokenJson(
                "other-access",
                "other-refresh",
                "ses_Other00000000000001",
                "\"user_id\":\"usr_SomeoneElse000000001\",\"identity\":{\"identity_id\":\"idn_Email00000000000001\",\"provider\":\"email\"}")));
            var client = Client(transport, new FakeClock());
            await client.SignInAsGuestAsync();
            var flow = await client.BeginGuestUpgradeAsync();

            var error = Assert.ThrowsAsync<Auth4Exception>(() => client.CompleteGuestUpgradeAsync(flow, "prf_EmailProof000000001"));

            Assert.That(error.Error, Is.EqualTo("invalid_response"));
            Assert.That(client.CurrentSession, Is.Null);
            var revoke = transport.To("/oauth/revoke").Single();
            Assert.That(revoke.Form["token"], Is.EqualTo(Token("other-refresh")));
        }

        [Test]
        public async Task ExpiredUpgradeFlowIsRejectedLocally()
        {
            var clock = new FakeClock();
            var transport = UpgradeServer();
            var client = Client(transport, clock);
            await client.SignInAsGuestAsync();
            var flow = await client.BeginGuestUpgradeAsync();
            clock.Advance(TimeSpan.FromSeconds(301));

            var error = Assert.ThrowsAsync<Auth4Exception>(() => client.StartEmailVerificationAsync(flow, "player@example.test"));
            Assert.That(error.Error, Is.EqualTo("expired_token"));
            Assert.That(transport.To("/t/" + TenantId + "/email/verification/start"), Is.Empty);
        }

        [Test]
        public async Task OnlyGuestsCanBeginUpgrade()
        {
            var client = Client(
                new FakeTransport(request => request.Path == "/device/authorization"
                    ? FakeTransport.Json(200, DeviceStart())
                    : FakeTransport.Json(200, TokenJson("device-access", "device-refresh"))),
                new FakeClock());
            await client.PollDeviceAuthorizationAsync(await client.StartDeviceAuthorizationAsync());

            Assert.ThrowsAsync<InvalidOperationException>(() => client.BeginGuestUpgradeAsync());
        }

        [Test]
        public void UpgradeRequiresFlowCookie()
        {
            var transport = new FakeTransport(request => request.Path.EndsWith("/linking-intent")
                ? FakeTransport.Json(200, "{\"upgrade_proof\":{\"proof_id\":\"prf_LinkIntent0000000001\",\"expires_in\":300}}")
                : FakeTransport.Json(200, GuestCreated()));
            var client = Client(transport, new FakeClock());

            Assert.ThrowsAsync<Auth4Exception>(async () =>
            {
                await client.SignInAsGuestAsync();
                await client.BeginGuestUpgradeAsync();
            });
        }
    }
}
