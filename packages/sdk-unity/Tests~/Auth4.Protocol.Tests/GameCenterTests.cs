using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using static Auth4.Protocol.Tests.Fixtures;

namespace Auth4.Protocol.Tests
{
    /// <summary>AUTH4D-311: SignInWithGameCenterAsync and its verified email step.</summary>
    public sealed class GameCenterTests
    {
        private const string PlayerId = "T:_9b2f6c1e7d4a3b5c8e0f1a2b3c4d5e6f";
        private const string GameCenterUserId = "usr_GameCenterPlayer0001";
        private static readonly string TokenPath = "/t/" + TenantId + "/game-center/token";
        private static readonly string SendPath = "/t/" + TenantId + "/game-center/email/send";
        private static readonly string ConfirmPath = "/t/" + TenantId + "/game-center/email/confirm";
        private static readonly string Continuation = "gcc_" + new string('C', 43);

        private sealed class FakeGameCenter : IAuth4GameCenter
        {
            public bool IsSupported { get; set; } = true;

            public int Fetches { get; private set; }

            public Task<GameCenterIdentity> FetchIdentityAsync(CancellationToken cancellationToken)
            {
                Fetches++;
                return Task.FromResult(new GameCenterIdentity(
                    PlayerId,
                    "dev.auth4.arcade",
                    "https://static.gc.apple.com/public-key/gc-prod-12.cer",
                    new byte[] { 1, 2, 3, 250 },
                    new byte[] { 9, 8, 7 },
                    1_792_000_000_123UL));
            }
        }

        private static Auth4Client Client(FakeTransport transport, FakeClock clock, IAuth4GameCenter gameCenter)
        {
            return new Auth4Client(new Auth4ClientOptions
            {
                TenantId = TenantId,
                ClientId = ClientId,
                AuthOrigin = Origin,
                Transport = transport,
                Clock = clock,
                GameCenter = gameCenter,
            });
        }

        private static string Signed(string userId, string session = "ses_GameCenter0000000001")
        {
            return TokenJson("gc-access", "gc-refresh", session, "\"user_id\":\"" + userId + "\"");
        }

        private static string EmailRequired()
        {
            return "{\"error\":\"email_verification_required\",\"continuation\":\"" + Continuation +
                   "\",\"reason\":\"no_email\",\"expires_in\":600}";
        }

        [Test]
        public async Task SignsInWithTheGameKitSignature()
        {
            var transport = new FakeTransport(request => FakeTransport.Json(200, Signed(GameCenterUserId)));
            var gameCenter = new FakeGameCenter();
            var client = Client(transport, new FakeClock(), gameCenter);

            var session = await client.SignInWithGameCenterAsync();

            var request = transport.Requests.Single();
            Assert.That(request.Uri.ToString(), Is.EqualTo(Origin + TokenPath));
            Assert.That(request.ContentType, Is.EqualTo("application/json"));
            Assert.That(request.Headers.ContainsKey("Origin"), Is.False);
            Assert.That(request.Headers.ContainsKey("Authorization"), Is.False);
            Assert.That(request.Body, Does.Contain("\"client_id\":\"" + ClientId + "\""));
            Assert.That(request.Body, Does.Contain("\"player_id\":\"" + PlayerId + "\""));
            Assert.That(request.Body, Does.Contain("\"bundle_id\":\"dev.auth4.arcade\""));
            Assert.That(request.Body, Does.Contain("\"public_key_url\":\"https://static.gc.apple.com/public-key/gc-prod-12.cer\""));
            Assert.That(request.Body, Does.Contain("\"signature\":\"AQID+g==\""));
            Assert.That(request.Body, Does.Contain("\"salt\":\"CQgH\""));
            Assert.That(request.Body, Does.Contain("\"timestamp\":1792000000123"));
            Assert.That(session.UserId, Is.EqualTo(GameCenterUserId));
            Assert.That(session.IsGuest, Is.False);
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("gc-access")));
            Assert.That(gameCenter.Fetches, Is.EqualTo(1));
        }

        [Test]
        public void NeedsASupportedAdapter()
        {
            var transport = new FakeTransport(request => FakeTransport.Json(500, Error("server_error")));
            Assert.ThrowsAsync<PlatformNotSupportedException>(
                () => Client(transport, new FakeClock(), null).SignInWithGameCenterAsync());
            Assert.ThrowsAsync<PlatformNotSupportedException>(
                () => Client(transport, new FakeClock(), new FakeGameCenter { IsSupported = false })
                    .SignInWithGameCenterAsync());
            Assert.That(transport.Requests, Is.Empty);
        }

        [Test]
        public async Task LinksTheCurrentGuestAndReplacesItsSession()
        {
            var transport = new FakeTransport(request => request.Path == "/t/" + TenantId + "/guest"
                ? FakeTransport.Json(200, GuestCreated())
                : FakeTransport.Json(200, Signed(GuestUserId, "ses_Linked00000000000001")));
            var client = Client(transport, new FakeClock(), new FakeGameCenter());
            await client.SignInAsGuestAsync();

            var session = await client.SignInWithGameCenterAsync();

            var request = transport.To(TokenPath).Single();
            Assert.That(request.Headers["Authorization"], Is.EqualTo("Bearer " + Token("guest-access")));
            Assert.That(session.UserId, Is.EqualTo(GuestUserId));
            Assert.That(session.IsGuest, Is.False);
            Assert.That(session.SessionId, Is.EqualTo("ses_Linked00000000000001"));
        }

        [Test]
        public async Task KeepsTheGuestWhenThePlayerAlreadyHasAnAccount()
        {
            var transport = new FakeTransport(request => request.Path == "/t/" + TenantId + "/guest"
                ? FakeTransport.Json(200, GuestCreated())
                : FakeTransport.Json(409, Error("identity_in_use")));
            var client = Client(transport, new FakeClock(), new FakeGameCenter());
            await client.SignInAsGuestAsync();

            var error = Assert.ThrowsAsync<Auth4Exception>(() => client.SignInWithGameCenterAsync());

            Assert.That(error.Error, Is.EqualTo("identity_in_use"));
            Assert.That(client.CurrentSession.IsGuest, Is.True);
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("guest-access")));
        }

        [Test]
        public async Task RefusesWhileAnotherPlayerIsSignedIn()
        {
            var transport = new FakeTransport(request => FakeTransport.Json(200, Signed(GameCenterUserId)));
            var client = Client(transport, new FakeClock(), new FakeGameCenter());
            await client.SignInWithGameCenterAsync();

            Assert.ThrowsAsync<InvalidOperationException>(() => client.SignInWithGameCenterAsync());
            Assert.That(transport.Requests, Has.Count.EqualTo(1));
        }

        [Test]
        public async Task FinishesTheVerifiedEmailStep()
        {
            var transport = new FakeTransport(request =>
            {
                if (request.Path == TokenPath) return FakeTransport.Json(403, EmailRequired());
                if (request.Path == SendPath) return FakeTransport.Json(202, "{\"expires_in\":600,\"resend_after\":60}");
                return request.Body.Contains("\"code\":\"123456\"")
                    ? FakeTransport.Json(200, Signed(GameCenterUserId))
                    : FakeTransport.Json(400, Error("invalid_code"));
            });
            var clock = new FakeClock();
            var client = Client(transport, clock, new FakeGameCenter());

            var required = Assert.ThrowsAsync<Auth4EmailVerificationRequiredException>(
                () => client.SignInWithGameCenterAsync());
            Assert.That(required.Reason, Is.EqualTo("no_email"));
            Assert.That(required.StatusCode, Is.EqualTo(403));
            Assert.That(required.Message, Does.Not.Contain(Continuation));
            Assert.That(required.Continuation.ExpiresAt, Is.EqualTo(clock.UtcNow.AddSeconds(600)));
            Assert.That(client.CurrentSession, Is.Null);

            await client.SendGameCenterEmailCodeAsync(required.Continuation, " Player@Example.test ");
            var send = transport.To(SendPath).Single();
            Assert.That(send.Body, Does.Contain("\"continuation\":\"" + Continuation + "\""));
            Assert.That(send.Body, Does.Contain("\"email\":\"Player@Example.test\""));

            var wrong = Assert.ThrowsAsync<Auth4Exception>(
                () => client.ConfirmGameCenterEmailCodeAsync(required.Continuation, "000000"));
            Assert.That(wrong.Error, Is.EqualTo("invalid_code"));

            var session = await client.ConfirmGameCenterEmailCodeAsync(required.Continuation, "123456");
            Assert.That(session.UserId, Is.EqualTo(GameCenterUserId));
            Assert.That(transport.To(ConfirmPath).Count(), Is.EqualTo(2));

            clock.Advance(TimeSpan.FromSeconds(601));
            var expired = Assert.ThrowsAsync<Auth4Exception>(
                () => client.SendGameCenterEmailCodeAsync(required.Continuation, "player@example.test"));
            Assert.That(expired.Error, Is.EqualTo("step_expired"));
        }

        [Test]
        public void RejectsAMalformedContinuation()
        {
            var transport = new FakeTransport(request => FakeTransport.Json(
                403,
                "{\"error\":\"email_verification_required\",\"continuation\":\"nope\",\"expires_in\":600}"));
            var client = Client(transport, new FakeClock(), new FakeGameCenter());

            var error = Assert.ThrowsAsync<Auth4Exception>(() => client.SignInWithGameCenterAsync());
            Assert.That(error.Error, Is.EqualTo("invalid_response"));
        }

        [Test]
        public void IdentityRequiresTheSignedValues()
        {
            Assert.Throws<ArgumentException>(() => new GameCenterIdentity(
                null, "dev.auth4.arcade", "https://static.gc.apple.com/k.cer", new byte[] { 1 }, new byte[] { 1 }, 1));
            Assert.Throws<ArgumentException>(() => new GameCenterIdentity(
                PlayerId, "dev.auth4.arcade", "https://static.gc.apple.com/k.cer", new byte[0], new byte[] { 1 }, 1));
            Assert.Throws<ArgumentException>(() => new GameCenterIdentity(
                PlayerId, "dev.auth4.arcade", "https://static.gc.apple.com/k.cer", new byte[] { 1 }, new byte[] { 1 }, 0));
        }
    }
}
