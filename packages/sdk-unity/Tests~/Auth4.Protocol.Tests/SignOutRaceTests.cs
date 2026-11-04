using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using static Auth4.Protocol.Tests.Fixtures;

namespace Auth4.Protocol.Tests
{
    /// <summary>AUTH4D-400: an initial sign-in that began before SignOutAsync must not create a session afterward.</summary>
    public sealed class SignOutRaceTests
    {
        private const string GameCenterUserId = "usr_GameCenterPlayer0001";
        private static readonly string GuestPath = "/t/" + TenantId + "/guest";
        private static readonly string GcTokenPath = "/t/" + TenantId + "/game-center/token";
        private static readonly string GcConfirmPath = "/t/" + TenantId + "/game-center/email/confirm";
        private static readonly string Continuation = "gcc_" + new string('C', 43);

        private sealed class FakeGameCenter : IAuth4GameCenter
        {
            public bool IsSupported => true;

            public Task<GameCenterIdentity> FetchIdentityAsync(CancellationToken cancellationToken)
            {
                return Task.FromResult(new GameCenterIdentity(
                    "T:_9b2f6c1e7d4a3b5c8e0f1a2b3c4d5e6f",
                    "dev.auth4.arcade",
                    "https://static.gc.apple.com/public-key/gc-prod-12.cer",
                    new byte[] { 1, 2, 3, 250 },
                    new byte[] { 9, 8, 7 },
                    1_792_000_000_123UL));
            }
        }

        /// <summary>Holds responses to chosen paths until released; everything else answers immediately.</summary>
        private sealed class Held
        {
            public readonly TaskCompletionSource<Auth4HttpResponse> Gate =
                new TaskCompletionSource<Auth4HttpResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        private static Auth4Client NewClient(FakeTransport transport, FakeSecureStorage storage, List<Auth4Session> events)
        {
            var client = new Auth4Client(new Auth4ClientOptions
            {
                TenantId = TenantId,
                ClientId = ClientId,
                AuthOrigin = Origin,
                Transport = transport,
                Clock = new FakeClock(),
                SecureStorage = storage,
                GameCenter = new FakeGameCenter(),
            });
            client.SessionChanged += session => events.Add(session);
            return client;
        }

        private static Auth4HttpResponse Ok() => FakeTransport.Json(200, string.Empty);

        private static async Task WaitForRequestAsync(FakeTransport transport, string path)
        {
            for (var i = 0; i < 500 && !transport.To(path).Any(); i++)
            {
                await Task.Delay(5);
            }

            Assert.That(transport.To(path), Is.Not.Empty);
        }

        [Test]
        public async Task GuestSignInStartedBeforeSignOutCreatesNoSession()
        {
            var held = new Held();
            var first = true;
            var transport = new FakeTransport(request =>
            {
                if (request.Path == GuestPath && first)
                {
                    first = false;
                    return held.Gate.Task;
                }

                return Task.FromResult(request.Path == GuestPath ? FakeTransport.Json(200, GuestCreated("second-access", "second-refresh")) : Ok());
            });
            var storage = new FakeSecureStorage();
            var events = new List<Auth4Session>();
            var client = NewClient(transport, storage, events);

            var pending = client.SignInAsGuestAsync();
            await WaitForRequestAsync(transport, GuestPath);
            await client.SignOutAsync();
            held.Gate.SetResult(FakeTransport.Json(200, GuestCreated()));

            Assert.ThrowsAsync<InvalidOperationException>(() => pending);
            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(storage.Writes, Is.EqualTo(0));
            Assert.That(events.Where(session => session != null), Is.Empty);
            var revoke = transport.To("/oauth/revoke").Single();
            Assert.That(revoke.Body, Does.Contain(Token("guest-refresh")));

            var next = await client.SignInAsGuestAsync();
            Assert.That(next.IsGuest, Is.True);
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("second-access")));
        }

        [Test]
        public async Task DeviceApprovalAfterSignOutCreatesNoSession()
        {
            var held = new Held();
            var transport = new FakeTransport(request =>
            {
                if (request.Path == "/device/authorization")
                {
                    return Task.FromResult(FakeTransport.Json(200, DeviceStart()));
                }

                if (request.Path == "/oauth/revoke")
                {
                    return Task.FromResult(Ok());
                }

                return held.Gate.Task;
            });
            var storage = new FakeSecureStorage();
            var events = new List<Auth4Session>();
            var client = NewClient(transport, storage, events);

            var authorization = await client.StartDeviceAuthorizationAsync();
            var poll = client.PollDeviceAuthorizationAsync(authorization);
            await WaitForRequestAsync(transport, "/oauth/token");
            await client.SignOutAsync();
            held.Gate.SetResult(FakeTransport.Json(200, TokenJson("device-access", "device-refresh")));

            Assert.ThrowsAsync<InvalidOperationException>(() => poll);
            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(storage.Writes, Is.EqualTo(0));
            Assert.That(events.Where(session => session != null), Is.Empty);
            Assert.That(transport.To("/oauth/revoke").Single().Body, Does.Contain(Token("device-refresh")));
        }

        [Test]
        public async Task DeviceAuthorizationStartedBeforeSignOutIsStaleWhenResumed()
        {
            var transport = new FakeTransport(request =>
            {
                if (request.Path == "/device/authorization")
                {
                    return FakeTransport.Json(200, DeviceStart());
                }

                return request.Path == "/oauth/revoke"
                    ? Ok()
                    : FakeTransport.Json(200, TokenJson("device-access", "device-refresh"));
            });
            var events = new List<Auth4Session>();
            var client = NewClient(transport, new FakeSecureStorage(), events);

            var stale = await client.StartDeviceAuthorizationAsync();
            await client.SignOutAsync();

            Assert.ThrowsAsync<InvalidOperationException>(() => client.PollDeviceAuthorizationAsync(stale));
            Assert.That(client.CurrentSession, Is.Null);

            var fresh = await client.StartDeviceAuthorizationAsync();
            var session = await client.PollDeviceAuthorizationAsync(fresh);
            Assert.That(session, Is.Not.Null);
        }

        [Test]
        public async Task GameCenterSignInStartedBeforeSignOutCreatesNoSession()
        {
            var held = new Held();
            var transport = new FakeTransport(request =>
            {
                if (request.Path == GcTokenPath)
                {
                    return held.Gate.Task;
                }

                return Task.FromResult(Ok());
            });
            var storage = new FakeSecureStorage();
            var events = new List<Auth4Session>();
            var client = NewClient(transport, storage, events);

            var pending = client.SignInWithGameCenterAsync();
            await WaitForRequestAsync(transport, GcTokenPath);
            await client.SignOutAsync();
            held.Gate.SetResult(FakeTransport.Json(
                200,
                TokenJson("gc-access", "gc-refresh", "ses_GameCenter0000000001", "\"user_id\":\"" + GameCenterUserId + "\"")));

            Assert.ThrowsAsync<InvalidOperationException>(() => pending);
            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(storage.Writes, Is.EqualTo(0));
            Assert.That(events.Where(session => session != null), Is.Empty);
            Assert.That(transport.To("/oauth/revoke").Single().Body, Does.Contain(Token("gc-refresh")));
        }

        [Test]
        public async Task GameCenterEmailContinuationKeepsItsOriginalGeneration()
        {
            var held = new Held();
            var transport = new FakeTransport(request =>
            {
                if (request.Path == GcTokenPath)
                {
                    return Task.FromResult(FakeTransport.Json(
                        403,
                        "{\"error\":\"email_verification_required\",\"continuation\":\"" + Continuation +
                        "\",\"reason\":\"no_email\",\"expires_in\":600}"));
                }

                if (request.Path == GcConfirmPath)
                {
                    return held.Gate.Task;
                }

                return Task.FromResult(Ok());
            });
            var storage = new FakeSecureStorage();
            var events = new List<Auth4Session>();
            var client = NewClient(transport, storage, events);

            var required = Assert.ThrowsAsync<Auth4EmailVerificationRequiredException>(
                () => client.SignInWithGameCenterAsync());
            var pending = client.ConfirmGameCenterEmailCodeAsync(required.Continuation, "123456");
            await WaitForRequestAsync(transport, GcConfirmPath);
            await client.SignOutAsync();
            held.Gate.SetResult(FakeTransport.Json(
                200,
                TokenJson("gc-access", "gc-refresh", "ses_GameCenter0000000001", "\"user_id\":\"" + GameCenterUserId + "\"")));

            Assert.ThrowsAsync<InvalidOperationException>(() => pending);
            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(storage.Writes, Is.EqualTo(0));
            Assert.That(events.Where(session => session != null), Is.Empty);
            Assert.That(transport.To("/oauth/revoke").Single().Body, Does.Contain(Token("gc-refresh")));
        }
    }
}
