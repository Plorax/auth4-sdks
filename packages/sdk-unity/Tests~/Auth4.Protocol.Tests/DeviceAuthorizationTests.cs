using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using static Auth4.Protocol.Tests.Fixtures;

namespace Auth4.Protocol.Tests
{
    public sealed class DeviceAuthorizationTests
    {
        private static FakeTransport DeviceServer(params Func<string>[] pollResults)
        {
            var poll = 0;
            return new FakeTransport(request =>
            {
                if (request.Path == "/device/authorization")
                {
                    return FakeTransport.Json(200, DeviceStart());
                }

                var next = pollResults[Math.Min(poll++, pollResults.Length - 1)]();
                return FakeTransport.Json(next.Contains("access_token") ? 200 : 400, next);
            });
        }

        private static string Pending() => Error("authorization_pending");

        private static string Approved() => TokenJson("device-access", "device-refresh");

        [Test]
        public async Task StartSendsPublicClientRequestAndExposesCode()
        {
            var transport = DeviceServer(Pending);
            var clock = new FakeClock();
            var client = Client(transport, clock);

            var authorization = await client.StartDeviceAuthorizationAsync("openid offline_access openid");

            var request = transport.Requests.Single();
            Assert.That(request.Uri.ToString(), Is.EqualTo(Origin + "/device/authorization?tenant_id=" + TenantId));
            Assert.That(request.ContentType, Is.EqualTo("application/x-www-form-urlencoded"));
            Assert.That(request.Form["client_id"], Is.EqualTo(ClientId));
            Assert.That(request.Form["scope"], Is.EqualTo("openid offline_access"));
            Assert.That(request.Form.ContainsKey("client_secret"), Is.False);
            Assert.That(request.Headers.ContainsKey("Authorization"), Is.False);
            Assert.That(authorization.UserCode, Is.EqualTo("ABCD2345"));
            Assert.That(authorization.VerificationUriComplete.Query, Does.Contain("user_code=ABCD2345"));
            Assert.That(authorization.ExpiresAt, Is.EqualTo(clock.UtcNow.AddSeconds(600)));
            Assert.That(authorization.IntervalSeconds, Is.EqualTo(5));
        }

        [Test]
        public void StartRequiresOpenIdAndRejectsForeignVerificationUri()
        {
            var client = Client(DeviceServer(Pending), new FakeClock());
            Assert.ThrowsAsync<ArgumentException>(() => client.StartDeviceAuthorizationAsync("profile"));

            var phishing = new FakeTransport(_ => FakeTransport.Json(200, DeviceStart(600, "https://evil.example")));
            var error = Assert.ThrowsAsync<Auth4Exception>(() => Client(phishing, new FakeClock()).StartDeviceAuthorizationAsync());
            Assert.That(error.Error, Is.EqualTo("invalid_response"));
        }

        [Test]
        public async Task PendingThenApprovalCreatesSession()
        {
            var transport = DeviceServer(Pending, Pending, Approved);
            var clock = new FakeClock();
            var client = Client(transport, clock);
            Auth4Session changed = null;
            client.SessionChanged += session => changed = session;

            var authorization = await client.StartDeviceAuthorizationAsync();
            var session = await client.PollDeviceAuthorizationAsync(authorization);

            var polls = transport.To("/oauth/token").ToList();
            Assert.That(polls, Has.Count.EqualTo(3));
            Assert.That(polls.All(poll => poll.Uri.Query == "?tenant_id=" + TenantId));
            Assert.That(polls.All(poll => poll.Form["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"));
            Assert.That(polls.All(poll => poll.Form["client_id"] == ClientId && poll.Form["device_code"] == Token("device")));
            Assert.That(polls.All(poll => !poll.Form.ContainsKey("client_secret")));
            Assert.That(clock.Delays, Is.EqualTo(new[] { TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5) }));
            Assert.That(session.IsGuest, Is.False);
            Assert.That(session.CanRefresh, Is.True);
            Assert.That(changed, Is.SameAs(session));
            Assert.That(authorization.IsCompleted, Is.True);
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("device-access")));
        }

        [Test]
        public async Task SlowDownAddsFiveSecondsToEverySubsequentPoll()
        {
            var clock = new FakeClock();
            var client = Client(DeviceServer(Pending, () => Error("slow_down"), Pending, Approved), clock);

            await client.PollDeviceAuthorizationAsync(await client.StartDeviceAuthorizationAsync());

            Assert.That(clock.Delays.Select(delay => delay.TotalSeconds), Is.EqualTo(new double[] { 5, 5, 10, 10 }));
        }

        [Test]
        public async Task DenialIsTerminal()
        {
            var transport = DeviceServer(Pending, () => Error("access_denied"));
            var client = Client(transport, new FakeClock());
            var authorization = await client.StartDeviceAuthorizationAsync();

            var error = Assert.ThrowsAsync<Auth4DeviceAuthorizationException>(() => client.PollDeviceAuthorizationAsync(authorization));

            Assert.That(error.Reason, Is.EqualTo(DeviceAuthorizationFailure.Denied));
            Assert.That(authorization.IsCompleted, Is.True);
            Assert.That(client.CurrentSession, Is.Null);
            Assert.ThrowsAsync<InvalidOperationException>(() => client.PollDeviceAuthorizationAsync(authorization));
            Assert.That(transport.To("/oauth/token").Count(), Is.EqualTo(2));
        }

        [Test]
        public async Task ServerExpiryIsTerminal()
        {
            var client = Client(DeviceServer(Pending, () => Error("expired_token")), new FakeClock());
            var authorization = await client.StartDeviceAuthorizationAsync();

            var error = Assert.ThrowsAsync<Auth4DeviceAuthorizationException>(() => client.PollDeviceAuthorizationAsync(authorization));

            Assert.That(error.Reason, Is.EqualTo(DeviceAuthorizationFailure.Expired));
            Assert.That(authorization.IsCompleted, Is.True);
        }

        [Test]
        public async Task PollingStopsAtLocalExpiryWithoutPollingPastIt()
        {
            var transport = DeviceServer(Pending);
            var clock = new FakeClock();
            var client = Client(transport, clock);
            var authorization = await client.StartDeviceAuthorizationAsync();

            var error = Assert.ThrowsAsync<Auth4DeviceAuthorizationException>(() => client.PollDeviceAuthorizationAsync(authorization));

            Assert.That(error.Reason, Is.EqualTo(DeviceAuthorizationFailure.Expired));
            Assert.That(transport.To("/oauth/token").Count(), Is.EqualTo(119));
            Assert.That(clock.UtcNow, Is.EqualTo(authorization.ExpiresAt));
        }

        [Test]
        public async Task PollingIsBoundedByAttemptLimit()
        {
            var transport = DeviceServer(Pending);
            var client = new Auth4Client(new Auth4ClientOptions
            {
                TenantId = TenantId,
                ClientId = ClientId,
                AuthOrigin = Origin,
                Transport = transport,
                Clock = new FakeClock(),
                MaxDevicePollAttempts = 3,
            });

            var authorization = await client.StartDeviceAuthorizationAsync();
            Assert.ThrowsAsync<Auth4DeviceAuthorizationException>(() => client.PollDeviceAuthorizationAsync(authorization));
            Assert.That(transport.To("/oauth/token").Count(), Is.EqualTo(3));
        }

        [Test]
        public async Task CancellationStopsPollingAndCanBeResumed()
        {
            var transport = DeviceServer(Pending, Pending, Approved);
            var clock = new FakeClock();
            var client = Client(transport, clock);
            var authorization = await client.StartDeviceAuthorizationAsync();
            using (var cancellation = new CancellationTokenSource())
            {
                clock.OnDelay = count =>
                {
                    if (count == 3)
                    {
                        cancellation.Cancel();
                    }
                };

                Assert.CatchAsync<OperationCanceledException>(() => client.PollDeviceAuthorizationAsync(authorization, cancellation.Token));
            }

            Assert.That(transport.To("/oauth/token").Count(), Is.EqualTo(2));
            Assert.That(authorization.IsCompleted, Is.False);
            Assert.That(client.CurrentSession, Is.Null);

            clock.OnDelay = null;
            var session = await client.PollDeviceAuthorizationAsync(authorization);
            Assert.That(session, Is.Not.Null);
            Assert.That(transport.To("/oauth/token").Count(), Is.EqualTo(3));
        }

        [Test]
        public async Task TransientFailuresBackOffThenRecover()
        {
            var clock = new FakeClock();
            var failures = 0;
            var transport = new FakeTransport(request =>
            {
                if (request.Path == "/device/authorization")
                {
                    return FakeTransport.Json(200, DeviceStart());
                }

                return failures++ < 2
                    ? FakeTransport.Json(503, "unavailable")
                    : FakeTransport.Json(200, Approved());
            });
            var client = Client(transport, clock);

            await client.PollDeviceAuthorizationAsync(await client.StartDeviceAuthorizationAsync());

            Assert.That(clock.Delays.Select(delay => delay.TotalSeconds), Is.EqualTo(new double[] { 5, 10, 20 }));
        }

        [Test]
        public async Task DeviceSignInRefusesToReplaceActiveSession()
        {
            var transport = new FakeTransport(request => FakeTransport.Json(200, GuestCreated()));
            var client = Client(transport, new FakeClock());
            await client.SignInAsGuestAsync();

            Assert.ThrowsAsync<InvalidOperationException>(() => client.StartDeviceAuthorizationAsync());
        }
    }
}
