using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Auth4.Server.Tests
{
    /// <summary>AUTH4D-391: ActivitySource and Meter output, its bounded fields and what it must never carry.</summary>
    [NonParallelizable]
    public class DiagnosticsTests
    {
        private const string JwksUrl = Ids.Issuer + "/.well-known/jwks.json";
        private const string IntrospectUrl = Ids.Origin + "/oauth/introspect?tenant_id=" + Ids.Tenant;
        private static readonly string[] Outcomes = { "success", "invalid_token", "unavailable", "refresh_limited", "error" };
        private static readonly string[] Operations = { "validate_access_token", "validate_id_token", "jwks_fetch", "introspect" };

        private TestKey key = null!;
        private FakeIssuer issuer = null!;
        private TestClock clock = null!;
        private ActivityListener activityListener = null!;
        private MeterListener meterListener = null!;
        private ConcurrentQueue<Activity> activities = new ConcurrentQueue<Activity>();
        private ConcurrentQueue<Measurement> measurements = new ConcurrentQueue<Measurement>();

        private sealed record Measurement(string Instrument, double Value, IReadOnlyDictionary<string, string?> Tags);

        [SetUp]
        public void SetUp()
        {
            // Fresh queues per test, captured by this test's listeners, so a late callback can't reach the next test.
            var seenActivities = activities = new ConcurrentQueue<Activity>();
            var seenMeasurements = measurements = new ConcurrentQueue<Measurement>();
            key = new TestKey("key-1");
            issuer = new FakeIssuer(key);
            clock = new TestClock();
            issuer.Route(IntrospectUrl, _ => FakeIssuer.Json(new { active = true, sub = Ids.User, client_id = Ids.Client, jti = Ids.Jti, tenant_id = Ids.Tenant }));
            activityListener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == Auth4Diagnostics.ActivitySourceName,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
                ActivityStopped = activity => seenActivities.Enqueue(activity),
            };
            ActivitySource.AddActivityListener(activityListener);
            meterListener = new MeterListener
            {
                InstrumentPublished = (instrument, listener) =>
                {
                    if (instrument.Meter.Name == Auth4Diagnostics.MeterName) listener.EnableMeasurementEvents(instrument);
                },
            };
            meterListener.SetMeasurementEventCallback<double>((i, v, t, _) => Record(seenMeasurements, i, v, t));
            meterListener.SetMeasurementEventCallback<long>((i, v, t, _) => Record(seenMeasurements, i, v, t));
            meterListener.Start();
        }

        [TearDown]
        public void TearDown()
        {
            activityListener.Dispose();
            meterListener.Dispose();
            issuer.Dispose();
            key.Dispose();
        }

        private static void Record(ConcurrentQueue<Measurement> queue, Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            var copy = new Dictionary<string, string?>();
            foreach (var tag in tags) copy[tag.Key] = tag.Value?.ToString();
            queue.Enqueue(new Measurement(instrument.Name, value, copy));
        }

        private Auth4ServerClient Create(bool introspect = false) => new Auth4ServerClient(new Auth4ServerOptions
        {
            TenantId = Ids.Tenant,
            Issuer = Ids.Issuer,
            Audience = Ids.Client,
            HttpClient = issuer.Client(),
            Now = () => clock.Now,
            JwksRefreshCooldown = TimeSpan.FromSeconds(30),
            Introspection = introspect
                ? new Auth4IntrospectionOptions { ClientId = Ids.ServerClient, ClientSecret = Ids.ServerSecret, CacheTtl = TimeSpan.Zero }
                : null,
        });

        private string AccessToken() => Tokens.Sign(key, Tokens.AccessClaims());

        private (string Operation, string Outcome)[] Seen() =>
            activities.Select(a => (Tag(a, "auth4.operation")!, Tag(a, "auth4.outcome")!)).ToArray();

        private static string? Tag(Activity activity, string name) => activity.GetTagItem(name)?.ToString();

        private IEnumerable<Measurement> Counts(string operation, string outcome) =>
            measurements.Where(m => m.Instrument == "auth4.server.operation.count" && m.Tags["auth4.operation"] == operation && m.Tags["auth4.outcome"] == outcome);

        [Test]
        public async Task ReportsASuccessfulVerificationWithItsKeyFetch()
        {
            using var client = Create();
            await client.ValidateAccessTokenAsync(AccessToken());
            Assert.That(Seen(), Is.EquivalentTo(new[] { ("jwks_fetch", "success"), ("validate_access_token", "success") }));
            Assert.That(Counts("validate_access_token", "success").Count(), Is.EqualTo(1));
            Assert.That(Counts("jwks_fetch", "success").Count(), Is.EqualTo(1));
            var duration = measurements.Single(m => m.Instrument == "auth4.server.operation.duration" && m.Tags["auth4.operation"] == "validate_access_token");
            Assert.That(duration.Value, Is.GreaterThanOrEqualTo(0));
            Assert.That(activities.All(a => a.Status != ActivityStatusCode.Error));
            Assert.That(activities.Select(a => a.Source.Name).Distinct(), Is.EqualTo(new[] { "Auth4.Server" }));

            // A cached key is not a fetch, so the second call adds one operation.
            activities.Clear();
            await client.ValidateAccessTokenAsync(AccessToken());
            Assert.That(Seen(), Is.EqualTo(new[] { ("validate_access_token", "success") }));
        }

        [Test]
        public async Task ReportsAnIdTokenCheck()
        {
            using var client = Create();
            await client.ValidateIdTokenAsync(Tokens.Sign(key, Tokens.IdClaims(), Tokens.Header(key, "JWT")), Ids.Client, "nonce-0123456789abcdef");
            Assert.That(Counts("validate_id_token", "success").Count(), Is.EqualTo(1));
        }

        [Test]
        public void CountsABadTokenAsInvalidWithoutMarkingTheActivityFailed()
        {
            using var client = Create();
            var token = Tokens.Sign(key, Tokens.AccessClaims().With("aud", Ids.OtherClient));
            var error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(token))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            Assert.That(Counts("validate_access_token", "invalid_token").Count(), Is.EqualTo(1));
            Assert.That(Counts("jwks_fetch", "success").Count(), Is.EqualTo(1), "the keys were reachable");
            Assert.That(activities.Single(a => Tag(a, "auth4.operation") == "validate_access_token").Status, Is.Not.EqualTo(ActivityStatusCode.Error));
        }

        [Test]
        public void CountsAnIdTokenForAnotherNonceAsInvalid()
        {
            using var client = Create();
            var token = Tokens.Sign(key, Tokens.IdClaims(), Tokens.Header(key, "JWT"));
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateIdTokenAsync(token, Ids.Client, "another-nonce-0123456789"));
            Assert.That(Counts("validate_id_token", "invalid_token").Count(), Is.EqualTo(1));
        }

        [Test]
        public void CountsAJwksOutageAsUnavailable()
        {
            issuer.Route(JwksUrl, _ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
            using var client = Create();
            var error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(AccessToken()))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.JwksUnavailable));
            Assert.That(Seen(), Is.EquivalentTo(new[] { ("jwks_fetch", "unavailable"), ("validate_access_token", "unavailable") }));
            Assert.That(activities.All(a => a.Status == ActivityStatusCode.Error));
        }

        [Test]
        public async Task CountsARefusedKeyRefreshAsRefreshLimited()
        {
            using var client = Create();
            await client.ValidateAccessTokenAsync(AccessToken());
            using var other = new TestKey("key-2");
            var unknown = Tokens.Sign(other, Tokens.AccessClaims());
            // The first unknown kid may refresh once; the cooldown blocks the next one.
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(unknown));
            measurements.Clear();
            activities.Clear();
            var error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(unknown))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.JwksRefreshLimited));
            Assert.That(Counts("jwks_fetch", "refresh_limited").Count(), Is.EqualTo(1));
            Assert.That(Counts("validate_access_token", "refresh_limited").Count(), Is.EqualTo(1));
        }

        [Test]
        public async Task ReportsIntrospectionSuccessAndOutage()
        {
            using var client = Create(introspect: true);
            await client.ValidateAccessTokenAsync(AccessToken());
            Assert.That(Counts("introspect", "success").Count(), Is.EqualTo(1));

            issuer.Route(IntrospectUrl, _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            var error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(AccessToken()))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.IntrospectionUnavailable));
            Assert.That(Counts("introspect", "unavailable").Count(), Is.EqualTo(1));
            Assert.That(Counts("validate_access_token", "unavailable").Count(), Is.EqualTo(1));
        }

        [Test]
        public void CountsAnInactiveSessionAsInvalidAndAnUnreadableAnswerAsUnavailable()
        {
            using var client = Create(introspect: true);
            issuer.Route(IntrospectUrl, _ => FakeIssuer.Json(new { active = false }));
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(AccessToken()));
            Assert.That(Counts("introspect", "success").Count(), Is.EqualTo(1), "the endpoint answered");
            Assert.That(Counts("validate_access_token", "invalid_token").Count(), Is.EqualTo(1));

            issuer.Route(IntrospectUrl, _ => FakeIssuer.Json(new { nonsense = 1 }));
            using var second = Create(introspect: true);
            Assert.ThrowsAsync<Auth4TokenException>(() => second.ValidateAccessTokenAsync(AccessToken()));
            Assert.That(Counts("introspect", "unavailable").Count(), Is.EqualTo(1));
        }

        [Test]
        public void KeepsEveryFieldBoundedAndFreeOfSensitiveData()
        {
            var token = AccessToken();
            var idToken = Tokens.Sign(key, Tokens.IdClaims(), Tokens.Header(key, "JWT"));
            using var client = Create(introspect: true);
            // Success, invalid and outage paths, so every kind of exception passes through the code.
            client.ValidateAccessTokenAsync(token).GetAwaiter().GetResult();
            client.ValidateIdTokenAsync(idToken, Ids.Client, "nonce-0123456789abcdef").GetAwaiter().GetResult();
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(Tokens.Sign(key, Tokens.AccessClaims().With("aud", Ids.OtherClient))));
            issuer.Route(IntrospectUrl, _ => new HttpResponseMessage(HttpStatusCode.BadGateway));
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(token));
            issuer.Route(JwksUrl, _ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
            clock.Advance(TimeSpan.FromHours(2));
            using var broken = Create();
            Assert.ThrowsAsync<Auth4TokenException>(() => broken.ValidateAccessTokenAsync(Tokens.Sign(key, Tokens.AccessClaims(clock.Now.ToUnixTimeSeconds()))));

            Assert.That(activities, Is.Not.Empty);
            Assert.That(measurements, Is.Not.Empty);
            var emitted = new List<string>();
            foreach (var activity in activities)
            {
                Assert.That(activity.TagObjects.Select(t => t.Key), Is.SubsetOf(new[] { "auth4.operation", "auth4.outcome" }));
                Assert.That(activity.Events, Is.Empty, "no exception events");
                Assert.That(activity.Baggage, Is.Empty);
                Assert.That(activity.StatusDescription, Is.Null);
                Assert.That(Operations, Does.Contain(Tag(activity, "auth4.operation")));
                Assert.That(Outcomes, Does.Contain(Tag(activity, "auth4.outcome")));
                emitted.Add(activity.OperationName);
                emitted.Add(activity.DisplayName);
                emitted.AddRange(activity.TagObjects.Select(t => $"{t.Key}={t.Value}"));
            }
            foreach (var measurement in measurements)
            {
                Assert.That(measurement.Tags.Keys, Is.EquivalentTo(new[] { "auth4.operation", "auth4.outcome" }));
                Assert.That(Operations, Does.Contain(measurement.Tags["auth4.operation"]));
                Assert.That(Outcomes, Does.Contain(measurement.Tags["auth4.outcome"]));
                emitted.Add(measurement.Instrument);
                emitted.AddRange(measurement.Tags.Select(t => $"{t.Key}={t.Value}"));
            }

            var secrets = new[]
            {
                token, idToken, token.Split('.')[1], token.Split('.')[2], Ids.ServerSecret, Ids.ServerClient, Ids.User, Ids.Session, Ids.Jti,
                Ids.Tenant, Ids.Client, Ids.OtherClient, Ids.Issuer, Ids.Origin, "player@example.test", "nonce-0123456789abcdef",
                "The token is invalid.", "could not be refreshed", "could not be checked",
            };
            var all = string.Join("\n", emitted);
            foreach (var secret in secrets) Assert.That(all, Does.Not.Contain(secret), $"diagnostics must not carry {secret.Length}-char fixture value");
        }

        [Test]
        public async Task LeavesResultsUnchangedWithoutListeners()
        {
            activityListener.Dispose();
            meterListener.Dispose();
            using var client = Create(introspect: true);
            var verified = await client.ValidateAccessTokenAsync(AccessToken());
            Assert.That(verified.Subject, Is.EqualTo(Ids.User));
            var bad = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync("not-a-token"))!;
            Assert.That(bad.Code, Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            Assert.That(bad.Message, Is.EqualTo("The token is invalid."));
        }
    }
}
