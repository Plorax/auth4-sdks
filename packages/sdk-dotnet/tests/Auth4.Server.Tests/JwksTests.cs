using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Auth4.Server.Tests
{
    public class JwksTests
    {
        private const string JwksUrl = Ids.Issuer + "/.well-known/jwks.json";
        private TestKey key = null!;
        private FakeIssuer issuer = null!;
        private TestClock clock = null!;
        private Auth4ServerClient client = null!;

        [SetUp]
        public void SetUp()
        {
            key = new TestKey("key-1");
            issuer = new FakeIssuer(key);
            clock = new TestClock();
            client = new Auth4ServerClient(new Auth4ServerOptions
            {
                TenantId = Ids.Tenant,
                Issuer = Ids.Issuer,
                Audience = Ids.Client,
                HttpClient = issuer.Client(),
                Now = () => clock.Now,
                JwksCacheTtl = TimeSpan.FromMinutes(5),
                JwksRefreshCooldown = TimeSpan.FromSeconds(30),
            });
        }

        [TearDown]
        public void TearDown()
        {
            client.Dispose();
            issuer.Dispose();
            key.Dispose();
        }

        private string Token(TestKey signer) => Tokens.Sign(signer, Tokens.AccessClaims(clock.Now.ToUnixTimeSeconds()));

        private Auth4TokenErrorCode Refused(string token) =>
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(token))!.Code;

        private void ServeJwks(object body) => issuer.Route(JwksUrl, _ => FakeIssuer.Json(body));

        [Test]
        public async Task CachesKeysUntilTheTtlExpires()
        {
            await client.ValidateAccessTokenAsync(Token(key));
            await client.ValidateAccessTokenAsync(Token(key));
            Assert.That(issuer.Count(JwksUrl), Is.EqualTo(1));
            clock.Advance(TimeSpan.FromMinutes(5));
            await client.ValidateAccessTokenAsync(Token(key));
            Assert.That(issuer.Count(JwksUrl), Is.EqualTo(2));
        }

        [Test]
        public async Task RefreshesOnceForAnUnknownKidSoRotationNeedsNoRestart()
        {
            await client.ValidateAccessTokenAsync(Token(key));
            using var rotated = new TestKey("key-2");
            issuer.Keys.Add(rotated);
            Assert.That((await client.ValidateAccessTokenAsync(Token(rotated))).Subject, Is.EqualTo(Ids.User));
            Assert.That(issuer.Count(JwksUrl), Is.EqualTo(2));

            // A second unknown kid inside the cooldown can't force another fetch.
            using var unknown = new TestKey("key-3");
            Assert.That(Refused(Token(unknown)), Is.EqualTo(Auth4TokenErrorCode.JwksRefreshLimited));
            Assert.That(issuer.Count(JwksUrl), Is.EqualTo(2));

            clock.Advance(TimeSpan.FromSeconds(30));
            Assert.That(Refused(Token(unknown)), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            Assert.That(issuer.Count(JwksUrl), Is.EqualTo(3));
        }

        [Test]
        public async Task SharesOneFetchBetweenConcurrentCallers()
        {
            var gate = new TaskCompletionSource<bool>();
            issuer.Route(JwksUrl, async _ =>
            {
                await gate.Task;
                return FakeIssuer.Json(new { keys = new[] { key.PublicJwk() } });
            });
            var token = Token(key);
            var calls = Enumerable.Range(0, 10).Select(_ => client.ValidateAccessTokenAsync(token)).ToArray();
            gate.SetResult(true);
            await Task.WhenAll(calls);
            Assert.That(issuer.Count(JwksUrl), Is.EqualTo(1));
        }

        [Test]
        public void FailsClosedWhenKeysAreUnavailableAndRateLimitsRetries()
        {
            issuer.Route(JwksUrl, _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            var error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(Token(key)))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.JwksUnavailable));
            Assert.That(error.IsOutage, Is.True);
            Assert.That(error.CodeName, Is.EqualTo("jwks_unavailable"));
            Assert.That(Refused(Token(key)), Is.EqualTo(Auth4TokenErrorCode.JwksRefreshLimited));
            Assert.That(issuer.Count(JwksUrl), Is.EqualTo(1));
        }

        private static IEnumerable<TestCaseData> UnusableKeySets()
        {
            yield return new TestCaseData((Func<TestKey, object>)(k => new { keys = Array.Empty<object>() })).SetName("no keys");
            yield return new TestCaseData((Func<TestKey, object>)(k => new { other = 1 })).SetName("no keys member");
            yield return new TestCaseData((Func<TestKey, object>)(k => new { keys = new[] { k.PublicJwk(), k.PublicJwk() } })).SetName("duplicate kid");
            yield return new TestCaseData((Func<TestKey, object>)(k => new { keys = Enumerable.Repeat(k.PublicJwk(), 65).ToArray() })).SetName("more than 64 keys");
            yield return new TestCaseData((Func<TestKey, object>)(k => new { keys = new[] { With(k.PublicJwk(), "alg", "RS512") } })).SetName("other alg only");
            yield return new TestCaseData((Func<TestKey, object>)(k => new { keys = new[] { With(k.PublicJwk(), "use", "enc") } })).SetName("encryption key only");
            yield return new TestCaseData((Func<TestKey, object>)(k => new { keys = new[] { With(k.PublicJwk(), "d", "AQAB") } })).SetName("private key only");
            yield return new TestCaseData((Func<TestKey, object>)(k => new { keys = new[] { With(k.PublicJwk(), "key_ops", new[] { "sign" }) } })).SetName("sign-only key_ops");
            yield return new TestCaseData((Func<TestKey, object>)(k => new { keys = new[] { With(k.PublicJwk(), "n", "AQAB") } })).SetName("short modulus");
        }

        private static Dictionary<string, object?> With(Dictionary<string, object?> jwk, string name, object value)
        {
            jwk[name] = value;
            return jwk;
        }

        [TestCaseSource(nameof(UnusableKeySets))]
        public void RefusesUnusableKeySets(Func<TestKey, object> body)
        {
            ServeJwks(body(key));
            Assert.That(Refused(Token(key)), Is.EqualTo(Auth4TokenErrorCode.JwksUnavailable));
        }

        [Test]
        public async Task SkipsUnusableKeysNextToAUsableOne()
        {
            using var other = new TestKey("key-enc");
            ServeJwks(new { keys = new object[] { With(other.PublicJwk(), "use", "enc"), new { kty = "EC", kid = "ec" }, key.PublicJwk() } });
            Assert.That((await client.ValidateAccessTokenAsync(Token(key))).Subject, Is.EqualTo(Ids.User));
            // The unknown kid triggers one refresh, which still has no usable key-enc.
            Assert.That(Refused(Token(other)), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            Assert.That(issuer.Count(JwksUrl), Is.EqualTo(2));
        }

        [Test]
        public void RefusesOversizedAndRedirectedResponses()
        {
            issuer.Route(JwksUrl, _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"keys\":[],\"pad\":\"" + new string('x', 300 * 1024) + "\"}", Encoding.UTF8, "application/json"),
            });
            Assert.That(Refused(Token(key)), Is.EqualTo(Auth4TokenErrorCode.JwksUnavailable));

            clock.Advance(TimeSpan.FromMinutes(1));
            issuer.Route(JwksUrl, request =>
            {
                var response = FakeIssuer.Json(new { keys = new[] { key.PublicJwk() } });
                // What an auto-redirecting HttpClient reports after following a Location header.
                response.RequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://elsewhere.test/jwks.json");
                return response;
            });
            Assert.That(Refused(Token(key)), Is.EqualTo(Auth4TokenErrorCode.JwksUnavailable));
        }

        [Test]
        public async Task OnlyEverCallsTheConfiguredIssuer()
        {
            await client.ValidateAccessTokenAsync(Token(key));
            Assert.That(issuer.Requests.Select(request => request.RequestUri!.ToString()).Distinct(), Is.EqualTo(new[] { JwksUrl }));
        }
    }
}
