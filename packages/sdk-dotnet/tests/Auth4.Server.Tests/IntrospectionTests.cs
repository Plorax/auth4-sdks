using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Auth4.Server.Tests
{
    public class IntrospectionTests
    {
        private const string IntrospectUrl = Ids.Origin + "/oauth/introspect?tenant_id=" + Ids.Tenant;
        private TestKey key = null!;
        private FakeIssuer issuer = null!;
        private TestClock clock = null!;
        private Auth4ServerClient client = null!;
        private bool active;

        [SetUp]
        public void SetUp()
        {
            key = new TestKey("key-1");
            issuer = new FakeIssuer(key);
            clock = new TestClock();
            active = true;
            issuer.Route(IntrospectUrl, _ => FakeIssuer.Json(active
                ? new { active = true, sub = Ids.User, client_id = Ids.Client, jti = Ids.Jti, tenant_id = Ids.Tenant }
                : (object)new { active = false }));
            client = Create(TimeSpan.FromSeconds(5));
        }

        [TearDown]
        public void TearDown()
        {
            client.Dispose();
            issuer.Dispose();
            key.Dispose();
        }

        private Auth4ServerClient Create(TimeSpan cacheTtl, string secret = Ids.ServerSecret) => new Auth4ServerClient(new Auth4ServerOptions
        {
            TenantId = Ids.Tenant,
            Issuer = Ids.Issuer,
            Audience = Ids.Client,
            HttpClient = issuer.Client(),
            Now = () => clock.Now,
            Introspection = new Auth4IntrospectionOptions { ClientId = Ids.ServerClient, ClientSecret = secret, CacheTtl = cacheTtl },
        });

        private string Token() => Tokens.Sign(key, Tokens.AccessClaims());

        [Test]
        public async Task SendsTheTokenWithBasicCredentialsToTheDerivedEndpoint()
        {
            await client.ValidateAccessTokenAsync(Token());
            Assert.That(client.IntrospectionUrl, Is.EqualTo(IntrospectUrl));
            var request = issuer.Requests.Single(r => r.RequestUri!.ToString() == IntrospectUrl);
            Assert.That(request.Method, Is.EqualTo(HttpMethod.Post));
            Assert.That(request.Headers.Authorization!.Scheme, Is.EqualTo("Basic"));
            var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(request.Headers.Authorization.Parameter!));
            Assert.That(credentials, Is.EqualTo(Ids.ServerClient + ":" + Ids.ServerSecret));
            Assert.That(issuer.Bodies.Single(), Is.EqualTo("token=" + Uri.EscapeDataString(Token())));
            Assert.That(request.RequestUri!.Query, Does.Not.Contain("token="), "the token never travels in the URL");
        }

        [Test]
        public async Task ReusesAnActiveAnswerForTheCacheTtl()
        {
            await client.ValidateAccessTokenAsync(Token());
            await client.ValidateAccessTokenAsync(Token());
            Assert.That(issuer.Count(IntrospectUrl), Is.EqualTo(1));
            clock.Advance(TimeSpan.FromSeconds(5));
            await client.ValidateAccessTokenAsync(Token());
            Assert.That(issuer.Count(IntrospectUrl), Is.EqualTo(2));
        }

        [Test]
        public async Task ChecksEveryRequestWhenTheTtlIsZero()
        {
            using var uncached = Create(TimeSpan.Zero);
            await uncached.ValidateAccessTokenAsync(Token());
            await uncached.ValidateAccessTokenAsync(Token());
            Assert.That(issuer.Count(IntrospectUrl), Is.EqualTo(2));
        }

        [Test]
        public async Task RefusesARevokedSessionAndRemembersItUntilExpiry()
        {
            await client.ValidateAccessTokenAsync(Token());
            active = false;
            clock.Advance(TimeSpan.FromSeconds(5));
            var error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(Token()))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            active = true;
            clock.Advance(TimeSpan.FromMinutes(1));
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(Token()));
            Assert.That(issuer.Count(IntrospectUrl), Is.EqualTo(2));
        }

        [Test]
        public void FailsClosedWhenTheEndpointIsUnavailable()
        {
            issuer.Route(IntrospectUrl, _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            var error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(Token()))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.IntrospectionUnavailable));
            Assert.That(error.IsOutage, Is.True);

            issuer.Route(IntrospectUrl, _ => FakeIssuer.Json(new { active = "yes" }));
            error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(Token()))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.IntrospectionUnavailable));
        }

        [Test]
        public void RefusesAnActiveAnswerForADifferentToken()
        {
            issuer.Route(IntrospectUrl, _ => FakeIssuer.Json(new { active = true, sub = "usr_someoneelse0000001", client_id = Ids.Client, jti = Ids.Jti, tenant_id = Ids.Tenant }));
            var error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(Token()))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
        }

        [Test]
        public void SkipsIntrospectionForTokensThatFailOfflineChecks()
        {
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(Tokens.Sign(key, Tokens.AccessClaims().With("aud", Ids.OtherClient))));
            Assert.That(issuer.Count(IntrospectUrl), Is.EqualTo(0));
        }

        [Test]
        public async Task SharesOneRequestBetweenConcurrentCallers()
        {
            var gate = new TaskCompletionSource<bool>();
            issuer.Route(IntrospectUrl, async _ =>
            {
                await gate.Task;
                return FakeIssuer.Json(new { active = true, sub = Ids.User, client_id = Ids.Client, jti = Ids.Jti, tenant_id = Ids.Tenant });
            });
            var token = Token();
            var calls = Enumerable.Range(0, 8).Select(_ => client.ValidateAccessTokenAsync(token)).ToArray();
            await Task.Delay(50);
            gate.SetResult(true);
            await Task.WhenAll(calls);
            Assert.That(issuer.Count(IntrospectUrl), Is.EqualTo(1));
        }

        [Test]
        public void KeepsTheSecretOutOfStringsAndRefusesWeakConfiguration()
        {
            var options = new Auth4IntrospectionOptions { ClientId = Ids.ServerClient, ClientSecret = Ids.ServerSecret };
            Assert.That(options.ToString(), Does.Not.Contain(Ids.ServerSecret));
            Assert.That(client.ToString(), Does.Not.Contain(Ids.ServerSecret));
            Assert.Throws<ArgumentException>(() => Create(TimeSpan.Zero, "short"));
            Assert.Throws<ArgumentOutOfRangeException>(() => Create(TimeSpan.FromSeconds(61)));
            Assert.Throws<ArgumentException>(() => new Auth4ServerClient(new Auth4ServerOptions
            {
                TenantId = Ids.Tenant,
                Issuer = Ids.Issuer,
                Audience = Ids.Client,
                Introspection = new Auth4IntrospectionOptions { ClientId = "server", ClientSecret = Ids.ServerSecret },
            }));
        }
    }
}
