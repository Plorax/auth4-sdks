using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Auth4.Server.Tests
{
    public class IdTokenAndDiscoveryTests
    {
        private TestKey key = null!;
        private FakeIssuer issuer = null!;
        private Auth4ServerClient client = null!;

        [SetUp]
        public void SetUp()
        {
            key = new TestKey("key-1");
            issuer = new FakeIssuer(key);
            client = new Auth4ServerClient(new Auth4ServerOptions
            {
                TenantId = Ids.Tenant,
                AuthOrigin = Ids.Origin,
                Audience = Ids.Client,
                HttpClient = issuer.Client(),
                Now = () => Ids.Now,
            });
        }

        [TearDown]
        public void TearDown()
        {
            client.Dispose();
            issuer.Dispose();
            key.Dispose();
        }

        private string IdToken(Func<System.Collections.Generic.Dictionary<string, object?>, System.Collections.Generic.Dictionary<string, object?>>? change = null) =>
            Tokens.Sign(key, (change ?? (claims => claims))(Tokens.IdClaims()), Tokens.Header(key, "JWT"));

        [Test]
        public async Task VerifiesAnIdTokenOnItsOwnPath()
        {
            var token = await client.ValidateIdTokenAsync(IdToken(), Ids.Client, "nonce-0123456789abcdef");
            Assert.That(token.Subject, Is.EqualTo(Ids.User));
            Assert.That(token.ClientId, Is.EqualTo(Ids.Client));
            Assert.That(token.Email, Is.EqualTo("player@example.test"));
            Assert.That(token.EmailVerified, Is.True);
            Assert.That(token.AuthTime, Is.EqualTo(Ids.Now.AddSeconds(-10)));
        }

        [Test]
        public void KeepsAccessAndIdTokensApart()
        {
            // An ID token never passes as an access token, even for an API whose audience is the client ID.
            var error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(IdToken()))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            var access = Tokens.Sign(key, Tokens.AccessClaims());
            error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateIdTokenAsync(access, Ids.Client))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            // Re-signing ID claims with the access-token typ doesn't help either.
            error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(Tokens.Sign(key, Tokens.IdClaims())))!;
            Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
        }

        [Test]
        public void RefusesInvalidIdTokens()
        {
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateIdTokenAsync(IdToken(), Ids.OtherClient));
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateIdTokenAsync(IdToken(), Ids.Client, "another-nonce-0123456789"));
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateIdTokenAsync(IdToken(c => c.Without("nonce")), Ids.Client, "nonce-0123456789abcdef"));
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateIdTokenAsync(IdToken(c => c.Without("auth_time")), Ids.Client));
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateIdTokenAsync(IdToken(c => c.Without("email")), Ids.Client));
            Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateIdTokenAsync(IdToken(c => c.With("auth4_guest", true)), Ids.Client));
            Assert.Throws<ArgumentException>(() => client.ValidateIdTokenAsync(IdToken(), "not-a-client").GetAwaiter().GetResult());
        }

        [Test]
        public void DerivesTheIssuerFromTheAuthOrigin()
        {
            Assert.That(client.Issuer, Is.EqualTo(Ids.Issuer));
            Assert.That(Auth4ServerClient.IssuerFor("https://auth.auth4.dev", Ids.Tenant), Is.EqualTo("https://auth.auth4.dev/t/" + Ids.Tenant));
            Assert.That(Auth4ServerClient.IssuerFor("https://auth.auth4.dev/", Ids.Tenant), Is.EqualTo("https://auth.auth4.dev/t/" + Ids.Tenant));
            Assert.That(Auth4ServerClient.IssuerFor("http://127.0.0.1:8787", Ids.Tenant), Is.EqualTo("http://127.0.0.1:8787/t/" + Ids.Tenant));
            Assert.Throws<ArgumentException>(() => Auth4ServerClient.IssuerFor("http://auth.auth4.dev", Ids.Tenant));
            Assert.Throws<ArgumentException>(() => Auth4ServerClient.IssuerFor("https://auth.auth4.dev/path", Ids.Tenant));
        }

        [TestCase("https://auth.example.test/t/ten_qrstuvwxyzabcdef")]
        [TestCase("https://auth.example.test/t/ten_abcdefghijklmnop/")]
        [TestCase("https://auth.example.test/t/ten_abcdefghijklmnop?x=1")]
        [TestCase("https://AUTH.example.test/t/ten_abcdefghijklmnop")]
        [TestCase("https://user@auth.example.test/t/ten_abcdefghijklmnop")]
        [TestCase("http://auth.example.test/t/ten_abcdefghijklmnop")]
        [TestCase("not a url")]
        public void RefusesANonCanonicalIssuer(string configured)
        {
            Assert.Throws<ArgumentException>(() => new Auth4ServerClient(new Auth4ServerOptions { TenantId = Ids.Tenant, Issuer = configured, Audience = Ids.Client }));
        }

        [Test]
        public void ValidatesTheRestOfTheOptions()
        {
            Assert.Throws<ArgumentException>(() => new Auth4ServerClient(new Auth4ServerOptions { TenantId = "tenant", Issuer = Ids.Issuer, Audience = Ids.Client }));
            Assert.Throws<ArgumentException>(() => new Auth4ServerClient(new Auth4ServerOptions { TenantId = Ids.Tenant, Audience = Ids.Client }));
            Assert.Throws<ArgumentException>(() => new Auth4ServerClient(new Auth4ServerOptions { TenantId = Ids.Tenant, Issuer = Ids.Issuer, Audience = "" }));
            Assert.Throws<ArgumentException>(() => new Auth4ServerClient(new Auth4ServerOptions { TenantId = Ids.Tenant, Issuer = Ids.Issuer, Audience = "urn:auth4:management" }));
            Assert.Throws<ArgumentOutOfRangeException>(() => new Auth4ServerClient(new Auth4ServerOptions { TenantId = Ids.Tenant, Issuer = Ids.Issuer, Audience = Ids.Client, ClockTolerance = TimeSpan.FromSeconds(61) }));
            Assert.Throws<ArgumentOutOfRangeException>(() => new Auth4ServerClient(new Auth4ServerOptions { TenantId = Ids.Tenant, Issuer = Ids.Issuer, Audience = Ids.Client, JwksCacheTtl = TimeSpan.FromSeconds(1) }));
            Assert.Throws<ArgumentOutOfRangeException>(() => new Auth4ServerClient(new Auth4ServerOptions { TenantId = Ids.Tenant, Issuer = Ids.Issuer, Audience = Ids.Client, JwksFetchTimeout = TimeSpan.FromSeconds(11) }));
        }

        [Test]
        public void ParsesBearerHeadersLikeTheTypeScriptSdk()
        {
            Assert.That(Auth4ServerClient.ParseBearerToken("Bearer abc.def.ghi"), Is.EqualTo("abc.def.ghi"));
            Assert.That(Auth4ServerClient.ParseBearerToken("BEARER abc"), Is.EqualTo("abc"));
            Assert.That(Auth4ServerClient.ParseBearerToken("Bearer  abc"), Is.Null);
            Assert.That(Auth4ServerClient.ParseBearerToken("Bearer abc\n"), Is.Null);
            Assert.That(Auth4ServerClient.ParseBearerToken("Basic abc"), Is.Null);
            Assert.That(Auth4ServerClient.ParseBearerToken(null), Is.Null);
        }

        private void ServeDiscovery(string issuerValue, string jwksUri) =>
            issuer.Route(Ids.Issuer + "/.well-known/openid-configuration", _ => FakeIssuer.Json(new
            {
                issuer = issuerValue,
                jwks_uri = jwksUri,
                token_endpoint = Ids.Origin + "/oauth/token?tenant_id=" + Ids.Tenant,
                userinfo_endpoint = Ids.Origin + "/oauth/userinfo?tenant_id=" + Ids.Tenant,
                introspection_endpoint = Ids.Origin + "/oauth/introspect?tenant_id=" + Ids.Tenant,
                id_token_signing_alg_values_supported = new[] { "RS256" },
            }));

        [Test]
        public async Task DiscoversAndChecksTheIssuerMetadata()
        {
            ServeDiscovery(Ids.Issuer, Ids.Issuer + "/.well-known/jwks.json");
            var discovery = await client.DiscoverAsync();
            Assert.That(discovery.Issuer, Is.EqualTo(Ids.Issuer));
            Assert.That(discovery.JwksUri, Is.EqualTo(client.JwksUrl));
            Assert.That(discovery.IntrospectionEndpoint, Is.EqualTo(Ids.Origin + "/oauth/introspect?tenant_id=" + Ids.Tenant));
            Assert.That(discovery.TokenEndpoint, Does.StartWith(Ids.Origin + "/oauth/token"));
        }

        [Test]
        public void RefusesMismatchedOrMissingDiscovery()
        {
            ServeDiscovery(Ids.Origin + "/t/" + Ids.OtherTenant, Ids.Issuer + "/.well-known/jwks.json");
            Assert.ThrowsAsync<Auth4DiscoveryException>(() => client.DiscoverAsync());
            ServeDiscovery(Ids.Issuer, "https://elsewhere.test/jwks.json");
            Assert.ThrowsAsync<Auth4DiscoveryException>(() => client.DiscoverAsync());
            issuer.Route(Ids.Issuer + "/.well-known/openid-configuration", _ => new HttpResponseMessage(HttpStatusCode.NotFound));
            Assert.ThrowsAsync<Auth4DiscoveryException>(() => client.DiscoverAsync());
        }
    }
}
