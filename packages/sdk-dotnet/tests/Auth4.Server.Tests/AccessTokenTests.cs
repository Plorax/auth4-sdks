using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Auth4.Server.Tests
{
    public class AccessTokenTests
    {
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
            client = Create();
        }

        [TearDown]
        public void TearDown()
        {
            client.Dispose();
            issuer.Dispose();
            key.Dispose();
        }

        private Auth4ServerClient Create(TimeSpan? tolerance = null) => new Auth4ServerClient(new Auth4ServerOptions
        {
            TenantId = Ids.Tenant,
            Issuer = Ids.Issuer,
            Audience = Ids.Client,
            HttpClient = issuer.Client(),
            Now = () => clock.Now,
            ClockTolerance = tolerance ?? TimeSpan.Zero,
        });

        private async Task<Auth4TokenErrorCode> Refused(string token)
        {
            var error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAccessTokenAsync(token))!;
            await Task.CompletedTask;
            return error.Code;
        }

        [Test]
        public async Task VerifiesAValidTokenAndExposesItsClaims()
        {
            var token = await client.ValidateAccessTokenAsync(Tokens.Sign(key, Tokens.AccessClaims()));
            Assert.That(token.Subject, Is.EqualTo(Ids.User));
            Assert.That(token.TenantId, Is.EqualTo(Ids.Tenant));
            Assert.That(token.ClientId, Is.EqualTo(Ids.Client));
            Assert.That(token.Audience, Is.EqualTo(Ids.Client));
            Assert.That(token.SessionId, Is.EqualTo(Ids.Session));
            Assert.That(token.Scopes, Is.EqualTo(new[] { "openid", "profile" }));
            Assert.That(token.HasScope("openid"), Is.True);
            Assert.That(token.IsGuest, Is.False);
            Assert.That(token.Roles, Is.Empty);
            Assert.That(token.Metadata, Is.Empty);
            Assert.That(token.ExpiresAt, Is.EqualTo(Ids.Now.AddMinutes(5)));
            Assert.That(token.ToString(), Does.Not.Contain("eyJ"));
            Assert.That(client.JwksUrl, Is.EqualTo(Ids.Issuer + "/.well-known/jwks.json"));
        }

        [Test]
        public async Task ValidatesAnAuthorizationHeader()
        {
            var jwt = Tokens.Sign(key, Tokens.AccessClaims());
            Assert.That((await client.ValidateAuthorizationHeaderAsync("Bearer " + jwt)).Subject, Is.EqualTo(Ids.User));
            Assert.That((await client.ValidateAuthorizationHeaderAsync("bearer " + jwt)).Subject, Is.EqualTo(Ids.User));
            foreach (var header in new[] { null, "", "Basic abc", "Bearer", "Bearer a b", "Bearer a,b", "Bearer " + jwt + "\n" })
            {
                var error = Assert.ThrowsAsync<Auth4TokenException>(() => client.ValidateAuthorizationHeaderAsync(header))!;
                Assert.That(error.Code, Is.EqualTo(Auth4TokenErrorCode.InvalidToken), header ?? "null");
            }
        }

        [Test]
        public async Task ReadsTheGuestClaim()
        {
            Assert.That((await client.ValidateAccessTokenAsync(Tokens.Sign(key, Tokens.AccessClaims().With("auth4_guest", true)))).IsGuest, Is.True);
            Assert.That((await client.ValidateAccessTokenAsync(Tokens.Sign(key, Tokens.AccessClaims().With("auth4_guest", false)))).IsGuest, Is.False);
            Assert.That(await Refused(Tokens.Sign(key, Tokens.AccessClaims().With("auth4_guest", "true"))), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
        }

        [Test]
        public async Task AcceptsThePlayerNameClaim()
        {
            // AUTH4D-324: projects can opt in to the player's Name#1234 in access tokens.
            await client.ValidateAccessTokenAsync(Tokens.Sign(key, Tokens.AccessClaims().With("name", "Ace#0427")));
            Assert.That(await Refused(Tokens.Sign(key, Tokens.AccessClaims().With("name", "Ace"))), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            Assert.That(await Refused(Tokens.Sign(key, Tokens.AccessClaims().With("name", 7))), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
        }

        [Test]
        public async Task ReadsRolesAndMetadata()
        {
            var claims = Tokens.AccessClaims()
                .With("auth4_roles", new[] { "admin", "moderator" })
                .With("auth4_meta", new Dictionary<string, object?> { ["level"] = 12, ["region"] = "eu", ["vip"] = true, ["clan"] = null });
            var token = await client.ValidateAccessTokenAsync(Tokens.Sign(key, claims));
            Assert.That(token.Roles, Is.EqualTo(new[] { "admin", "moderator" }));
            Assert.That(token.HasRole("admin"), Is.True);
            Assert.That(token.HasRole("Admin"), Is.False);
            Assert.That(token.HasAnyRole("owner", "moderator"), Is.True);
            Assert.That(token.HasAnyRole(), Is.False);
            Assert.That(token.Metadata["level"].GetInt32(), Is.EqualTo(12));
            Assert.That(token.Metadata["region"].GetString(), Is.EqualTo("eu"));
            Assert.That(token.Metadata["vip"].GetBoolean(), Is.True);
            Assert.That(token.Metadata.ContainsKey("clan"), Is.True);
        }

        private static IEnumerable<TestCaseData> MalformedCustomClaims()
        {
            yield return new TestCaseData("auth4_roles", new string[0]).SetName("empty roles");
            yield return new TestCaseData("auth4_roles", new[] { "admin", "admin" }).SetName("duplicate roles");
            yield return new TestCaseData("auth4_roles", new[] { "Admin" }).SetName("uppercase role");
            yield return new TestCaseData("auth4_roles", "admin").SetName("roles as a string");
            yield return new TestCaseData("auth4_meta", new Dictionary<string, object?>()).SetName("empty metadata");
            yield return new TestCaseData("auth4_meta", new Dictionary<string, object?> { ["nested"] = new[] { 1 } }).SetName("nested metadata");
            yield return new TestCaseData("auth4_meta", new Dictionary<string, object?> { ["email"] = "x" }).SetName("reserved metadata key");
            yield return new TestCaseData("auth4_meta", new Dictionary<string, object?> { ["auth4_x"] = "x" }).SetName("auth4_ metadata key");
            yield return new TestCaseData("auth4_meta", new Dictionary<string, object?> { ["long"] = new string('x', 257) }).SetName("long metadata string");
            var big = new Dictionary<string, object?>();
            for (var i = 0; i < 10; i++) big["k" + i] = new string('x', 250);
            yield return new TestCaseData("auth4_meta", big).SetName("metadata over 2048 bytes");
        }

        [TestCaseSource(nameof(MalformedCustomClaims))]
        public async Task RefusesMalformedCustomClaims(string claim, object value)
        {
            Assert.That(await Refused(Tokens.Sign(key, Tokens.AccessClaims().With(claim, value))), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
        }

        private static IEnumerable<TestCaseData> InvalidClaims()
        {
            var now = Ids.Now.ToUnixTimeSeconds();
            yield return new TestCaseData(Tokens.AccessClaims().With("iss", Ids.Origin + "/t/" + Ids.OtherTenant)).SetName("other issuer");
            yield return new TestCaseData(Tokens.AccessClaims().With("tenant_id", Ids.OtherTenant)).SetName("other tenant");
            yield return new TestCaseData(Tokens.AccessClaims().With("aud", Ids.OtherClient)).SetName("other audience");
            yield return new TestCaseData(Tokens.AccessClaims().With("aud", new[] { Ids.Client })).SetName("audience array");
            yield return new TestCaseData(Tokens.AccessClaims().With("aud", "urn:auth4:management")).SetName("management audience");
            yield return new TestCaseData(Tokens.AccessClaims().With("token_use", "id")).SetName("token_use id");
            yield return new TestCaseData(Tokens.AccessClaims(now - 300)).SetName("expired");
            yield return new TestCaseData(Tokens.AccessClaims().With("exp", now + 301)).SetName("lifetime over five minutes");
            yield return new TestCaseData(Tokens.AccessClaims().With("exp", now)).SetName("exp equals iat");
            yield return new TestCaseData(Tokens.AccessClaims().With("nbf", now + 1)).SetName("not yet valid");
            yield return new TestCaseData(Tokens.AccessClaims().With("exp", 1.5)).SetName("fractional exp");
            yield return new TestCaseData(Tokens.AccessClaims().With("extra", "x")).SetName("unknown claim");
            yield return new TestCaseData(Tokens.AccessClaims().With("email", "player@example.test")).SetName("email in an access token");
            yield return new TestCaseData(Tokens.AccessClaims().Without("jti")).SetName("missing jti");
            yield return new TestCaseData(Tokens.AccessClaims().Without("scope")).SetName("missing scope");
            yield return new TestCaseData(Tokens.AccessClaims().With("scope", "openid openid")).SetName("duplicate scope");
            yield return new TestCaseData(Tokens.AccessClaims().With("sub", "player")).SetName("malformed sub");
            yield return new TestCaseData(Tokens.AccessClaims().With("sid", "session")).SetName("malformed sid");
            yield return new TestCaseData(Tokens.AccessClaims().With("client_id", "cli_x")).SetName("malformed client_id");
        }

        [TestCaseSource(nameof(InvalidClaims))]
        public async Task RefusesInvalidClaims(Dictionary<string, object?> claims)
        {
            Assert.That(await Refused(Tokens.Sign(key, claims)), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
        }

        [Test]
        public async Task AppliesTheClockToleranceToExpAndNbf()
        {
            var now = Ids.Now.ToUnixTimeSeconds();
            var expired = Tokens.Sign(key, Tokens.AccessClaims(now - 310));
            var early = Tokens.Sign(key, Tokens.AccessClaims().With("nbf", now + 20));
            Assert.That(await Refused(expired), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            using var tolerant = Create(TimeSpan.FromSeconds(30));
            Assert.That((await tolerant.ValidateAccessTokenAsync(expired)).Subject, Is.EqualTo(Ids.User));
            Assert.That((await tolerant.ValidateAccessTokenAsync(early)).NotBefore, Is.EqualTo(Ids.Now.AddSeconds(20)));
        }

        private static IEnumerable<TestCaseData> InvalidHeaders()
        {
            yield return new TestCaseData(new Dictionary<string, object?> { ["alg"] = "none", ["kid"] = "key-1", ["typ"] = "at+jwt" }).SetName("alg none");
            yield return new TestCaseData(new Dictionary<string, object?> { ["alg"] = "HS256", ["kid"] = "key-1", ["typ"] = "at+jwt" }).SetName("alg HS256");
            yield return new TestCaseData(new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = "key-1", ["typ"] = "JWT" }).SetName("ID-token typ");
            yield return new TestCaseData(new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = "key-1" }).SetName("missing typ");
            yield return new TestCaseData(new Dictionary<string, object?> { ["alg"] = "RS256", ["typ"] = "at+jwt" }).SetName("missing kid");
            yield return new TestCaseData(new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = "key-1", ["typ"] = "at+jwt", ["jku"] = "https://evil.test/jwks" }).SetName("jku");
            yield return new TestCaseData(new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = "key-1", ["typ"] = "at+jwt", ["x5u"] = "https://evil.test/x5u" }).SetName("x5u");
            yield return new TestCaseData(new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = "key-1", ["typ"] = "at+jwt", ["crit"] = new[] { "exp" } }).SetName("crit");
        }

        [TestCaseSource(nameof(InvalidHeaders))]
        public async Task RefusesInvalidHeaders(Dictionary<string, object?> header)
        {
            Assert.That(await Refused(Tokens.Sign(key, Tokens.AccessClaims(), header)), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            Assert.That(issuer.Requests, Is.Empty, "header checks run before any key fetch");
        }

        [Test]
        public async Task AcceptsTheMediaTypeFormOfTyp()
        {
            var header = Tokens.Header(key, "application/at+jwt");
            Assert.That((await client.ValidateAccessTokenAsync(Tokens.Sign(key, Tokens.AccessClaims(), header))).Subject, Is.EqualTo(Ids.User));
        }

        [Test]
        public async Task RefusesTamperedAndMalformedTokens()
        {
            var jwt = Tokens.Sign(key, Tokens.AccessClaims());
            var parts = jwt.Split('.');
            var forged = Tokens.Sign(key, Tokens.AccessClaims().With("sub", "usr_attacker0000000001")).Split('.')[1];
            Assert.That(await Refused($"{parts[0]}.{forged}.{parts[2]}"), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            Assert.That(await Refused($"{parts[0]}.{parts[1]}."), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            Assert.That(await Refused($"{parts[0]}.{parts[1]}"), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            Assert.That(await Refused("not-a-token"), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            Assert.That(await Refused(""), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            Assert.That(await Refused(new string('a', 16_385)), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
            using var stranger = new TestKey("key-1");
            Assert.That(await Refused(Tokens.Sign(stranger, Tokens.AccessClaims())), Is.EqualTo(Auth4TokenErrorCode.InvalidToken));
        }
    }
}
