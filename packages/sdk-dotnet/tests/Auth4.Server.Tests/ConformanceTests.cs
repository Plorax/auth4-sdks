using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Auth4.Server.Tests
{
    /// <summary>
    /// tests/fixtures/conformance.json holds a public JWKS and signed tokens with the verdict both
    /// SDKs must reach. tests/integration/auth4d-169.dotnet-sdk.test.ts runs the same cases through
    /// @auth4/sdk-server. The private key is discarded after generation. To regenerate:
    /// AUTH4D169_WRITE_FIXTURE=1 dotnet test --filter Conformance
    /// </summary>
    public class ConformanceTests
    {
        private static string FixturePath([CallerFilePath] string source = "") =>
            Path.GetFullPath(Path.Combine(Path.GetDirectoryName(source)!, "..", "fixtures", "conformance.json"));

        [Test, Order(1)]
        public void WriteFixture()
        {
            if (Environment.GetEnvironmentVariable("AUTH4D169_WRITE_FIXTURE") != "1")
            {
                Assert.Ignore("Set AUTH4D169_WRITE_FIXTURE=1 to regenerate the fixture.");
            }
            using var key = new TestKey("conformance-1");
            using var stranger = new TestKey("conformance-1");
            var now = Ids.Now.ToUnixTimeSeconds();
            var access = Tokens.AccessClaims();
            var cases = new List<object>
            {
                Case("valid access token", "access", true, Tokens.Sign(key, access)),
                Case("guest with roles and metadata", "access", true, Tokens.Sign(key, access
                    .With("auth4_guest", true)
                    .With("auth4_roles", new[] { "moderator", "tester" })
                    .With("auth4_meta", new Dictionary<string, object?> { ["level"] = 7, ["region"] = "eu", ["beta"] = false }))),
                Case("expired", "access", false, Tokens.Sign(key, Tokens.AccessClaims(now - 300))),
                Case("not yet valid", "access", false, Tokens.Sign(key, access.With("nbf", now + 60))),
                Case("other audience", "access", false, Tokens.Sign(key, access.With("aud", Ids.OtherClient))),
                Case("other tenant", "access", false, Tokens.Sign(key, access.With("tenant_id", Ids.OtherTenant).With("iss", Ids.Origin + "/t/" + Ids.OtherTenant))),
                Case("management audience", "access", false, Tokens.Sign(key, access.With("aud", "urn:auth4:management"))),
                Case("unknown claim", "access", false, Tokens.Sign(key, access.With("role", "admin"))),
                Case("non-boolean guest claim", "access", false, Tokens.Sign(key, access.With("auth4_guest", "true"))),
                Case("duplicate roles", "access", false, Tokens.Sign(key, access.With("auth4_roles", new[] { "a", "a" }))),
                Case("nested metadata", "access", false, Tokens.Sign(key, access.With("auth4_meta", new Dictionary<string, object?> { ["x"] = new { y = 1 } }))),
                Case("lifetime over five minutes", "access", false, Tokens.Sign(key, access.With("exp", now + 600))),
                Case("signed by another key", "access", false, Tokens.Sign(stranger, access)),
                Case("alg none", "access", false, Tokens.Sign(key, access, new Dictionary<string, object?> { ["alg"] = "none", ["kid"] = key.Kid, ["typ"] = "at+jwt" })),
                Case("ID token presented as an access token", "access", false, Tokens.Sign(key, Tokens.IdClaims(), Tokens.Header(key, "JWT"))),
                Case("valid ID token", "id", true, Tokens.Sign(key, Tokens.IdClaims(), Tokens.Header(key, "JWT"))),
                Case("access token presented as an ID token", "id", false, Tokens.Sign(key, access)),
            };
            var fixture = new
            {
                description = "AUTH4D-169 shared verdicts for Auth4.Server (C#) and @auth4/sdk-server. Test keys only; the private key was discarded.",
                tenantId = Ids.Tenant,
                issuer = Ids.Issuer,
                audience = Ids.Client,
                now,
                jwks = new { keys = new[] { key.PublicJwk() } },
                cases,
            };
            Directory.CreateDirectory(Path.GetDirectoryName(FixturePath())!);
            File.WriteAllText(FixturePath(),JsonSerializer.Serialize(fixture, new JsonSerializerOptions { WriteIndented = true }) + "\n");
        }

        private static object Case(string name, string kind, bool valid, string token) => new { name, kind, valid, token };

        [Test, Order(2)]
        public async Task EveryFixtureCaseGetsItsRecordedVerdict()
        {
            using var document = JsonDocument.Parse(File.ReadAllText(FixturePath()));
            var root = document.RootElement;
            var issuer = new FakeIssuer();
            issuer.Route(root.GetProperty("issuer").GetString() + "/.well-known/jwks.json", _ => new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(root.GetProperty("jwks").GetRawText()),
            });
            using var client = new Auth4ServerClient(new Auth4ServerOptions
            {
                TenantId = root.GetProperty("tenantId").GetString()!,
                Issuer = root.GetProperty("issuer").GetString(),
                Audience = root.GetProperty("audience").GetString()!,
                HttpClient = issuer.Client(),
                Now = () => DateTimeOffset.FromUnixTimeSeconds(root.GetProperty("now").GetInt64()),
            });
            var cases = root.GetProperty("cases").EnumerateArray().ToList();
            Assert.That(cases, Has.Count.GreaterThanOrEqualTo(10));
            foreach (var item in cases)
            {
                var name = item.GetProperty("name").GetString();
                var token = item.GetProperty("token").GetString()!;
                bool valid;
                try
                {
                    if (item.GetProperty("kind").GetString() == "id") await client.ValidateIdTokenAsync(token, root.GetProperty("audience").GetString()!);
                    else await client.ValidateAccessTokenAsync(token);
                    valid = true;
                }
                catch (Auth4TokenException error) when (error.Code == Auth4TokenErrorCode.InvalidToken)
                {
                    valid = false;
                }
                Assert.That(valid, Is.EqualTo(item.GetProperty("valid").GetBoolean()), name);
            }
        }
    }
}
