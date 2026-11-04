using System.Linq;
using System.Threading.Tasks;
using NUnit.Framework;
using static Auth4.Protocol.Tests.Fixtures;

namespace Auth4.Protocol.Tests
{
    /// <summary>
    /// AUTH4D-324: GetPlayerNameAsync and UpdatePlayerNameAsync over GET and PUT /t/{tenant}/me/name
    /// with the player's bearer token. The server assigns the discriminator.
    /// </summary>
    public sealed class PlayerNameTests
    {
        private static readonly string NamePath = "/t/" + TenantId + "/me/name";

        private static FakeTransport Server(int status, string body)
        {
            return new FakeTransport(request =>
            {
                if (request.Path == "/t/" + TenantId + "/guest")
                {
                    return FakeTransport.Json(200, GuestCreated());
                }

                return request.Path == NamePath
                    ? FakeTransport.Json(status, body)
                    : FakeTransport.Json(404, Error("not_found"));
            });
        }

        private static async Task<(Auth4Client Client, FakeTransport Transport)> SignedIn(int status, string body)
        {
            var transport = Server(status, body);
            var client = Client(transport, new FakeClock());
            await client.SignInAsGuestAsync();
            return (client, transport);
        }

        [Test]
        public void NeedsASession()
        {
            var transport = Server(200, "{}");
            var client = Client(transport, new FakeClock());
            var error = Assert.ThrowsAsync<Auth4Exception>(() => client.GetPlayerNameAsync());
            Assert.That(error.Error, Is.EqualTo("login_required"));
            Assert.That(transport.To(NamePath), Is.Empty);
        }

        [Test]
        public async Task ReadsAnUnsetName()
        {
            var (client, transport) = await SignedIn(200, "{\"name\":null,\"discriminator\":null,\"tag\":null}");
            var name = await client.GetPlayerNameAsync();
            Assert.That(name.IsSet, Is.False);
            Assert.That(name.Tag, Is.Null);
            var request = transport.To(NamePath).Single();
            Assert.That(request.Method, Is.EqualTo("GET"));
            Assert.That(request.Body, Is.Null.Or.Empty);
            Assert.That(request.Headers["Authorization"], Is.EqualTo("Bearer " + Token("guest-access")));
        }

        [Test]
        public async Task SetsANameAndReturnsTheServerDiscriminator()
        {
            var (client, transport) = await SignedIn(200, "{\"name\":\"Ace\",\"discriminator\":\"0427\",\"tag\":\"Ace#0427\"}");
            var name = await client.UpdatePlayerNameAsync("Ace");
            Assert.That(name.Name, Is.EqualTo("Ace"));
            Assert.That(name.Discriminator, Is.EqualTo("0427"));
            Assert.That(name.Tag, Is.EqualTo("Ace#0427"));
            var request = transport.To(NamePath).Single();
            Assert.That(request.Method, Is.EqualTo("PUT"));
            Assert.That(request.ContentType, Is.EqualTo("application/json"));
            Assert.That(request.Body, Is.EqualTo("{\"name\":\"Ace\"}"));
        }

        [Test]
        public async Task ClearsANameWithNull()
        {
            var (client, transport) = await SignedIn(200, "{\"name\":null,\"discriminator\":null,\"tag\":null}");
            var name = await client.UpdatePlayerNameAsync(null);
            Assert.That(name.IsSet, Is.False);
            Assert.That(transport.To(NamePath).Single().Body, Is.EqualTo("{\"name\":null}"));
        }

        [TestCase(400, "invalid_name")]
        [TestCase(409, "name_unavailable")]
        [TestCase(429, "rate_limited")]
        [TestCase(401, "invalid_token")]
        public async Task SurfacesTheServerError(int status, string code)
        {
            var (client, _) = await SignedIn(status, Error(code));
            var error = Assert.ThrowsAsync<Auth4Exception>(() => client.UpdatePlayerNameAsync("Ace"));
            Assert.That(error.Error, Is.EqualTo(code));
        }

        [TestCase("{\"name\":\"Ace\",\"discriminator\":\"12\",\"tag\":\"Ace#12\"}")]
        [TestCase("{\"name\":\"Ace\",\"discriminator\":\"1234\",\"tag\":\"Bob#1234\"}")]
        [TestCase("not json")]
        public async Task RefusesAMalformedResponse(string body)
        {
            var (client, _) = await SignedIn(200, body);
            var error = Assert.ThrowsAsync<Auth4Exception>(() => client.GetPlayerNameAsync());
            Assert.That(error.Error, Is.EqualTo("invalid_response"));
        }
    }
}
