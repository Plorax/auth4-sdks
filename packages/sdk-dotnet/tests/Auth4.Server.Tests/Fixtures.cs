using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Auth4.Server.Internal;

namespace Auth4.Server.Tests
{
    /// <summary>A signing key generated per test run. Private keys never leave the process.</summary>
    public sealed class TestKey : IDisposable
    {
        public TestKey(string kid, int bits = 2048)
        {
            Kid = kid;
            Rsa = RSA.Create(bits);
        }

        public string Kid { get; }
        public RSA Rsa { get; }

        public Dictionary<string, object?> PublicJwk()
        {
            var parameters = Rsa.ExportParameters(false);
            return new Dictionary<string, object?>
            {
                ["kty"] = "RSA",
                ["kid"] = Kid,
                ["use"] = "sig",
                ["alg"] = "RS256",
                ["n"] = Base64Url.Encode(parameters.Modulus!),
                ["e"] = Base64Url.Encode(parameters.Exponent!),
            };
        }

        public void Dispose() => Rsa.Dispose();
    }

    /// <summary>The fixed tenant, issuer and clock every test uses.</summary>
    internal static class Ids
    {
        public const string Tenant = "ten_abcdefghijklmnop";
        public const string OtherTenant = "ten_qrstuvwxyzabcdef";
        public const string Origin = "https://auth.example.test";
        public const string Issuer = Origin + "/t/" + Tenant;
        public const string Client = "cli_gameclient000001";
        public const string OtherClient = "cli_webclient00000002";
        public const string ServerClient = "cli_serverclient00001";
        public const string User = "usr_player0000000001";
        public const string Session = "ses_session000000001";
        public const string Jti = "jti_token00000000000001";
        public const string ServerSecret = "server-secret-for-tests-only-0123456789";
        public static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
    }

    internal static class Tokens
    {
        public static Dictionary<string, object?> AccessClaims(long? iat = null) => new Dictionary<string, object?>
        {
            ["iss"] = Ids.Issuer,
            ["sub"] = Ids.User,
            ["aud"] = Ids.Client,
            ["exp"] = (iat ?? Ids.Now.ToUnixTimeSeconds()) + 300,
            ["iat"] = iat ?? Ids.Now.ToUnixTimeSeconds(),
            ["jti"] = Ids.Jti,
            ["tenant_id"] = Ids.Tenant,
            ["token_use"] = "access",
            ["client_id"] = Ids.Client,
            ["scope"] = "openid profile",
            ["sid"] = Ids.Session,
        };

        public static Dictionary<string, object?> IdClaims() => new Dictionary<string, object?>
        {
            ["iss"] = Ids.Issuer,
            ["sub"] = Ids.User,
            ["aud"] = Ids.Client,
            ["exp"] = Ids.Now.ToUnixTimeSeconds() + 300,
            ["iat"] = Ids.Now.ToUnixTimeSeconds(),
            ["jti"] = Ids.Jti,
            ["tenant_id"] = Ids.Tenant,
            ["token_use"] = "id",
            ["auth_time"] = Ids.Now.ToUnixTimeSeconds() - 10,
            ["nonce"] = "nonce-0123456789abcdef",
            ["email"] = "player@example.test",
            ["email_verified"] = true,
        };

        public static Dictionary<string, object?> Header(TestKey key, string typ = "at+jwt") => new Dictionary<string, object?>
        {
            ["alg"] = "RS256",
            ["kid"] = key.Kid,
            ["typ"] = typ,
        };

        public static string Sign(TestKey key, IDictionary<string, object?> claims, IDictionary<string, object?>? header = null)
        {
            var head = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(header ?? Header(key)));
            var body = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(claims));
            var signature = key.Rsa.SignData(Encoding.ASCII.GetBytes($"{head}.{body}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return $"{head}.{body}.{Base64Url.Encode(signature)}";
        }

        public static Dictionary<string, object?> With(this Dictionary<string, object?> claims, string name, object? value)
        {
            var copy = new Dictionary<string, object?>(claims) { [name] = value };
            return copy;
        }

        public static Dictionary<string, object?> Without(this Dictionary<string, object?> claims, string name)
        {
            var copy = new Dictionary<string, object?>(claims);
            copy.Remove(name);
            return copy;
        }
    }

    /// <summary>
    /// Stands in for the issuer over HTTP. Routes are matched on the full URL; unknown URLs return
    /// 404, so a request to anything but the configured issuer's endpoints fails the test.
    /// </summary>
    internal sealed class FakeIssuer : HttpMessageHandler
    {
        private readonly ConcurrentDictionary<string, Func<HttpRequestMessage, Task<HttpResponseMessage>>> routes =
            new ConcurrentDictionary<string, Func<HttpRequestMessage, Task<HttpResponseMessage>>>();

        public FakeIssuer(params TestKey[] keys)
        {
            Keys = keys.ToList();
            Route(Ids.Issuer + "/.well-known/jwks.json", _ => Json(new { keys = Keys.Select(key => key.PublicJwk()).ToArray() }));
        }

        public List<TestKey> Keys { get; }
        public ConcurrentQueue<HttpRequestMessage> Requests { get; } = new ConcurrentQueue<HttpRequestMessage>();
        public ConcurrentQueue<string> Bodies { get; } = new ConcurrentQueue<string>();

        public int Count(string url) => Requests.Count(request => request.RequestUri!.ToString() == url);

        public void Route(string url, Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) => routes[url] = handler;

        public void Route(string url, Func<HttpRequestMessage, HttpResponseMessage> handler) =>
            routes[url] = request => Task.FromResult(handler(request));

        public static HttpResponseMessage Json(object body, HttpStatusCode status = HttpStatusCode.OK) =>
            new HttpResponseMessage(status)
            {
                Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
            };

        public HttpClient Client() => new HttpClient(this, disposeHandler: false);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Enqueue(request);
            if (request.Content != null) Bodies.Enqueue(await request.Content.ReadAsStringAsync(cancellationToken));
            var url = request.RequestUri!.ToString();
            var response = routes.TryGetValue(url, out var handler)
                ? await handler(request)
                : new HttpResponseMessage(HttpStatusCode.NotFound);
            response.RequestMessage ??= request;
            return response;
        }
    }

    internal sealed class TestClock
    {
        public DateTimeOffset Now { get; set; } = Ids.Now;

        public void Advance(TimeSpan by) => Now += by;
    }
}
