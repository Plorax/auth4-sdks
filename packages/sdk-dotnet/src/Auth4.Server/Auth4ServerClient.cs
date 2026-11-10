using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Auth4.Server.Internal;

namespace Auth4.Server
{
    /// <summary>
    /// Verifies auth4.dev access tokens for one configured tenant and resource audience, like
    /// <c>Auth4ServerClient</c> in @auth4/sdk-server. Signing keys are fetched only from the URL
    /// derived from the configured issuer. Create one instance per audience and reuse it, so its
    /// key cache is shared across requests. Thread-safe.
    /// </summary>
    public sealed class Auth4ServerClient : IDisposable
    {
        private static readonly Regex BearerPattern = new Regex(@"^Bearer ([^\s,]+)\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly IReadOnlyDictionary<string, JsonElement> NoMetadata = new Dictionary<string, JsonElement>();

        private readonly HttpClient httpClient;
        private readonly bool ownsHttpClient;
        private readonly Func<DateTimeOffset> now;
        private readonly long clockToleranceSeconds;
        private readonly TimeSpan fetchTimeout;
        private readonly JwksCache jwks;
        private readonly Introspector? introspector;

        /// <summary>Validates <paramref name="options"/> and creates the client. Makes no network calls.</summary>
        public Auth4ServerClient(Auth4ServerOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            if (options.TenantId == null || !Auth4Rules.TenantId.IsMatch(options.TenantId))
            {
                throw new ArgumentException("TenantId must be a project ID (ten_…).", nameof(options));
            }
            TenantId = options.TenantId;
            if (!string.IsNullOrEmpty(options.Issuer))
            {
                Issuer = Auth4Rules.ValidateIssuer(TenantId, options.Issuer!);
            }
            else if (!string.IsNullOrEmpty(options.AuthOrigin))
            {
                Issuer = Auth4Rules.IssuerFromOrigin(TenantId, options.AuthOrigin!);
            }
            else
            {
                throw new ArgumentException("Set Issuer or AuthOrigin.", nameof(options));
            }
            if (options.Audience == null || options.Audience.Length < 1 || options.Audience.Length > 255)
            {
                throw new ArgumentException("Audience must be 1 to 255 characters.", nameof(options));
            }
            if (options.Audience == Auth4Rules.ManagementAudience)
            {
                throw new ArgumentException("Customer server clients cannot use the management audience.", nameof(options));
            }
            Audience = options.Audience;
            // No token-supplied issuer, jku or x5u value is ever used to build this URL.
            JwksUrl = $"{Issuer}/.well-known/jwks.json";

            var cacheTtl = Introspector.Bounded(nameof(options.JwksCacheTtl), options.JwksCacheTtl, TimeSpan.FromSeconds(10), TimeSpan.FromHours(1));
            var cooldown = Introspector.Bounded(nameof(options.JwksRefreshCooldown), options.JwksRefreshCooldown, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(10));
            fetchTimeout = Introspector.Bounded(nameof(options.JwksFetchTimeout), options.JwksFetchTimeout, TimeSpan.FromMilliseconds(10), TimeSpan.FromSeconds(10));
            var tolerance = Introspector.Bounded(nameof(options.ClockTolerance), options.ClockTolerance, TimeSpan.Zero, TimeSpan.FromSeconds(60));
            if (tolerance.Ticks % TimeSpan.TicksPerSecond != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(options.ClockTolerance), "ClockTolerance must be whole seconds.");
            }
            clockToleranceSeconds = (long)tolerance.TotalSeconds;
            now = options.Now ?? (() => DateTimeOffset.UtcNow);

            if (options.HttpClient != null)
            {
                httpClient = options.HttpClient;
            }
            else
            {
                httpClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
                ownsHttpClient = true;
            }
            Func<long> nowMs = () => now().ToUnixTimeMilliseconds();
            jwks = new JwksCache(httpClient, JwksUrl, cacheTtl, cooldown, fetchTimeout, nowMs);
            if (options.Introspection != null)
            {
                introspector = new Introspector(httpClient, Issuer, TenantId, options.Introspection, nowMs);
            }
        }

        /// <summary>The configured project ID.</summary>
        public string TenantId { get; }

        /// <summary>The configured issuer, <c>{AUTH_ORIGIN}/t/{tenantId}</c>.</summary>
        public string Issuer { get; }

        /// <summary>The configured audience.</summary>
        public string Audience { get; }

        /// <summary><c>{issuer}/.well-known/jwks.json</c>.</summary>
        public string JwksUrl { get; }

        /// <summary>The endpoint introspect mode calls, derived from the configured issuer; null when off.</summary>
        public string? IntrospectionUrl => introspector?.Url;

        /// <summary>The issuer for a project on an auth origin, for example <c>https://auth.auth4.dev/t/ten_…</c>.</summary>
        public static string IssuerFor(string authOrigin, string tenantId)
        {
            if (tenantId == null || !Auth4Rules.TenantId.IsMatch(tenantId))
            {
                throw new ArgumentException("tenantId must be a project ID (ten_…).", nameof(tenantId));
            }
            return Auth4Rules.IssuerFromOrigin(tenantId, authOrigin);
        }

        /// <summary>
        /// Parses a single RFC 6750 Bearer credential from an Authorization header value. It does not
        /// validate the token. Returns null for anything else.
        /// </summary>
        public static string? ParseBearerToken(string? header)
        {
            if (header == null || header.Length > Auth4Rules.MaxTokenLength + 16) return null;
            var match = BearerPattern.Match(header);
            return match.Success ? match.Groups[1].Value : null;
        }

        /// <summary>
        /// Fetches <c>{issuer}/.well-known/openid-configuration</c> and checks that it names the
        /// configured issuer, the derived JWKS URL and RS256. Optional: verification never depends on
        /// it, so call it at startup to catch a misconfigured project or origin early.
        /// </summary>
        public async Task<Auth4Discovery> DiscoverAsync()
        {
            JsonDocument document;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"{Issuer}/.well-known/openid-configuration");
                request.Headers.TryAddWithoutValidation("Accept", "application/json");
                document = await BoundedHttp.SendForJsonObjectAsync(httpClient, request, fetchTimeout, "The discovery endpoint").ConfigureAwait(false);
            }
            catch (Exception cause)
            {
                throw new Auth4DiscoveryException("The issuer's discovery document could not be fetched.", cause);
            }
            using (document)
            {
                var root = document.RootElement;
                string? Text(string name) =>
                    root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
                if (Text("issuer") != Issuer) throw new Auth4DiscoveryException("The discovery document names a different issuer.");
                if (Text("jwks_uri") != JwksUrl) throw new Auth4DiscoveryException("The discovery document names a different JWKS URL.");
                if (!root.TryGetProperty("id_token_signing_alg_values_supported", out var algs) ||
                    algs.ValueKind != JsonValueKind.Array ||
                    !algs.EnumerateArray().Any(alg => alg.ValueKind == JsonValueKind.String && alg.GetString() == "RS256"))
                {
                    throw new Auth4DiscoveryException("The issuer does not advertise RS256.");
                }
                var introspection = Text("introspection_endpoint");
                if (IntrospectionUrl != null && introspection != IntrospectionUrl)
                {
                    throw new Auth4DiscoveryException("The issuer does not advertise the introspection endpoint introspect mode uses.");
                }
                return new Auth4Discovery(Issuer, JwksUrl, Text("token_endpoint"), Text("userinfo_endpoint"), introspection);
            }
        }

        /// <summary>
        /// Verifies an access token: RS256 signature from the issuer's keys, <c>typ</c> at+jwt,
        /// <c>iss</c>, <c>aud</c>, <c>exp</c>, <c>nbf</c>, <c>tenant_id</c> and the claim contract.
        /// Throws <see cref="Auth4TokenException"/>; in introspect mode it also checks the session.
        /// </summary>
        public Task<Auth4AccessToken> ValidateAccessTokenAsync(string token) =>
            Telemetry.TrackAsync(Telemetry.ValidateAccessToken, async () =>
            {
                using var jwt = await VerifySignatureAsync(token, expectedType: "access").ConfigureAwait(false);
                var verified = ReadAccessClaims(jwt.Payload.RootElement) ?? throw Auth4TokenException.Invalid();
                if (introspector != null) await introspector.AssertActiveAsync(token, verified).ConfigureAwait(false);
                return verified;
            });

        /// <summary>Verifies an Authorization header value and rejects absent or malformed Bearer credentials.</summary>
        public async Task<Auth4AccessToken> ValidateAuthorizationHeaderAsync(string? header)
        {
            var token = ParseBearerToken(header) ?? throw Auth4TokenException.Invalid();
            return await ValidateAccessTokenAsync(token).ConfigureAwait(false);
        }

        /// <summary>
        /// Verifies an ID token for <paramref name="clientId"/>. ID tokens have <c>typ</c> JWT and
        /// <c>token_use</c> id, so neither validation path accepts the other kind of token. Pass the
        /// <paramref name="expectedNonce"/> your authorization request sent, if any. Never use an ID
        /// token to authorize an API call.
        /// </summary>
        public async Task<Auth4IdToken> ValidateIdTokenAsync(string idToken, string clientId, string? expectedNonce = null)
        {
            if (clientId == null || !Auth4Rules.ClientId.IsMatch(clientId))
            {
                throw new ArgumentException("clientId must be an application client ID (cli_…).", nameof(clientId));
            }
            return await Telemetry.TrackAsync(Telemetry.ValidateIdToken, async () =>
            {
                using var jwt = await VerifySignatureAsync(idToken, expectedType: "id").ConfigureAwait(false);
                var verified = ReadIdClaims(jwt.Payload.RootElement, clientId) ?? throw Auth4TokenException.Invalid();
                if (expectedNonce != null &&
                    (verified.Nonce == null || !FixedTimeEquals(verified.Nonce, expectedNonce)))
                {
                    throw Auth4TokenException.Invalid();
                }
                return verified;
            }).ConfigureAwait(false);
        }

        /// <summary>Disposes the HttpClient when the client created it.</summary>
        public void Dispose()
        {
            if (ownsHttpClient) httpClient.Dispose();
        }

        private async Task<JwtParts> VerifySignatureAsync(string token, string expectedType)
        {
            if (string.IsNullOrEmpty(token) || token.Length > Auth4Rules.MaxTokenLength) throw Auth4TokenException.Invalid();
            var jwt = JwtParts.TryParse(token) ?? throw Auth4TokenException.Invalid();
            try
            {
                var header = jwt.Header.RootElement;
                // typ separates the two token kinds, as packages/crypto signs them.
                var typ = HeaderText(header, "typ");
                var typeMatches = expectedType == "access"
                    ? string.Equals(typ, "at+jwt", StringComparison.OrdinalIgnoreCase) || string.Equals(typ, "application/at+jwt", StringComparison.OrdinalIgnoreCase)
                    : string.Equals(typ, "JWT", StringComparison.OrdinalIgnoreCase);
                var kid = HeaderText(header, "kid");
                if (HeaderText(header, "alg") != "RS256" || !typeMatches ||
                    kid == null || kid.Length < 1 || kid.Length > 128 ||
                    header.TryGetProperty("jku", out _) || header.TryGetProperty("x5u", out _) ||
                    header.TryGetProperty("jwk", out _) || header.TryGetProperty("crit", out _))
                {
                    throw Auth4TokenException.Invalid();
                }

                var key = await jwks.GetKeyAsync(kid).ConfigureAwait(false) ?? throw Auth4TokenException.Invalid();
                bool valid;
                using (var rsa = RSA.Create())
                {
                    rsa.ImportParameters(key);
                    try
                    {
                        valid = rsa.VerifyData(jwt.SigningInput, jwt.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    }
                    catch (CryptographicException)
                    {
                        valid = false;
                    }
                }
                if (!valid) throw Auth4TokenException.Invalid();
                return jwt;
            }
            catch
            {
                jwt.Dispose();
                throw;
            }
        }

        private static string? HeaderText(JsonElement header, string name) =>
            header.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

        /// <summary>Registered claims shared by both token kinds; returns false on any violation.</summary>
        private bool ReadCommon(JsonElement payload, HashSet<string> allowed, string tokenUse, int maxLifetime, out Common common)
        {
            common = default;
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in payload.EnumerateObject())
            {
                // Duplicate or unknown claims fail, like the strict contract schemas.
                if (!allowed.Contains(property.Name) || !names.Add(property.Name)) return false;
            }
            if (!Str(payload, "iss", out var iss) || iss != Issuer) return false;
            if (!Str(payload, "sub", out var sub) || !Auth4Rules.UserId.IsMatch(sub)) return false;
            if (!Str(payload, "jti", out var jti) || !Auth4Rules.TokenId.IsMatch(jti)) return false;
            if (!Str(payload, "tenant_id", out var tenantId) || tenantId != TenantId) return false;
            if (!Str(payload, "token_use", out var use) || use != tokenUse) return false;
            if (!PositiveInt(payload, "exp", out var exp) || !PositiveInt(payload, "iat", out var iat)) return false;
            long? nbf = null;
            if (payload.TryGetProperty("nbf", out _))
            {
                if (!PositiveInt(payload, "nbf", out var notBefore)) return false;
                nbf = notBefore;
            }
            if (exp <= iat || exp - iat > maxLifetime) return false;

            // Same comparisons as jose: whole seconds, with the configured tolerance.
            var nowSeconds = now().ToUnixTimeSeconds();
            if (exp <= nowSeconds - clockToleranceSeconds) return false;
            if (nbf != null && nbf > nowSeconds + clockToleranceSeconds) return false;
            common = new Common(sub, jti, exp, iat, nbf);
            return true;
        }

        private Auth4AccessToken? ReadAccessClaims(JsonElement payload)
        {
            if (!ReadCommon(payload, Auth4Rules.AccessTokenClaims, "access", Auth4Rules.AccessTokenLifetimeSeconds, out var common)) return null;
            // aud is a single string in the contract; an array is refused.
            if (!Str(payload, "aud", out var aud) || aud != Audience || aud == Auth4Rules.ManagementAudience) return null;
            if (!Str(payload, "client_id", out var clientId) || !Auth4Rules.ClientId.IsMatch(clientId)) return null;
            if (!Str(payload, "scope", out var scope) || !Auth4Rules.IsScopeList(scope)) return null;
            string? sid = null;
            if (payload.TryGetProperty("sid", out _))
            {
                if (!Str(payload, "sid", out var session) || !Auth4Rules.SessionId.IsMatch(session)) return null;
                sid = session;
            }
            // A non-boolean auth4_guest and malformed auth4_roles or auth4_meta make the token invalid;
            // absent claims mean not a guest, no roles and no metadata.
            var isGuest = false;
            if (payload.TryGetProperty(Auth4Rules.GuestClaim, out var guest))
            {
                if (guest.ValueKind != JsonValueKind.True && guest.ValueKind != JsonValueKind.False) return null;
                isGuest = guest.GetBoolean();
            }
            IReadOnlyList<string> roles = Array.Empty<string>();
            if (payload.TryGetProperty(Auth4Rules.RolesClaim, out var rolesClaim))
            {
                roles = Auth4Rules.ReadRoles(rolesClaim) ?? throw Auth4TokenException.Invalid();
            }
            var metadata = NoMetadata;
            if (payload.TryGetProperty(Auth4Rules.MetadataClaim, out var metadataClaim))
            {
                metadata = Auth4Rules.ReadMetadata(metadataClaim) ?? throw Auth4TokenException.Invalid();
            }
            if (!IdpIsValid(payload) || !PlayerNameIsValid(payload)) return null;
            return new Auth4AccessToken(
                common.Subject, TenantId, Issuer, aud, clientId, scope, sid, common.TokenId,
                DateTimeOffset.FromUnixTimeSeconds(common.IssuedAt),
                DateTimeOffset.FromUnixTimeSeconds(common.ExpiresAt),
                common.NotBefore == null ? (DateTimeOffset?)null : DateTimeOffset.FromUnixTimeSeconds(common.NotBefore.Value),
                isGuest, roles, metadata);
        }

        private Auth4IdToken? ReadIdClaims(JsonElement payload, string clientId)
        {
            if (!ReadCommon(payload, Auth4Rules.IdTokenClaims, "id", Auth4Rules.IdTokenLifetimeSeconds, out var common)) return null;
            if (!Str(payload, "aud", out var aud) || aud != clientId) return null;
            if (!PositiveInt(payload, "auth_time", out var authTime)) return null;
            string? nonce = null;
            if (payload.TryGetProperty("nonce", out _))
            {
                if (!Str(payload, "nonce", out var value) || value.Length < 16 || value.Length > 512) return null;
                nonce = value;
            }
            string? email = null;
            if (payload.TryGetProperty("email", out _))
            {
                if (!Str(payload, "email", out var value) || !Auth4Rules.IsEmailAddress(value)) return null;
                email = value;
            }
            bool? emailVerified = null;
            if (payload.TryGetProperty("email_verified", out var verified))
            {
                if (verified.ValueKind != JsonValueKind.True && verified.ValueKind != JsonValueKind.False) return null;
                emailVerified = verified.GetBoolean();
            }
            if (emailVerified == true && email == null) return null;
            if (!IdpIsValid(payload)) return null;
            return new Auth4IdToken(
                common.Subject, TenantId, Issuer, aud, common.TokenId,
                DateTimeOffset.FromUnixTimeSeconds(common.IssuedAt),
                DateTimeOffset.FromUnixTimeSeconds(common.ExpiresAt),
                DateTimeOffset.FromUnixTimeSeconds(authTime),
                nonce, email, emailVerified);
        }

        /// <summary>AUTH4D-258: idp, when present, is any well-formed method name.</summary>
        private static bool IdpIsValid(JsonElement payload) =>
            !payload.TryGetProperty("idp", out _) || (Str(payload, "idp", out var idp) && Auth4Rules.Idp.IsMatch(idp));

        /// <summary>AUTH4D-324: name, when present, is Name#1234.</summary>
        private static bool PlayerNameIsValid(JsonElement payload) =>
            !payload.TryGetProperty("name", out _) ||
            (Str(payload, "name", out var name) && Auth4Rules.PlayerName.IsMatch(name));

        private static bool Str(JsonElement payload, string name, out string value)
        {
            value = "";
            if (!payload.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String) return false;
            value = element.GetString()!;
            return true;
        }

        private static bool PositiveInt(JsonElement payload, string name, out long value)
        {
            value = 0;
            return payload.TryGetProperty(name, out var element) &&
                element.ValueKind == JsonValueKind.Number &&
                element.TryGetInt64(out value) &&
                value > 0;
        }

        private static bool FixedTimeEquals(string left, string right)
        {
            var a = Encoding.UTF8.GetBytes(left);
            var b = Encoding.UTF8.GetBytes(right);
            if (a.Length != b.Length) return false;
            var difference = 0;
            for (var i = 0; i < a.Length; i++) difference |= a[i] ^ b[i];
            return difference == 0;
        }

        private readonly struct Common
        {
            public Common(string subject, string tokenId, long expiresAt, long issuedAt, long? notBefore)
            {
                Subject = subject;
                TokenId = tokenId;
                ExpiresAt = expiresAt;
                IssuedAt = issuedAt;
                NotBefore = notBefore;
            }

            public string Subject { get; }
            public string TokenId { get; }
            public long ExpiresAt { get; }
            public long IssuedAt { get; }
            public long? NotBefore { get; }
        }
    }

    /// <summary>The checked parts of a tenant's OpenID Connect discovery document.</summary>
    public sealed class Auth4Discovery
    {
        internal Auth4Discovery(string issuer, string jwksUri, string? tokenEndpoint, string? userInfoEndpoint, string? introspectionEndpoint)
        {
            Issuer = issuer;
            JwksUri = jwksUri;
            TokenEndpoint = tokenEndpoint;
            UserInfoEndpoint = userInfoEndpoint;
            IntrospectionEndpoint = introspectionEndpoint;
        }

        /// <summary><c>issuer</c>: equal to the configured issuer.</summary>
        public string Issuer { get; }

        /// <summary><c>jwks_uri</c>: equal to the derived JWKS URL.</summary>
        public string JwksUri { get; }

        /// <summary><c>token_endpoint</c>.</summary>
        public string? TokenEndpoint { get; }

        /// <summary><c>userinfo_endpoint</c>.</summary>
        public string? UserInfoEndpoint { get; }

        /// <summary><c>introspection_endpoint</c>, when the issuer offers introspection.</summary>
        public string? IntrospectionEndpoint { get; }
    }
}
