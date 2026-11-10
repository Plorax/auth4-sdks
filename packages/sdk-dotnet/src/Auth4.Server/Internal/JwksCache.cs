using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace Auth4.Server.Internal
{
    /// <summary>
    /// Signing keys from the configured issuer's JWKS, cached for <c>JwksCacheTtl</c>. An unknown
    /// <c>kid</c> triggers one refresh per cooldown, so key rotation needs no restart. Concurrent
    /// callers share one in-flight fetch.
    /// </summary>
    internal sealed class JwksCache
    {
        private const int MaxKeys = 64;
        private static readonly string[] PrivateRsaParameters = { "d", "p", "q", "dp", "dq", "qi", "oth" };

        private readonly HttpClient httpClient;
        private readonly string jwksUrl;
        private readonly long cacheTtlMs;
        private readonly long refreshCooldownMs;
        private readonly TimeSpan fetchTimeout;
        private readonly Func<long> nowMs;
        private readonly object gate = new object();
        private Snapshot? cached;
        private Task? refresh;
        private long lastFetchAttemptAt = long.MinValue / 2;
        private long lastUnknownKidRefreshAt = long.MinValue / 2;

        public JwksCache(HttpClient httpClient, string jwksUrl, TimeSpan cacheTtl, TimeSpan refreshCooldown, TimeSpan fetchTimeout, Func<long> nowMs)
        {
            this.httpClient = httpClient;
            this.jwksUrl = jwksUrl;
            cacheTtlMs = (long)cacheTtl.TotalMilliseconds;
            refreshCooldownMs = (long)refreshCooldown.TotalMilliseconds;
            this.fetchTimeout = fetchTimeout;
            this.nowMs = nowMs;
        }

        public async Task<RSAParameters?> GetKeyAsync(string kid)
        {
            var snapshot = cached;
            if (snapshot != null && snapshot.ExpiresAt > nowMs())
            {
                if (snapshot.Keys.TryGetValue(kid, out var existing)) return existing;
                await RefreshAsync(unknownKid: true).ConfigureAwait(false);
            }
            else
            {
                await RefreshAsync(unknownKid: false).ConfigureAwait(false);
            }
            return cached != null && cached.Keys.TryGetValue(kid, out var key) ? key : (RSAParameters?)null;
        }

        private Task RefreshAsync(bool unknownKid)
        {
            lock (gate)
            {
                if (refresh != null) return refresh;
                var now = nowMs();
                if (unknownKid)
                {
                    if (now - lastUnknownKidRefreshAt < refreshCooldownMs) throw Limited();
                    lastUnknownKidRefreshAt = now;
                }
                else if (now - lastFetchAttemptAt < refreshCooldownMs)
                {
                    throw Limited();
                }
                lastFetchAttemptAt = now;
                refresh = FetchAndClearAsync();
                return refresh;
            }
        }

        private async Task FetchAndClearAsync()
        {
            try
            {
                await Task.Yield();
                cached = await Telemetry.TrackAsync(Telemetry.JwksFetch, FetchAsync).ConfigureAwait(false);
            }
            finally
            {
                lock (gate) refresh = null;
            }
        }

        private async Task<Snapshot> FetchAsync()
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, jwksUrl);
                request.Headers.TryAddWithoutValidation("Accept", "application/jwk-set+json, application/json");
                using var body = await BoundedHttp
                    .SendForJsonObjectAsync(httpClient, request, fetchTimeout, "The JWKS endpoint")
                    .ConfigureAwait(false);
                if (!body.RootElement.TryGetProperty("keys", out var keys) ||
                    keys.ValueKind != JsonValueKind.Array ||
                    keys.GetArrayLength() > MaxKeys)
                {
                    throw new InvalidOperationException("JWKS response has an invalid or oversized key set.");
                }

                var imported = new Dictionary<string, RSAParameters>(StringComparer.Ordinal);
                foreach (var candidate in keys.EnumerateArray())
                {
                    if (!IsPublicRs256Jwk(candidate)) continue;
                    var kid = candidate.GetProperty("kid").GetString()!;
                    if (imported.ContainsKey(kid)) throw new InvalidOperationException("JWKS contains duplicate key IDs.");
                    imported[kid] = Import(candidate);
                }
                if (imported.Count == 0) throw new InvalidOperationException("JWKS contains no usable RS256 public keys.");
                return new Snapshot(imported, nowMs() + cacheTtlMs);
            }
            catch (Exception cause)
            {
                throw new Auth4TokenException(
                    Auth4TokenErrorCode.JwksUnavailable,
                    "Signing keys could not be refreshed from the configured issuer.",
                    cause);
            }
        }

        private static bool IsPublicRs256Jwk(JsonElement value)
        {
            if (value.ValueKind != JsonValueKind.Object) return false;
            if (!IsString(value, "kty", out var kty) || kty != "RSA") return false;
            if (!IsString(value, "kid", out var kid) || kid.Length < 1 || kid.Length > 128) return false;
            if (!IsString(value, "n", out _) || !IsString(value, "e", out _)) return false;
            if (value.TryGetProperty("alg", out var alg) && !(alg.ValueKind == JsonValueKind.String && alg.GetString() == "RS256")) return false;
            if (value.TryGetProperty("use", out var use) && !(use.ValueKind == JsonValueKind.String && use.GetString() == "sig")) return false;
            if (value.TryGetProperty("key_ops", out var ops) &&
                !(ops.ValueKind == JsonValueKind.Array &&
                  ops.EnumerateArray().Any(op => op.ValueKind == JsonValueKind.String && op.GetString() == "verify")))
            {
                return false;
            }
            return PrivateRsaParameters.All(parameter => !value.TryGetProperty(parameter, out _));
        }

        private static bool IsString(JsonElement value, string name, out string result)
        {
            result = "";
            if (!value.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String) return false;
            result = property.GetString()!;
            return true;
        }

        private static RSAParameters Import(JsonElement jwk)
        {
            var modulus = Base64Url.TryDecode(jwk.GetProperty("n").GetString()!);
            var exponent = Base64Url.TryDecode(jwk.GetProperty("e").GetString()!);
            if (modulus == null || exponent == null) throw new InvalidOperationException("JWKS key is not valid base64url.");
            var significant = modulus.SkipWhile(b => b == 0).ToArray();
            // RS256 keys must be at least 2048 bits, as jose enforces for the TypeScript SDK.
            if (significant.Length < 256) throw new InvalidOperationException("JWKS key is shorter than 2048 bits.");
            var parameters = new RSAParameters { Modulus = significant, Exponent = exponent };
            // Import once to reject malformed keys while fetching. Each verification imports its own
            // instance, because RSA objects aren't documented as safe for concurrent use.
            using (var rsa = RSA.Create()) rsa.ImportParameters(parameters);
            return parameters;
        }

        private static Auth4TokenException Limited()
        {
            Telemetry.Instant(Telemetry.JwksFetch, Telemetry.RefreshLimited);
            return new Auth4TokenException(Auth4TokenErrorCode.JwksRefreshLimited, "A signing-key refresh was recently attempted.");
        }

        private sealed class Snapshot
        {
            public Snapshot(IReadOnlyDictionary<string, RSAParameters> keys, long expiresAt)
            {
                Keys = keys;
                ExpiresAt = expiresAt;
            }

            public IReadOnlyDictionary<string, RSAParameters> Keys { get; }
            public long ExpiresAt { get; }
        }
    }
}
