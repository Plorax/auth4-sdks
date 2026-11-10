using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Auth4.Server.Internal
{
    /// <summary>
    /// Introspect mode (AUTH4D-155): after offline verification, asks the tenant's RFC 7662
    /// endpoint whether the token's session is still live. Unreachable or unexpected answers fail
    /// closed. Mirrors @auth4/sdk-server's assertActive.
    /// </summary>
    internal sealed class Introspector
    {
        private const int MaxCacheEntries = 10_000;

        private readonly HttpClient httpClient;
        private readonly string tenantId;
        private readonly AuthenticationHeaderValue authorization;
        private readonly long cacheTtlMs;
        private readonly TimeSpan timeout;
        private readonly Func<long> nowMs;
        private readonly object gate = new object();
        private readonly Dictionary<string, CacheEntry> cache = new Dictionary<string, CacheEntry>(StringComparer.Ordinal);
        private readonly Queue<KeyValuePair<string, long>> insertionOrder = new Queue<KeyValuePair<string, long>>();
        private readonly ConcurrentDictionary<string, Lazy<Task<Answer>>> inFlight = new ConcurrentDictionary<string, Lazy<Task<Answer>>>(StringComparer.Ordinal);
        private long stamp;

        public Introspector(HttpClient httpClient, string issuer, string tenantId, Auth4IntrospectionOptions options, Func<long> nowMs)
        {
            if (options.ClientId == null || !Auth4Rules.ClientId.IsMatch(options.ClientId))
            {
                throw new ArgumentException("Introspection.ClientId must be a server client ID.", nameof(options));
            }
            if (options.ClientSecret == null || options.ClientSecret.Length < 32 || options.ClientSecret.Length > 512)
            {
                throw new ArgumentException("Introspection.ClientSecret must be the server client's secret.", nameof(options));
            }
            cacheTtlMs = (long)Bounded("Introspection.CacheTtl", options.CacheTtl, TimeSpan.Zero, TimeSpan.FromSeconds(60)).TotalMilliseconds;
            timeout = Bounded("Introspection.Timeout", options.Timeout, TimeSpan.FromMilliseconds(10), TimeSpan.FromSeconds(10));
            this.httpClient = httpClient;
            this.tenantId = tenantId;
            this.nowMs = nowMs;
            // Like the JWKS URL, the endpoint comes only from the configured issuer, never from a token.
            Url = $"{new Uri(issuer).GetLeftPart(UriPartial.Authority)}/oauth/introspect?tenant_id={Uri.EscapeDataString(tenantId)}";
            // RFC 6749 section 2.3.1: form-encode each part before Basic encoding.
            var credentials = $"{FormEncode(options.ClientId)}:{FormEncode(options.ClientSecret)}";
            authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials)));
        }

        public string Url { get; }

        internal static TimeSpan Bounded(string name, TimeSpan value, TimeSpan minimum, TimeSpan maximum)
        {
            if (value < minimum || value > maximum)
            {
                throw new ArgumentOutOfRangeException(name, $"{name} must be from {minimum} to {maximum}.");
            }
            return value;
        }

        /// <summary>Percent-encodes like encodeURIComponent; the server percent-decodes both parts.</summary>
        private static string FormEncode(string value) => Uri.EscapeDataString(value);

        public async Task AssertActiveAsync(string token, Auth4AccessToken claims)
        {
            var cacheKey = Sha256Hex(token);
            var now = nowMs();
            lock (gate)
            {
                if (cache.TryGetValue(cacheKey, out var cached))
                {
                    if (cached.ExpiresAt > now)
                    {
                        if (!cached.Active) throw Auth4TokenException.Invalid();
                        return;
                    }
                    cache.Remove(cacheKey);
                }
            }

            // Lazy, because GetOrAdd may run its factory twice under contention.
            var pending = inFlight.GetOrAdd(cacheKey, _ => new Lazy<Task<Answer>>(() => IntrospectAndForgetAsync(cacheKey, token)));
            var answer = await pending.Value.ConfigureAwait(false);
            if (answer.Active == null)
            {
                throw new Auth4TokenException(
                    Auth4TokenErrorCode.IntrospectionUnavailable,
                    "The introspection response was not understood.");
            }
            var active = answer.Active.Value;
            if (active &&
                (answer.Subject != claims.Subject ||
                 answer.ClientId != claims.ClientId ||
                 answer.TokenId != claims.TokenId ||
                 answer.TenantId != tenantId))
            {
                throw Auth4TokenException.Invalid();
            }
            // A revoked session never comes back, so an inactive answer is kept until the token expires.
            var tokenExpiresAt = claims.ExpiresAt.ToUnixTimeMilliseconds();
            var expiresAt = active ? Math.Min(now + cacheTtlMs, tokenExpiresAt) : tokenExpiresAt;
            if (expiresAt > now && (cacheTtlMs > 0 || !active)) Remember(cacheKey, active, expiresAt);
            if (!active) throw Auth4TokenException.Invalid();
        }

        private void Remember(string key, bool active, long expiresAt)
        {
            lock (gate)
            {
                if (!cache.ContainsKey(key) && cache.Count >= MaxCacheEntries)
                {
                    // Evict the oldest live entry; queue items for replaced entries are skipped.
                    while (insertionOrder.Count > 0)
                    {
                        var oldest = insertionOrder.Dequeue();
                        if (cache.TryGetValue(oldest.Key, out var entry) && entry.Stamp == oldest.Value)
                        {
                            cache.Remove(oldest.Key);
                            break;
                        }
                    }
                }
                var next = ++stamp;
                cache[key] = new CacheEntry(active, expiresAt, next);
                insertionOrder.Enqueue(new KeyValuePair<string, long>(key, next));
                if (insertionOrder.Count > MaxCacheEntries * 2)
                {
                    var live = cache.OrderBy(pair => pair.Value.Stamp).Select(pair => new KeyValuePair<string, long>(pair.Key, pair.Value.Stamp)).ToList();
                    insertionOrder.Clear();
                    foreach (var item in live) insertionOrder.Enqueue(item);
                }
            }
        }

        internal int CacheCount
        {
            get
            {
                lock (gate) return cache.Count;
            }
        }

        private async Task<Answer> IntrospectAndForgetAsync(string cacheKey, string token)
        {
            try
            {
                await Task.Yield();
                return await IntrospectAsync(token).ConfigureAwait(false);
            }
            finally
            {
                inFlight.TryRemove(cacheKey, out _);
            }
        }

        private async Task<Answer> IntrospectAsync(string token)
        {
            var scope = Telemetry.Begin(Telemetry.Introspect);
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, Url)
                {
                    Content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("token", token) }),
                };
                request.Headers.Authorization = authorization;
                request.Headers.TryAddWithoutValidation("Accept", "application/json");
                using var body = await BoundedHttp
                    .SendForJsonObjectAsync(httpClient, request, timeout, "The introspection endpoint")
                    .ConfigureAwait(false);
                var root = body.RootElement;
                bool? active = null;
                if (root.TryGetProperty("active", out var value) &&
                    (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False))
                {
                    active = value.GetBoolean();
                }
                // An answer without a boolean active field is refused by the caller, so it counts as unavailable.
                scope.End(active == null ? Telemetry.Unavailable : Telemetry.Success);
                return new Answer(active, Text(root, "sub"), Text(root, "client_id"), Text(root, "jti"), Text(root, "tenant_id"));
            }
            catch (Exception cause)
            {
                scope.End(Telemetry.Unavailable);
                throw new Auth4TokenException(
                    Auth4TokenErrorCode.IntrospectionUnavailable,
                    "The token's session could not be checked with the configured issuer.",
                    cause);
            }
        }

        private static string? Text(JsonElement root, string name) =>
            root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

        private static string Sha256Hex(string value)
        {
            using var sha = SHA256.Create();
            var digest = sha.ComputeHash(Encoding.UTF8.GetBytes(value));
            return string.Concat(digest.Select(b => b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture)));
        }

        private readonly struct CacheEntry
        {
            public CacheEntry(bool active, long expiresAt, long stamp)
            {
                Active = active;
                ExpiresAt = expiresAt;
                Stamp = stamp;
            }

            public bool Active { get; }
            public long ExpiresAt { get; }
            public long Stamp { get; }
        }

        private sealed class Answer
        {
            public Answer(bool? active, string? subject, string? clientId, string? tokenId, string? tenantId)
            {
                Active = active;
                Subject = subject;
                ClientId = clientId;
                TokenId = tokenId;
                TenantId = tenantId;
            }

            public bool? Active { get; }
            public string? Subject { get; }
            public string? ClientId { get; }
            public string? TokenId { get; }
            public string? TenantId { get; }
        }
    }
}
