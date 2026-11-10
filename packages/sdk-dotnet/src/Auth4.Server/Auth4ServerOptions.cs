using System;
using System.Net.Http;

namespace Auth4.Server
{
    /// <summary>Configuration for one tenant and one resource audience. Mirrors @auth4/sdk-server.</summary>
    public sealed class Auth4ServerOptions
    {
        /// <summary>The project ID, <c>ten_…</c>.</summary>
        public string TenantId { get; set; } = "";

        /// <summary>
        /// Trusted, configured tenant issuer, <c>{AUTH_ORIGIN}/t/{tenantId}</c>. Leave empty and set
        /// <see cref="AuthOrigin"/> instead to have it derived.
        /// </summary>
        public string? Issuer { get; set; }

        /// <summary>The auth origin, for example <c>https://auth.auth4.dev</c>. Used when <see cref="Issuer"/> is empty.</summary>
        public string? AuthOrigin { get; set; }

        /// <summary>The API audience this server accepts: the client ID of the application calling it.</summary>
        public string Audience { get; set; } = "";

        /// <summary>
        /// Injectable for tests and custom hosts. The SDK only ever sends it to the URLs derived from
        /// the configured issuer. When null, the client creates and owns its own instance.
        /// </summary>
        public HttpClient? HttpClient { get; set; }

        /// <summary>How long a fetched key set is trusted. Default 5 minutes; 10 seconds to 1 hour.</summary>
        public TimeSpan JwksCacheTtl { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>Minimum gap between key refreshes. Default 30 seconds; 1 second to 10 minutes.</summary>
        public TimeSpan JwksRefreshCooldown { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>Timeout for one key-set request. Default 3 seconds; 10 ms to 10 seconds.</summary>
        public TimeSpan JwksFetchTimeout { get; set; } = TimeSpan.FromSeconds(3);

        /// <summary>Allowed clock drift for <c>exp</c> and <c>nbf</c>. Default zero; at most 60 seconds.</summary>
        public TimeSpan ClockTolerance { get; set; } = TimeSpan.Zero;

        /// <summary>Injectable clock, primarily for deterministic tests.</summary>
        public Func<DateTimeOffset>? Now { get; set; }

        /// <summary>
        /// AUTH4D-155: opt in to a live revocation check. After local verification succeeds, the
        /// token is also sent to the tenant's introspection endpoint, so a revoked session is refused
        /// within <see cref="Auth4IntrospectionOptions.CacheTtl"/> instead of up to five minutes later.
        /// Off by default.
        /// </summary>
        public Auth4IntrospectionOptions? Introspection { get; set; }
    }

    /// <summary>Confidential server client credentials and cache settings for introspect mode.</summary>
    public sealed class Auth4IntrospectionOptions
    {
        /// <summary>The server client's ID, <c>cli_…</c>.</summary>
        public string ClientId { get; set; } = "";

        /// <summary>Keep this in a secret store. The SDK never exposes, logs or serializes it.</summary>
        public string ClientSecret { get; set; } = "";

        /// <summary>How long an active answer is reused for the same token. Default 5 seconds; zero disables caching; at most 60 seconds.</summary>
        public TimeSpan CacheTtl { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>Timeout for one introspection request. Default 3 seconds; 10 ms to 10 seconds.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);

        /// <summary>The secret is never part of the string form.</summary>
        public override string ToString() => $"Auth4IntrospectionOptions {{ ClientId = {ClientId} }}";
    }
}
