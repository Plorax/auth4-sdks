using System;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication;

namespace Auth4.Server.AspNetCore
{
    /// <summary>Default names for the auth4.dev bearer scheme.</summary>
    public static class Auth4BearerDefaults
    {
        /// <summary>The default scheme name, <c>Auth4</c>.</summary>
        public const string AuthenticationScheme = "Auth4";
    }

    /// <summary>
    /// Options for <see cref="Auth4BearerHandler"/>. They mirror <see cref="Auth4ServerOptions"/>;
    /// one <see cref="Auth4ServerClient"/> is created per scheme and reused for every request.
    /// </summary>
    public sealed class Auth4BearerOptions : AuthenticationSchemeOptions
    {
        /// <inheritdoc cref="Auth4ServerOptions.TenantId"/>
        public string TenantId { get; set; } = "";

        /// <inheritdoc cref="Auth4ServerOptions.Issuer"/>
        public string? Issuer { get; set; }

        /// <inheritdoc cref="Auth4ServerOptions.AuthOrigin"/>
        public string? AuthOrigin { get; set; }

        /// <inheritdoc cref="Auth4ServerOptions.Audience"/>
        public string Audience { get; set; } = "";

        /// <inheritdoc cref="Auth4ServerOptions.Introspection"/>
        public Auth4IntrospectionOptions? Introspection { get; set; }

        /// <inheritdoc cref="Auth4ServerOptions.ClockTolerance"/>
        public TimeSpan ClockTolerance { get; set; } = TimeSpan.Zero;

        /// <inheritdoc cref="Auth4ServerOptions.JwksCacheTtl"/>
        public TimeSpan JwksCacheTtl { get; set; } = TimeSpan.FromMinutes(5);

        /// <inheritdoc cref="Auth4ServerOptions.JwksRefreshCooldown"/>
        public TimeSpan JwksRefreshCooldown { get; set; } = TimeSpan.FromSeconds(30);

        /// <inheritdoc cref="Auth4ServerOptions.JwksFetchTimeout"/>
        public TimeSpan JwksFetchTimeout { get; set; } = TimeSpan.FromSeconds(3);

        /// <inheritdoc cref="Auth4ServerOptions.HttpClient"/>
        public HttpClient? HttpClient { get; set; }

        /// <inheritdoc cref="Auth4ServerOptions.Now"/>
        public Func<DateTimeOffset>? Now { get; set; }

        /// <summary>
        /// When signing keys or introspection are unavailable, challenge with 503 and
        /// <c>Retry-After: 5</c> instead of 401, so an outage doesn't sign players out. Default true.
        /// </summary>
        public bool OutageAsServiceUnavailable { get; set; } = true;

        internal Auth4ServerOptions ToServerOptions() => new Auth4ServerOptions
        {
            TenantId = TenantId,
            Issuer = Issuer,
            AuthOrigin = AuthOrigin,
            Audience = Audience,
            Introspection = Introspection,
            ClockTolerance = ClockTolerance,
            JwksCacheTtl = JwksCacheTtl,
            JwksRefreshCooldown = JwksRefreshCooldown,
            JwksFetchTimeout = JwksFetchTimeout,
            HttpClient = HttpClient,
            Now = Now,
        };
    }
}
