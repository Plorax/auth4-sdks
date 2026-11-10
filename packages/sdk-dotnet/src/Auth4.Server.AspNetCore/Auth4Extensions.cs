using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Auth4.Server.AspNetCore
{
    /// <summary>Registration and request helpers for auth4.dev bearer authentication.</summary>
    public static class Auth4Extensions
    {
        /// <summary>Adds the auth4.dev bearer scheme under <see cref="Auth4BearerDefaults.AuthenticationScheme"/>.</summary>
        public static AuthenticationBuilder AddAuth4Bearer(this AuthenticationBuilder builder, Action<Auth4BearerOptions> configure) =>
            builder.AddAuth4Bearer(Auth4BearerDefaults.AuthenticationScheme, configure);

        /// <summary>
        /// Adds an auth4.dev bearer scheme. Add one scheme per audience when several applications
        /// call the same API.
        /// </summary>
        public static AuthenticationBuilder AddAuth4Bearer(this AuthenticationBuilder builder, string scheme, Action<Auth4BearerOptions> configure)
        {
            if (builder == null) throw new ArgumentNullException(nameof(builder));
            builder.Services.TryAddSingleton<Auth4BearerClients>();
            return builder.AddScheme<Auth4BearerOptions, Auth4BearerHandler>(scheme, configure);
        }

        /// <summary>The verified access token for this request, or null when it isn't authenticated by auth4.dev.</summary>
        public static Auth4AccessToken? GetAuth4AccessToken(this HttpContext context) =>
            context?.Features.Get<IAuth4AccessTokenFeature>()?.AccessToken;

        /// <summary>True when the principal comes from a token with <c>"auth4_guest": true</c>.</summary>
        public static bool IsAuth4Guest(this ClaimsPrincipal principal) =>
            principal?.HasClaim(Auth4ClaimTypes.Guest, "true") == true;

        /// <summary>Requires a token whose player has upgraded from a guest account (or never was one).</summary>
        public static AuthorizationPolicyBuilder RequireNonGuest(this AuthorizationPolicyBuilder builder) =>
            builder.RequireClaim(Auth4ClaimTypes.Guest, "false");

        /// <summary>Requires a granted scope, matched exactly.</summary>
        public static AuthorizationPolicyBuilder RequireScope(this AuthorizationPolicyBuilder builder, string scope) =>
            builder.RequireAssertion(context =>
                context.User.FindFirst(Auth4ClaimTypes.Scope)?.Value.Split(' ') is { } scopes &&
                Array.IndexOf(scopes, scope) >= 0);
    }
}
