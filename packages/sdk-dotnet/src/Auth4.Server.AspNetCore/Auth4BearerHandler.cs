using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth4.Server.AspNetCore
{
    /// <summary>
    /// One <see cref="Auth4ServerClient"/> per scheme, so the signing-key and introspection caches
    /// are shared by every request. Registered as a singleton by <c>AddAuth4Bearer</c>.
    /// </summary>
    public sealed class Auth4BearerClients : IDisposable
    {
        private readonly IOptionsMonitor<Auth4BearerOptions> options;
        private readonly ConcurrentDictionary<string, Lazy<Auth4ServerClient>> clients =
            new ConcurrentDictionary<string, Lazy<Auth4ServerClient>>(StringComparer.Ordinal);

        /// <summary>Created by dependency injection.</summary>
        public Auth4BearerClients(IOptionsMonitor<Auth4BearerOptions> options)
        {
            this.options = options;
        }

        /// <summary>The client for a scheme, for example to call <see cref="Auth4ServerClient.DiscoverAsync"/> at startup.</summary>
        public Auth4ServerClient Get(string scheme = Auth4BearerDefaults.AuthenticationScheme) =>
            clients.GetOrAdd(scheme, name => new Lazy<Auth4ServerClient>(() => new Auth4ServerClient(options.Get(name).ToServerOptions()))).Value;

        /// <summary>Disposes every client.</summary>
        public void Dispose()
        {
            foreach (var client in clients.Values)
            {
                if (client.IsValueCreated) client.Value.Dispose();
            }
        }
    }

    /// <summary>
    /// Authenticates <c>Authorization: Bearer</c> requests with an auth4.dev access token. Requests
    /// without the header get no result, so <c>[AllowAnonymous]</c> endpoints still work. Invalid
    /// tokens fail and are challenged with 401 and <c>WWW-Authenticate: Bearer realm="auth4"</c>.
    /// </summary>
    public sealed class Auth4BearerHandler : AuthenticationHandler<Auth4BearerOptions>
    {
        // Per-scheme request markers, so one scheme's outage never changes another's challenge.
        private const string OutageItem = "Auth4.Server.Outage:";
        private const string PresentedItem = "Auth4.Server.Presented:";
        private readonly Auth4BearerClients clients;

        /// <summary>Created by the authentication middleware.</summary>
        public Auth4BearerHandler(
            IOptionsMonitor<Auth4BearerOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            Auth4BearerClients clients)
            : base(options, logger, encoder)
        {
            this.clients = clients;
        }

        /// <inheritdoc/>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var header = Request.Headers.Authorization.ToString();
            if (string.IsNullOrEmpty(header)) return AuthenticateResult.NoResult();
            Context.Items[PresentedItem + Scheme.Name] = true;
            var token = Auth4ServerClient.ParseBearerToken(header);
            if (token == null) return AuthenticateResult.Fail("The Authorization header is not a single Bearer token.");

            Auth4AccessToken verified;
            try
            {
                verified = await clients.Get(Scheme.Name).ValidateAccessTokenAsync(token).ConfigureAwait(false);
            }
            catch (Auth4TokenException error)
            {
                // Log the code only: the token and the issuer's answer never reach the logs.
                if (error.IsOutage)
                {
                    Context.Items[OutageItem + Scheme.Name] = true;
                    Logger.LogWarning("auth4.dev token check unavailable: {Code}", error.CodeName);
                }
                return AuthenticateResult.Fail(error.CodeName);
            }

            Context.Features.Set<IAuth4AccessTokenFeature>(new Auth4AccessTokenFeature(verified));
            var principal = new ClaimsPrincipal(CreateIdentity(verified, Scheme.Name));
            return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
        }

        /// <inheritdoc/>
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (Options.OutageAsServiceUnavailable && Context.Items.ContainsKey(OutageItem + Scheme.Name))
            {
                Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                Response.Headers.RetryAfter = "5";
                await Response.WriteAsJsonAsync(new Dictionary<string, string> { ["error"] = "temporarily_unavailable" }).ConfigureAwait(false);
                return;
            }
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            Response.Headers.WWWAuthenticate = Context.Items.ContainsKey(PresentedItem + Scheme.Name)
                ? "Bearer realm=\"auth4\", error=\"invalid_token\""
                : "Bearer realm=\"auth4\"";
            await Response.WriteAsJsonAsync(new Dictionary<string, string> { ["error"] = "unauthorized" }).ConfigureAwait(false);
        }

        /// <summary>
        /// The identity built from a verified token. Its name is <c>sub</c> and its roles are the
        /// token's <c>auth4_roles</c>, so <c>[Authorize(Roles = "…")]</c> and <c>User.IsInRole</c> work.
        /// </summary>
        public static ClaimsIdentity CreateIdentity(Auth4AccessToken token, string authenticationType)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            var claims = new List<Claim>
            {
                new Claim(Auth4ClaimTypes.Subject, token.Subject),
                new Claim(ClaimTypes.NameIdentifier, token.Subject),
                new Claim(Auth4ClaimTypes.TenantId, token.TenantId),
                new Claim(Auth4ClaimTypes.ClientId, token.ClientId),
                new Claim(Auth4ClaimTypes.Scope, token.Scope),
                new Claim(Auth4ClaimTypes.Guest, token.IsGuest ? "true" : "false", ClaimValueTypes.Boolean),
            };
            if (token.SessionId != null) claims.Add(new Claim(Auth4ClaimTypes.SessionId, token.SessionId));
            foreach (var role in token.Roles) claims.Add(new Claim(ClaimTypes.Role, role));
            return new ClaimsIdentity(claims, authenticationType, Auth4ClaimTypes.Subject, ClaimTypes.Role);
        }
    }

    /// <summary>Claim types on the <see cref="ClaimsPrincipal"/> the handler builds.</summary>
    public static class Auth4ClaimTypes
    {
        /// <summary><c>sub</c>.</summary>
        public const string Subject = "sub";

        /// <summary><c>tenant_id</c>.</summary>
        public const string TenantId = "tenant_id";

        /// <summary><c>client_id</c>.</summary>
        public const string ClientId = "client_id";

        /// <summary><c>scope</c>.</summary>
        public const string Scope = "scope";

        /// <summary><c>sid</c>.</summary>
        public const string SessionId = "sid";

        /// <summary><c>auth4_guest</c>: <c>true</c> or <c>false</c>.</summary>
        public const string Guest = "auth4_guest";
    }

    /// <summary>The verified token for the current request.</summary>
    public interface IAuth4AccessTokenFeature
    {
        /// <summary>The verified access token.</summary>
        Auth4AccessToken AccessToken { get; }
    }

    internal sealed class Auth4AccessTokenFeature : IAuth4AccessTokenFeature
    {
        public Auth4AccessTokenFeature(Auth4AccessToken accessToken)
        {
            AccessToken = accessToken;
        }

        public Auth4AccessToken AccessToken { get; }
    }
}
