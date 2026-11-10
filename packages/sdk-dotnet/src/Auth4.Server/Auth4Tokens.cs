using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Auth4.Server
{
    /// <summary>Claims from a verified access token. Every value has already been checked.</summary>
    public sealed class Auth4AccessToken
    {
        internal Auth4AccessToken(
            string subject,
            string tenantId,
            string issuer,
            string audience,
            string clientId,
            string scope,
            string? sessionId,
            string tokenId,
            DateTimeOffset issuedAt,
            DateTimeOffset expiresAt,
            DateTimeOffset? notBefore,
            bool isGuest,
            IReadOnlyList<string> roles,
            IReadOnlyDictionary<string, JsonElement> metadata)
        {
            Subject = subject;
            TenantId = tenantId;
            Issuer = issuer;
            Audience = audience;
            ClientId = clientId;
            Scope = scope;
            Scopes = scope.Split(' ');
            SessionId = sessionId;
            TokenId = tokenId;
            IssuedAt = issuedAt;
            ExpiresAt = expiresAt;
            NotBefore = notBefore;
            IsGuest = isGuest;
            Roles = roles;
            Metadata = metadata;
        }

        /// <summary><c>sub</c>: the player's user ID. It stays the same when a guest upgrades.</summary>
        public string Subject { get; }

        /// <summary><c>tenant_id</c>: always the configured project ID.</summary>
        public string TenantId { get; }

        /// <summary><c>iss</c>: always the configured issuer.</summary>
        public string Issuer { get; }

        /// <summary><c>aud</c>: always the configured audience.</summary>
        public string Audience { get; }

        /// <summary><c>client_id</c>: the application the token was issued to.</summary>
        public string ClientId { get; }

        /// <summary><c>scope</c>: space-separated granted scopes.</summary>
        public string Scope { get; }

        /// <summary><see cref="Scope"/> split into names.</summary>
        public IReadOnlyList<string> Scopes { get; }

        /// <summary><c>sid</c>: the session ID, when the token belongs to a session.</summary>
        public string? SessionId { get; }

        /// <summary><c>jti</c>: the token ID.</summary>
        public string TokenId { get; }

        /// <summary><c>iat</c>.</summary>
        public DateTimeOffset IssuedAt { get; }

        /// <summary><c>exp</c>: at most five minutes after <see cref="IssuedAt"/>.</summary>
        public DateTimeOffset ExpiresAt { get; }

        /// <summary><c>nbf</c>, when present.</summary>
        public DateTimeOffset? NotBefore { get; }

        /// <summary>
        /// True only when the signed <c>auth4_guest</c> claim is true (AUTH4D-64). The claim is
        /// re-evaluated on every issuance, so it becomes false on the first token issued after a guest
        /// upgrades. Tokens without the claim are not guests.
        /// </summary>
        public bool IsGuest { get; }

        /// <summary>
        /// The subject's roles in the token's application, from the signed <c>auth4_roles</c> claim
        /// (AUTH4D-154). Empty when the claim is absent.
        /// </summary>
        public IReadOnlyList<string> Roles { get; }

        /// <summary>
        /// The signed <c>auth4_meta</c> claim: flat per-user metadata whose values are strings,
        /// numbers, booleans or null. Empty when the claim is absent.
        /// </summary>
        public IReadOnlyDictionary<string, JsonElement> Metadata { get; }

        /// <summary>True when the token carries <paramref name="role"/>. Exact and case-sensitive.</summary>
        public bool HasRole(string role) => Roles.Contains(role, StringComparer.Ordinal);

        /// <summary>True when the token carries at least one of <paramref name="roles"/>. An empty list never matches.</summary>
        public bool HasAnyRole(params string[] roles) => roles.Any(HasRole);

        /// <summary>True when <paramref name="scope"/> was granted. Exact and case-sensitive.</summary>
        public bool HasScope(string scope) => Scopes.Contains(scope, StringComparer.Ordinal);

        /// <summary>Tokens are never part of the string form.</summary>
        public override string ToString() => $"Auth4AccessToken {{ Subject = {Subject}, ClientId = {ClientId} }}";
    }

    /// <summary>
    /// Claims from a verified ID token. ID tokens prove a sign-in to the application that requested
    /// it; they never authorize API calls, so they have their own type and validation path.
    /// </summary>
    public sealed class Auth4IdToken
    {
        internal Auth4IdToken(
            string subject,
            string tenantId,
            string issuer,
            string clientId,
            string tokenId,
            DateTimeOffset issuedAt,
            DateTimeOffset expiresAt,
            DateTimeOffset authTime,
            string? nonce,
            string? email,
            bool? emailVerified)
        {
            Subject = subject;
            TenantId = tenantId;
            Issuer = issuer;
            ClientId = clientId;
            TokenId = tokenId;
            IssuedAt = issuedAt;
            ExpiresAt = expiresAt;
            AuthTime = authTime;
            Nonce = nonce;
            Email = email;
            EmailVerified = emailVerified;
        }

        /// <summary><c>sub</c>.</summary>
        public string Subject { get; }

        /// <summary><c>tenant_id</c>.</summary>
        public string TenantId { get; }

        /// <summary><c>iss</c>.</summary>
        public string Issuer { get; }

        /// <summary><c>aud</c>: the client ID the ID token was issued to.</summary>
        public string ClientId { get; }

        /// <summary><c>jti</c>.</summary>
        public string TokenId { get; }

        /// <summary><c>iat</c>.</summary>
        public DateTimeOffset IssuedAt { get; }

        /// <summary><c>exp</c>.</summary>
        public DateTimeOffset ExpiresAt { get; }

        /// <summary><c>auth_time</c>.</summary>
        public DateTimeOffset AuthTime { get; }

        /// <summary><c>nonce</c>, when the authorization request sent one.</summary>
        public string? Nonce { get; }

        /// <summary><c>email</c>, when the <c>email</c> scope was granted.</summary>
        public string? Email { get; }

        /// <summary><c>email_verified</c>, when present.</summary>
        public bool? EmailVerified { get; }

        /// <summary>Tokens are never part of the string form.</summary>
        public override string ToString() => $"Auth4IdToken {{ Subject = {Subject}, ClientId = {ClientId} }}";
    }
}
