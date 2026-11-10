using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Auth4.Server.Internal
{
    /// <summary>
    /// Wire rules copied from packages/contracts (AccessTokenClaimsSchema, IdTokenClaimsSchema and
    /// custom-claims.ts). tests/integration/auth4d-169.dotnet-sdk.test.ts keeps them in step.
    /// Patterns end in \z because .NET's $ also matches before a trailing newline.
    /// </summary>
    internal static class Auth4Rules
    {
        public const string ManagementAudience = "urn:auth4:management";
        public const string GuestClaim = "auth4_guest";
        public const string RolesClaim = "auth4_roles";
        public const string MetadataClaim = "auth4_meta";
        public const int AccessTokenLifetimeSeconds = 300;
        public const int IdTokenLifetimeSeconds = 300;
        public const int MaxTokenLength = 16_384;
        public const int MaxScopes = 32;
        public const int MaxRolesPerToken = 20;
        public const int MaxMetadataKeys = 32;
        public const int MaxMetadataBytes = 2_048;
        public const int MaxMetadataStringLength = 256;

        private const RegexOptions Options = RegexOptions.CultureInvariant;
        public static readonly Regex TenantId = new Regex(@"^ten_[A-Za-z0-9]{16,64}\z", Options);
        public static readonly Regex ClientId = new Regex(@"^cli_[A-Za-z0-9]{16,64}\z", Options);
        public static readonly Regex UserId = new Regex(@"^usr_[A-Za-z0-9]{16,64}\z", Options);
        public static readonly Regex SessionId = new Regex(@"^ses_[A-Za-z0-9]{16,64}\z", Options);
        public static readonly Regex TokenId = new Regex(@"^jti_[A-Za-z0-9_-]{16,64}\z", Options);
        public static readonly Regex ScopeName = new Regex(@"^[a-z][a-z0-9:_-]{0,63}\z", Options);
        public static readonly Regex RoleName = new Regex(@"^[a-z][a-z0-9_.-]{0,63}\z", Options);
        public static readonly Regex MetadataKey = new Regex(@"^[a-z][a-z0-9_]{0,39}\z", Options);
        public static readonly Regex Idp = new Regex(@"^[a-z][a-z0-9_]{1,31}\z", Options);
        /// <summary>AUTH4D-324: the opt-in player name claim, Name#1234 (read leniently).</summary>
        public static readonly Regex PlayerName = new Regex(@"^[^#]{1,64}#[0-9]{4}\z", Options);

        public static readonly string[] ReservedClaimNames =
        {
            "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "azp", "auth_time", "nonce", "acr", "amr",
            "sid", "scope", "client_id", "tenant_id", "token_use", "email", "email_verified",
        };

        /// <summary>The contract schemas are strict: any other claim makes the token invalid.</summary>
        public static readonly HashSet<string> AccessTokenClaims = new HashSet<string>(StringComparer.Ordinal)
        {
            "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "tenant_id", "token_use", "client_id",
            "scope", "sid", GuestClaim, RolesClaim, MetadataClaim, "idp", "name",
        };

        public static readonly HashSet<string> IdTokenClaims = new HashSet<string>(StringComparer.Ordinal)
        {
            "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "tenant_id", "token_use", "auth_time",
            "nonce", "email", "email_verified", "idp",
        };

        public static bool IsReservedClaimName(string name) =>
            ReservedClaimNames.Contains(name) || name.StartsWith("auth4_", StringComparison.Ordinal);

        public static bool IsScopeList(string value)
        {
            if (value.Length < 1 || value.Length > 2_048) return false;
            var scopes = value.Split(' ');
            return scopes.Length <= MaxScopes &&
                scopes.All(ScopeName.IsMatch) &&
                new HashSet<string>(scopes, StringComparer.Ordinal).Count == scopes.Length;
        }

        /// <summary>RolesClaimSchema: 1 to 20 unique role names.</summary>
        public static IReadOnlyList<string>? ReadRoles(JsonElement value)
        {
            if (value.ValueKind != JsonValueKind.Array) return null;
            var roles = new List<string>();
            foreach (var item in value.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String) return null;
                var role = item.GetString()!;
                if (!RoleName.IsMatch(role) || roles.Contains(role, StringComparer.Ordinal)) return null;
                roles.Add(role);
            }
            return roles.Count >= 1 && roles.Count <= MaxRolesPerToken ? roles.AsReadOnly() : null;
        }

        /// <summary>MetadataClaimSchema: a non-empty flat object of scalar values, at most 2048 bytes.</summary>
        public static IReadOnlyDictionary<string, JsonElement>? ReadMetadata(JsonElement value)
        {
            if (value.ValueKind != JsonValueKind.Object) return null;
            if (Encoding.UTF8.GetByteCount(value.GetRawText()) > MaxMetadataBytes) return null;
            var metadata = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!MetadataKey.IsMatch(property.Name) || IsReservedClaimName(property.Name)) return null;
                if (metadata.ContainsKey(property.Name)) return null;
                var item = property.Value;
                var scalar = item.ValueKind switch
                {
                    JsonValueKind.String => item.GetString()!.Length <= MaxMetadataStringLength,
                    JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null => true,
                    _ => false,
                };
                if (!scalar) return null;
                metadata[property.Name] = item.Clone();
            }
            return metadata.Count >= 1 && metadata.Count <= MaxMetadataKeys ? metadata : null;
        }

        public static bool IsEmailAddress(string value) =>
            value.Length <= 254 &&
            value.IndexOf('@') > 0 &&
            value.IndexOf('@') == value.LastIndexOf('@') &&
            value.IndexOf('@') < value.Length - 1 &&
            !value.Any(char.IsWhiteSpace);

        /// <summary>
        /// Mirrors @auth4/sdk-server validateIssuer: https (or http on loopback), no credentials,
        /// query or fragment, path exactly /t/{tenantId}, already in canonical form.
        /// </summary>
        public static string ValidateIssuer(string tenantId, string issuer)
        {
            if (!Uri.TryCreate(issuer, UriKind.Absolute, out var url))
            {
                throw new ArgumentException("Issuer must be a valid absolute URL.", nameof(issuer));
            }
            var canonical = $"{CanonicalOrigin(url, nameof(issuer))}/t/{tenantId}";
            if (url.AbsolutePath != $"/t/{tenantId}" || url.Query != "" || url.Fragment != "" ||
                !string.Equals(issuer, canonical, StringComparison.Ordinal))
            {
                throw new ArgumentException("Issuer must be the canonical issuer URL for TenantId.", nameof(issuer));
            }
            return issuer;
        }

        public static string IssuerFromOrigin(string tenantId, string authOrigin)
        {
            if (!Uri.TryCreate(authOrigin, UriKind.Absolute, out var url) ||
                (url.AbsolutePath != "/" && url.AbsolutePath != "") || url.Query != "" || url.Fragment != "")
            {
                throw new ArgumentException("AuthOrigin must be an origin such as https://auth.auth4.dev.", nameof(authOrigin));
            }
            return $"{CanonicalOrigin(url, nameof(authOrigin))}/t/{tenantId}";
        }

        private static string CanonicalOrigin(Uri url, string name)
        {
            var host = url.Host;
            var loopback = host == "localhost" || host == "127.0.0.1" || host == "[::1]";
            var secure = url.Scheme == Uri.UriSchemeHttps || (url.Scheme == Uri.UriSchemeHttp && loopback);
            if (!secure || url.UserInfo != "")
            {
                throw new ArgumentException("The issuer must use https (http only on loopback) and no credentials.", name);
            }
            return url.GetLeftPart(UriPartial.Authority);
        }
    }
}
