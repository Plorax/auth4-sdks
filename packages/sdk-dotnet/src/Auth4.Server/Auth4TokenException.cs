using System;

namespace Auth4.Server
{
    /// <summary>Why a token was refused. The wire names match @auth4/sdk-server's error codes.</summary>
    public enum Auth4TokenErrorCode
    {
        /// <summary><c>invalid_token</c>: the token is malformed, expired, revoked or not for this API.</summary>
        InvalidToken,

        /// <summary><c>jwks_unavailable</c>: signing keys could not be fetched from the configured issuer.</summary>
        JwksUnavailable,

        /// <summary><c>jwks_refresh_limited</c>: a key refresh was attempted too recently.</summary>
        JwksRefreshLimited,

        /// <summary><c>introspection_unavailable</c>: introspect mode could not check the session.</summary>
        IntrospectionUnavailable,
    }

    /// <summary>
    /// Thrown when verification fails. Only <see cref="Auth4TokenErrorCode.InvalidToken"/> means the
    /// token itself is bad; the other codes are outages, which callers may report as 503.
    /// </summary>
    public sealed class Auth4TokenException : Exception
    {
        /// <summary>Creates the exception.</summary>
        public Auth4TokenException(Auth4TokenErrorCode code, string message, Exception? inner = null)
            : base(message, inner)
        {
            Code = code;
        }

        /// <summary>The failure category.</summary>
        public Auth4TokenErrorCode Code { get; }

        /// <summary>The protocol name of <see cref="Code"/>, for example <c>invalid_token</c>.</summary>
        public string CodeName => Code switch
        {
            Auth4TokenErrorCode.InvalidToken => "invalid_token",
            Auth4TokenErrorCode.JwksUnavailable => "jwks_unavailable",
            Auth4TokenErrorCode.JwksRefreshLimited => "jwks_refresh_limited",
            _ => "introspection_unavailable",
        };

        /// <summary>True for every code except <see cref="Auth4TokenErrorCode.InvalidToken"/>.</summary>
        public bool IsOutage => Code != Auth4TokenErrorCode.InvalidToken;

        internal static Auth4TokenException Invalid(Exception? inner = null) =>
            new Auth4TokenException(Auth4TokenErrorCode.InvalidToken, "The token is invalid.", inner);
    }

    /// <summary>Thrown by <see cref="Auth4ServerClient.DiscoverAsync"/> when the issuer's metadata can't be used.</summary>
    public sealed class Auth4DiscoveryException : Exception
    {
        /// <summary>Creates the exception.</summary>
        public Auth4DiscoveryException(string message, Exception? inner = null)
            : base(message, inner)
        {
        }
    }
}
