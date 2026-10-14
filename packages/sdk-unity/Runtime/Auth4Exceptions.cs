using System;

namespace Auth4
{
    /// <summary>An OAuth or transport failure. Messages never contain token values.</summary>
    public class Auth4Exception : Exception
    {
        public Auth4Exception(string error, string description = null, int statusCode = 0, Exception inner = null)
            : base(description == null ? error : error + ": " + description, inner)
        {
            Error = error;
            Description = description;
            StatusCode = statusCode;
        }

        /// <summary>OAuth error code, or a client code such as network_error or login_required.</summary>
        public string Error { get; }

        public string Description { get; }

        /// <summary>HTTP status, or 0 when no response was received.</summary>
        public int StatusCode { get; }

        /// <summary>True for failures that may succeed if retried later.</summary>
        public bool IsTransient =>
            Error == "network_error" ||
            Error == "temporarily_unavailable" ||
            Error == "server_error" ||
            StatusCode >= 500;
    }

    public enum DeviceAuthorizationFailure
    {
        Denied,
        Expired,
    }

    /// <summary>The user denied the device, or the device code expired before approval.</summary>
    public sealed class Auth4DeviceAuthorizationException : Auth4Exception
    {
        public Auth4DeviceAuthorizationException(DeviceAuthorizationFailure reason, string error, int statusCode = 0)
            : base(error, null, statusCode)
        {
            Reason = reason;
        }

        public DeviceAuthorizationFailure Reason { get; }
    }

    public enum GuestUpgradeFailure
    {
        /// <summary>The email, Discord or Steam account already belongs to another player. Nothing was merged.</summary>
        Conflict,

        /// <summary>The upgrade intent expired before the player finished in the browser.</summary>
        Expired,

        /// <summary>The player chose Not now on the hosted page.</summary>
        Denied,

        /// <summary>The cancellation token fired; the game stopped waiting.</summary>
        Cancelled,

        /// <summary>WebGL: the browser blocked the upgrade popup. Start the upgrade from a pointer-down handler.</summary>
        PopupBlocked,

        /// <summary>WebGL: the player closed the upgrade window.</summary>
        WindowClosed,

        /// <summary>WebGL: the guest session ended (signed out, replaced or rejected by the server).</summary>
        SessionEnded,
    }

    /// <summary>
    /// UpgradeGuestAsync ended without an upgraded session. The guest session is unchanged except
    /// after Cancelled, when the player may still have finished linking in the browser, and after
    /// SessionEnded.
    /// </summary>
    public sealed class Auth4GuestUpgradeException : Auth4Exception
    {
        public Auth4GuestUpgradeException(
            GuestUpgradeFailure reason,
            string error,
            int statusCode = 0,
            Exception inner = null)
            : base(error, null, statusCode, inner)
        {
            Reason = reason;
        }

        public GuestUpgradeFailure Reason { get; }
    }

    public enum AddEmailFailure
    {
        /// <summary>The player is still a guest; save the progress with UpgradeGuestAsync instead.</summary>
        GuestAccount,

        /// <summary>The account already has an email address.</summary>
        AlreadyAdded,

        /// <summary>Email sign-in is turned off for this project.</summary>
        EmailSignInDisabled,

        /// <summary>The request expired before the player finished in the browser.</summary>
        Expired,

        /// <summary>The player chose Not now on the hosted page.</summary>
        Denied,

        /// <summary>The cancellation token fired; the game stopped waiting.</summary>
        Cancelled,

        /// <summary>ChangeEmailAsync or RemoveEmailAsync: the account has no email address.</summary>
        NotAdded,

        /// <summary>
        /// RemoveEmailAsync: the address is the player's only way to sign in, so it cannot be removed.
        /// </summary>
        OnlySignInMethod,
    }

    /// <summary>
    /// AddEmailAsync, ChangeEmailAsync or RemoveEmailAsync ended without changing the address. The
    /// session is unchanged except after Cancelled, when the player may still have finished in the
    /// browser.
    /// </summary>
    public sealed class Auth4AddEmailException : Auth4Exception
    {
        public Auth4AddEmailException(AddEmailFailure reason, string error, int statusCode = 0, Exception inner = null)
            : base(error, null, statusCode, inner)
        {
            Reason = reason;
        }

        public AddEmailFailure Reason { get; }
    }

    /// <summary>The refresh credential was rejected; the local session has been cleared.</summary>
    public sealed class Auth4SessionExpiredException : Auth4Exception
    {
        public Auth4SessionExpiredException(string error, string description, int statusCode)
            : base(error, description, statusCode)
        {
        }
    }
}
