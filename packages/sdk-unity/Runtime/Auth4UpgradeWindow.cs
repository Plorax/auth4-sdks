using System;

namespace Auth4
{
    /// <summary>
    /// Opens the hosted guest-upgrade page in a browser popup and relays its window protocol
    /// (docs/api-spec/auth4d-23.md) for games that themselves run in a browser. In Unity WebGL builds
    /// use Auth4.Unity.WebGLUpgradeWindow. Implementations accept messages only from the popup they
    /// opened, on the exact auth origin, and post the guest access token only to that origin. Tokens
    /// never enter a URL or browser storage.
    /// </summary>
    public interface IAuth4UpgradeWindow
    {
        /// <summary>True only where the game runs in a browser page that can open the popup.</summary>
        bool IsSupported { get; }

        /// <summary>
        /// Opens <paramref name="upgradeUri"/> in a popup, or waits for the player's next pointer-up
        /// or touch-end if the browser no longer counts the current input as a user gesture. Messages
        /// from the window are reported on <paramref name="onMessage"/>.
        /// </summary>
        IAuth4UpgradeWindowHandle Open(Uri upgradeUri, string authOrigin, Action<Auth4UpgradeWindowMessage> onMessage);
    }

    /// <summary>One open (or pending) upgrade window. Dispose stops listening but leaves the page open.</summary>
    public interface IAuth4UpgradeWindowHandle : IDisposable
    {
        /// <summary>Posts the guest access token to the window, targeting the auth origin only.</summary>
        void SendAccessToken(string accessToken);

        /// <summary>Closes the window, or stops waiting for the gesture that would have opened it.</summary>
        void Close();
    }

    public enum Auth4UpgradeWindowEvent
    {
        /// <summary>The popup opened; the player is in the hosted page.</summary>
        Opened,

        /// <summary>The browser blocked the popup.</summary>
        Blocked,

        /// <summary>The page asks for the guest access token. Data is {"tenant_id","client_id"} as JSON.</summary>
        Ready,

        /// <summary>The upgrade finished. Data is the upgrade result (user_id, identity, token set) as JSON.</summary>
        Complete,

        /// <summary>The page reported an error. Data is the error code, such as identity_in_use.</summary>
        Failed,

        /// <summary>The player chose Not now.</summary>
        Cancelled,

        /// <summary>The player closed the window.</summary>
        Closed,
    }

    public sealed class Auth4UpgradeWindowMessage
    {
        public Auth4UpgradeWindowMessage(Auth4UpgradeWindowEvent kind, string data = null)
        {
            Kind = kind;
            Data = data;
        }

        public Auth4UpgradeWindowEvent Kind { get; }

        /// <summary>Event payload, or null. A Complete payload holds tokens; never log it.</summary>
        public string Data { get; }

        /// <summary>Hides the payload, which may hold tokens.</summary>
        public override string ToString()
        {
            return "Auth4UpgradeWindowMessage(" + Kind + ")";
        }
    }
}
