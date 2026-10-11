using System;

namespace Auth4
{
    public sealed class Auth4ClientOptions
    {
        /// <summary>Tenant ID, for example ten_xxxxxxxxxxxxxxxx.</summary>
        public string TenantId { get; set; }

        /// <summary>Public native client ID. Native clients never hold a client secret.</summary>
        public string ClientId { get; set; }

        /// <summary>Auth API origin, for example https://auth.auth4.dev. Plain HTTP is allowed only for loopback hosts.</summary>
        public string AuthOrigin { get; set; }

        /// <summary>Scopes requested by device authorization when none are passed explicitly.</summary>
        public string DefaultScope { get; set; } = "openid offline_access";

        /// <summary>HTTP transport. Defaults to HttpClientTransport.</summary>
        public IAuth4HttpTransport Transport { get; set; }

        /// <summary>Clock and delay source. Defaults to the system clock.</summary>
        public IAuth4Clock Clock { get; set; }

        /// <summary>
        /// Secure platform storage for the refresh credential. When null, credentials are kept in
        /// memory only and the player signs in again after the game restarts.
        /// </summary>
        public ISecureStorageAdapter SecureStorage { get; set; }

        /// <summary>
        /// Opens the hosted page for UpgradeGuestAsync. In Unity use UnityBrowserLauncher. When null,
        /// UpgradeGuestAsync is unavailable; the in-game email upgrade still works.
        /// </summary>
        public IAuth4BrowserLauncher BrowserLauncher { get; set; }

        /// <summary>
        /// Opens the hosted page in a browser popup for games that run in a browser. In Unity use
        /// WebGLUpgradeWindow. Where it is supported, UpgradeGuestAsync uses it instead of the
        /// BrowserLauncher; set both and each platform picks the one that applies.
        /// </summary>
        public IAuth4UpgradeWindow UpgradeWindow { get; set; }

        /// <summary>Refresh this long before the access token expires.</summary>
        public TimeSpan AccessTokenRefreshMargin { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>Upper bound on token requests for one device authorization.</summary>
        public int MaxDevicePollAttempts { get; set; } = 240;

        /// <summary>Consecutive network or 5xx failures tolerated while polling.</summary>
        public int MaxConsecutiveTransientPollFailures { get; set; } = 5;
    }
}
