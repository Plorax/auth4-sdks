using System;
using System.Threading;

namespace Auth4
{
    /// <summary>
    /// A snapshot of the signed-in session. It deliberately carries no access or refresh token; use
    /// Auth4Client.GetAccessTokenAsync when calling the game server.
    /// </summary>
    public sealed class Auth4Session
    {
        internal Auth4Session(
            string userId,
            string sessionId,
            string scope,
            bool isGuest,
            DateTimeOffset accessTokenExpiresAt,
            bool canRefresh,
            bool isRefreshPersistent)
        {
            UserId = userId;
            SessionId = sessionId;
            Scope = scope;
            IsGuest = isGuest;
            AccessTokenExpiresAt = accessTokenExpiresAt;
            CanRefresh = canRefresh;
            IsRefreshPersistent = isRefreshPersistent;
        }

        /// <summary>The tenant user ID when the API returned it (guest and upgrade flows); otherwise null.</summary>
        public string UserId { get; }

        public string SessionId { get; }

        public string Scope { get; }

        public bool IsGuest { get; }

        public DateTimeOffset AccessTokenExpiresAt { get; }

        public bool CanRefresh { get; }

        /// <summary>True only when a secure storage adapter holds the refresh credential.</summary>
        public bool IsRefreshPersistent { get; }
    }

    /// <summary>A pending device authorization. Show UserCode and VerificationUri to the player.</summary>
    public sealed class DeviceAuthorization
    {
        private int _state;

        internal DeviceAuthorization(
            string deviceCode,
            string userCode,
            Uri verificationUri,
            Uri verificationUriComplete,
            DateTimeOffset expiresAt,
            int intervalSeconds,
            string scope)
        {
            DeviceCode = deviceCode;
            UserCode = userCode;
            VerificationUri = verificationUri;
            VerificationUriComplete = verificationUriComplete;
            ExpiresAt = expiresAt;
            IntervalSeconds = intervalSeconds;
            Scope = scope;
        }

        internal string DeviceCode { get; }

        public string UserCode { get; }

        public Uri VerificationUri { get; }

        /// <summary>Verification URL with the code included, suitable for a QR code. May be null.</summary>
        public Uri VerificationUriComplete { get; }

        public DateTimeOffset ExpiresAt { get; }

        public int IntervalSeconds { get; }

        public string Scope { get; }

        /// <summary>True once polling finished with a session or a terminal error.</summary>
        public bool IsCompleted => Volatile.Read(ref _state) == 2;

        internal bool TryBeginPolling()
        {
            return Interlocked.CompareExchange(ref _state, 1, 0) == 0;
        }

        internal void EndPolling(bool completed)
        {
            Volatile.Write(ref _state, completed ? 2 : 0);
        }
    }

    /// <summary>
    /// A linking intent for upgrading the current guest. It holds the flow cookie in memory only and
    /// is bound to the guest session that created it.
    /// </summary>
    public sealed class GuestUpgradeFlow
    {
        internal GuestUpgradeFlow(
            string browserFlowId,
            string flowCookie,
            string guestUserId,
            string sessionId,
            DateTimeOffset expiresAt)
        {
            BrowserFlowId = browserFlowId;
            FlowCookie = flowCookie;
            GuestUserId = guestUserId;
            SessionId = sessionId;
            ExpiresAt = expiresAt;
        }

        public string BrowserFlowId { get; }

        internal string FlowCookie { get; }

        public string GuestUserId { get; }

        internal string SessionId { get; }

        /// <summary>When the linking intent expires; begin a new upgrade after this time.</summary>
        public DateTimeOffset ExpiresAt { get; }
    }

    /// <summary>Third-party sign-in providers the hosted pages offer for linking a guest.</summary>
    public enum Auth4Provider
    {
        Discord,
        Steam,

        /// <summary>Epic Games accounts (AUTH4D-147).</summary>
        Epic,

        /// <summary>Google accounts (AUTH4D-213).</summary>
        Google,

        /// <summary>Apple accounts (AUTH4D-213).</summary>
        Apple,

        /// <summary>Microsoft accounts (AUTH4D-213).</summary>
        Microsoft,
    }

    public enum GuestUpgradeStage
    {
        /// <summary>The upgrade intent exists and the browser is about to open.</summary>
        OpeningBrowser,

        /// <summary>The browser is open; the game is polling while the player links an account.</summary>
        WaitingForPlayer,

        /// <summary>The upgraded session replaced the guest session.</summary>
        Completed,
    }

    /// <summary>Reported by UpgradeGuestAsync. Carries no secret: the page URL holds only a public handle.</summary>
    public sealed class GuestUpgradeProgress
    {
        internal GuestUpgradeProgress(
            GuestUpgradeStage stage,
            Uri upgradeUri,
            DateTimeOffset expiresAt,
            int intervalSeconds,
            int pollAttempts)
        {
            Stage = stage;
            UpgradeUri = upgradeUri;
            ExpiresAt = expiresAt;
            IntervalSeconds = intervalSeconds;
            PollAttempts = pollAttempts;
        }

        public GuestUpgradeStage Stage { get; }

        /// <summary>The hosted page, so the game can offer "Open again" if the player closed it.</summary>
        public Uri UpgradeUri { get; }

        public DateTimeOffset ExpiresAt { get; }

        /// <summary>Seconds until the next poll, as set by the server.</summary>
        public int IntervalSeconds { get; }

        public int PollAttempts { get; }
    }

    public sealed class LinkedIdentity
    {
        internal LinkedIdentity(string identityId, string provider)
        {
            IdentityId = identityId;
            Provider = provider;
        }

        public string IdentityId { get; }

        /// <summary>email, discord or steam.</summary>
        public string Provider { get; }
    }

    /// <summary>Returned by AddEmailAsync: the refreshed session and the address the player verified.</summary>
    public sealed class AddEmailResult
    {
        internal AddEmailResult(Auth4Session session, string email, LinkedIdentity identity)
        {
            Session = session;
            Email = email;
            Identity = identity;
        }

        public Auth4Session Session { get; }

        public string Email { get; }

        public LinkedIdentity Identity { get; }
    }

    public sealed class GuestUpgradeResult
    {
        internal GuestUpgradeResult(Auth4Session session, LinkedIdentity identity)
        {
            Session = session;
            Identity = identity;
        }

        public Auth4Session Session { get; }

        public LinkedIdentity Identity { get; }
    }
}
