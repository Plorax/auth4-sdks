// auth4.dev client for native games: device authorization, guest sessions, guest upgrades through
// upgrade intents and rotating refresh tokens. It mirrors the Unity SDK (packages/sdk-unity). Access
// tokens are opaque credentials for the game server to validate.
//
// The client is single-threaded: call it on the game thread, and it calls back on the game thread
// through the supplied ITransport and IScheduler. Callbacks for argument and state errors may run
// before the call returns.
#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "Auth4Core/Auth4Platform.h"
#include "Auth4Core/Auth4Types.h"

// UnrealBuildTool defines AUTH4CORE_API as DLLEXPORT or DLLIMPORT so the client is exported from the
// Auth4Core DLL in modular (editor) builds; those come from the engine's platform header. The
// standalone test build links statically, defines neither and includes no engine header.
#if defined(AUTH4CORE_API)
#include "HAL/Platform.h"
#else
#define AUTH4CORE_API
#endif

namespace Auth4
{
    struct ClientOptions
    {
        /// Tenant ID, for example ten_xxxxxxxxxxxxxxxx.
        std::string TenantId;

        /// Public native client ID. Native clients never hold a client secret.
        std::string ClientId;

        /// Auth API origin, for example https://auth.auth4.dev. Plain HTTP is allowed only for loopback hosts.
        std::string AuthOrigin;

        /// Scopes requested by device authorization when none are passed explicitly.
        std::string DefaultScope = "openid offline_access";

        /// Required. Sends HTTPS requests.
        std::shared_ptr<ITransport> Transport;

        /// Required. Clock and timers.
        std::shared_ptr<IScheduler> Scheduler;

        /// Secure platform storage for the refresh credential. When null, credentials are kept in
        /// memory only and the player signs in again after the game restarts.
        std::shared_ptr<ISecureStorage> SecureStorage;

        /// Opens the hosted page for UpgradeGuest. When null, UpgradeGuest reports NotSupported.
        std::shared_ptr<IBrowserLauncher> BrowserLauncher;

        /// Refresh this many seconds before the access token expires.
        double AccessTokenRefreshMarginSeconds = 30;

        /// Upper bound on token requests for one device authorization or upgrade intent.
        int MaxPollAttempts = 240;

        /// Consecutive network or 5xx failures tolerated while polling.
        int MaxConsecutiveTransientPollFailures = 5;
    };

    /// A pending device authorization. Show UserCode and VerificationUri to the player.
    class DeviceAuthorization
    {
    public:
        std::string UserCode;
        std::string VerificationUri;
        /// Verification URL with the code included, suitable for a QR code. May be empty.
        std::string VerificationUriComplete;
        double ExpiresAt = 0;
        int IntervalSeconds = 0;
        std::string Scope;

        /// True once polling finished with a session or a terminal error.
        bool IsCompleted() const { return PollState == 2; }

    private:
        friend class ClientImpl;
        std::string DeviceCode;
        int PollState = 0;
    };

    using DeviceAuthorizationPtr = std::shared_ptr<DeviceAuthorization>;

    class ClientImpl;

    class AUTH4CORE_API Client
    {
    public:
        template <typename T>
        using Callback = std::function<void(const Result<T>&)>;

        /// Validates the options. Fails with InvalidArgument instead of throwing.
        static Result<std::shared_ptr<Client>> Create(const ClientOptions& Options);

        /// Pending callbacks are dropped once the client is destroyed.
        ~Client();
        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;

        const std::string& TenantId() const;
        const std::string& ClientId() const;
        const std::string& AuthOrigin() const;

        /// True only when a secure storage adapter was supplied.
        bool IsRefreshPersistent() const;

        /// The current session, or nothing when signed out.
        std::optional<Session> CurrentSession() const;

        /// Called after sign-in, refresh, upgrade or sign-out. The argument is null when signed out.
        void SetSessionChangedListener(std::function<void(const Session*)> Listener);

        // ----- Device authorization (RFC 8628) -----

        /// Scope may be empty to use DefaultScope.
        void StartDeviceAuthorization(const std::string& Scope, Callback<DeviceAuthorizationPtr> Done);

        /// Polls until the player approves or denies, the code expires, or Cancel fires. Polling is
        /// bounded by the code's expiry and MaxPollAttempts. A cancelled poll can be resumed with the
        /// same authorization until it expires.
        void PollDeviceAuthorization(DeviceAuthorizationPtr Authorization, CancellationToken Cancel, Callback<Session> Done);

        /// Starts device authorization, reports the code, then polls until it finishes.
        void SignInWithDevice(
            std::function<void(const DeviceAuthorization&)> ShowUserCode,
            const std::string& Scope,
            CancellationToken Cancel,
            Callback<Session> Done);

        // ----- Guest sessions and upgrades -----

        /// Creates a new guest player. Fails if a session is already active so a guest is never abandoned silently.
        void SignInAsGuest(Callback<Session> Done);

        /// Upgrades the current guest by email or an enabled social provider on the hosted page (AUTH4D-67). It
        /// creates an upgrade intent, opens the page with the BrowserLauncher and polls at the server's
        /// interval until the player finishes. On success the guest's tokens are replaced in one step
        /// and the user ID is unchanged. With PreferredProvider the page offers that provider first
        /// (AUTH4D-125, AUTH4D-213); the other enabled methods stay available.
        void UpgradeGuest(
            std::optional<Provider> PreferredProvider,
            std::function<void(const UpgradeProgress&)> OnProgress,
            CancellationToken Cancel,
            Callback<UpgradeResult> Done);

        // ----- Tokens -----

        /// Returns a valid access token, refreshing first when it is about to expire. Never log it.
        void GetAccessToken(Callback<std::string> Done);

        /// Rotates the refresh token. Concurrent callers share one request, so parallel game requests
        /// never present the same refresh token twice.
        void Refresh(Callback<Session> Done);

        /// Restores a session from secure storage. The value is true only after a refresh returned a usable
        /// access token, and false when nothing usable is stored or the credential was rejected (it is then
        /// cleared). A transient failure is returned as an error and keeps the stored credential, so call
        /// again to retry. Concurrent calls share one outcome, and a sign-out during a restore wins.
        void TryRestoreSession(Callback<bool> Done);

        /// Revokes the refresh credential and clears local state. The value is false when the server
        /// could not confirm revocation; the local session is cleared either way.
        void SignOut(Callback<bool> Done);

    private:
        explicit Client(std::shared_ptr<ClientImpl> InImpl);
        std::shared_ptr<ClientImpl> Impl;
    };
}
