// auth4.dev protocol core: value types. Plain C++17 with no engine headers and no exceptions, so the
// same code builds inside Unreal Engine (Auth4Core module) and in the standalone test suite.
#pragma once

#include <string>
#include <utility>

namespace Auth4
{
    enum class ErrorKind
    {
        None,
        /// An OAuth error returned by the API; Code holds the error string.
        Protocol,
        /// The API could not be reached. Transient.
        Network,
        /// The API answered with a malformed or unexpected body.
        InvalidResponse,
        /// A caller argument or a client option is invalid.
        InvalidArgument,
        /// The call does not fit the current session, for example signing in while signed in.
        InvalidState,
        /// No session is active, or the access token expired and cannot be refreshed.
        LoginRequired,
        /// The refresh credential was rejected; the local session has been cleared.
        SessionExpired,
        /// The player denied the device on the verification page.
        DeviceDenied,
        /// The device code expired before the player approved it.
        DeviceExpired,
        /// The email, Discord or Steam account already belongs to another player. Nothing was merged.
        UpgradeConflict,
        /// The upgrade intent expired before the player finished in the browser.
        UpgradeExpired,
        /// The player chose Not now on the hosted page.
        UpgradeDenied,
        /// The cancellation token fired; the game stopped waiting.
        Cancelled,
        /// No browser launcher is available on this platform.
        NotSupported,
    };

    /// A failure. Messages never contain token values. Description comes from the server and is
    /// for logs only; never show it to players.
    struct Error
    {
        ErrorKind Kind = ErrorKind::None;
        /// OAuth error code, or a client code such as network_error or login_required.
        std::string Code;
        std::string Description;
        /// HTTP status, or 0 when no response was received.
        int StatusCode = 0;

        /// True for failures that may succeed if retried later.
        bool IsTransient() const
        {
            return Kind == ErrorKind::Network || Code == "network_error" || Code == "temporarily_unavailable" ||
                   Code == "server_error" || StatusCode >= 500;
        }
    };

    /// A value or an error. The core never throws.
    template <typename T>
    class Result
    {
    public:
        static Result Success(T InValue)
        {
            Result Out;
            Out.bOk = true;
            Out.ValueField = std::move(InValue);
            return Out;
        }

        static Result Failure(Error InError)
        {
            Result Out;
            Out.ErrorField = std::move(InError);
            return Out;
        }

        bool Ok() const { return bOk; }
        const T& Value() const { return ValueField; }
        const Error& GetError() const { return ErrorField; }

    private:
        bool bOk = false;
        T ValueField{};
        Error ErrorField;
    };

    /// A snapshot of the signed-in session. It deliberately carries no access or refresh token; use
    /// Client::GetAccessToken when calling the game server.
    struct Session
    {
        /// The tenant user ID when the API returned it (guest and upgrade flows); otherwise empty.
        std::string UserId;
        std::string SessionId;
        std::string Scope;
        bool bIsGuest = false;
        /// Unix time in seconds.
        double AccessTokenExpiresAt = 0;
        bool bCanRefresh = false;
        /// True only when a secure storage adapter holds the refresh credential.
        bool bIsRefreshPersistent = false;
    };

    /// Third-party sign-in providers the hosted pages offer for linking a guest.
    enum class Provider
    {
        Discord,
        Steam,
        Epic,
        Google,
        Apple,
        Microsoft,
    };

    enum class UpgradeStage
    {
        /// The upgrade intent exists and the browser is about to open.
        OpeningBrowser,
        /// The browser is open; the game is polling while the player links an account.
        WaitingForPlayer,
        /// The upgraded session replaced the guest session.
        Completed,
    };

    /// Reported by UpgradeGuest. Carries no secret: the page URL holds only a public handle.
    struct UpgradeProgress
    {
        UpgradeStage Stage = UpgradeStage::OpeningBrowser;
        /// The hosted page, so the game can offer "Open again" if the player closed it.
        std::string UpgradeUri;
        double ExpiresAt = 0;
        /// Seconds until the next poll, as set by the server.
        int IntervalSeconds = 0;
        int PollAttempts = 0;
    };

    struct LinkedIdentity
    {
        std::string IdentityId;
        /// The linked provider name, such as email, discord, steam, epic, google, apple or microsoft.
        std::string Provider;
    };

    struct UpgradeResult
    {
        Session NewSession;
        LinkedIdentity Identity;
    };
}
