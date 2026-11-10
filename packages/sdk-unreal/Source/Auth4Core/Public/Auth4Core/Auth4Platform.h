// auth4.dev protocol core: the platform services a game supplies. The Unreal layer implements them
// with FHttpModule, FTSTicker and FPlatformProcess::LaunchURL; the tests use a local mock server.
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Auth4
{
    struct HttpRequest
    {
        std::string Method = "POST";
        std::string Url;
        std::vector<std::pair<std::string, std::string>> Headers;
        std::string Body;
    };

    struct HttpResponse
    {
        /// True when no HTTP response was received (DNS, TLS, connection or timeout failure).
        bool bNetworkError = false;
        int StatusCode = 0;
        std::string Body;
    };

    /// Sends one HTTPS request. Done must be called exactly once, on the game thread, and never
    /// before Send returns. Implementations must not log request or response bodies: they carry tokens.
    class ITransport
    {
    public:
        virtual ~ITransport() = default;
        virtual void Send(const HttpRequest& Request, std::function<void(HttpResponse)> Done) = 0;
    };

    /// Clock and timer. Callbacks run on the game thread and never before After returns.
    class IScheduler
    {
    public:
        virtual ~IScheduler() = default;
        /// Unix time in seconds.
        virtual double Now() = 0;
        virtual void After(double Seconds, std::function<void()> Callback) = 0;
    };

    /// Contract for platform secure storage, such as the iOS Keychain, Android Keystore-backed
    /// encrypted storage, Windows DPAPI or a console vendor's protected save API. Implementations must
    /// encrypt at rest with an OS-protected key and must never write to SaveGame slots, config files,
    /// plain files or logs. Refresh tokens are persisted only when an adapter is supplied explicitly.
    /// Callbacks run on the game thread.
    class ISecureStorage
    {
    public:
        virtual ~ISecureStorage() = default;
        /// bFound is false when the key is absent. bOk is false when storage is unavailable.
        virtual void Read(const std::string& Key, std::function<void(bool bOk, bool bFound, std::string Value)> Done) = 0;
        virtual void Write(const std::string& Key, const std::string& Value, std::function<void(bool bOk)> Done) = 0;
        virtual void Delete(const std::string& Key, std::function<void(bool bOk)> Done) = 0;
    };

    /// Opens the hosted upgrade page in the system browser.
    class IBrowserLauncher
    {
    public:
        virtual ~IBrowserLauncher() = default;
        virtual bool IsSupported() const = 0;
        virtual void Open(const std::string& Url) = 0;
    };

    namespace Detail
    {
        struct CancellationState
        {
            bool bCancelled = false;
            int NextId = 1;
            std::map<int, std::function<void()>> Callbacks;
        };
    }

    /// Observes a CancellationSource. A default token can never be cancelled.
    class CancellationToken
    {
    public:
        CancellationToken() = default;

        bool IsCancelled() const { return State && State->bCancelled; }

        /// Runs Callback once when the source is cancelled. Returns 0 if it can never run.
        int Register(std::function<void()> Callback) const
        {
            if (!State || State->bCancelled)
            {
                return 0;
            }

            const int Id = State->NextId++;
            State->Callbacks[Id] = std::move(Callback);
            return Id;
        }

        void Unregister(int Id) const
        {
            if (State && Id != 0)
            {
                State->Callbacks.erase(Id);
            }
        }

    private:
        friend class CancellationSource;
        explicit CancellationToken(std::shared_ptr<Detail::CancellationState> InState) : State(std::move(InState)) {}

        std::shared_ptr<Detail::CancellationState> State;
    };

    /// Stops a device sign-in or guest upgrade from waiting. Use one source per operation.
    class CancellationSource
    {
    public:
        CancellationSource() : State(std::make_shared<Detail::CancellationState>()) {}

        CancellationToken Token() const { return CancellationToken(State); }

        void Cancel()
        {
            if (State->bCancelled)
            {
                return;
            }

            State->bCancelled = true;
            auto Callbacks = std::move(State->Callbacks);
            State->Callbacks.clear();
            for (auto& Entry : Callbacks)
            {
                Entry.second();
            }
        }

    private:
        std::shared_ptr<Detail::CancellationState> State;
    };
}
