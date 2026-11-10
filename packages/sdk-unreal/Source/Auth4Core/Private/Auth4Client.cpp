#include "Auth4Core/Auth4Client.h"

#include <algorithm>
#include <cmath>
#include <deque>
#include <random>
#include <vector>

#include "Auth4Json.h"
#include "Auth4Url.h"

namespace Auth4
{
    namespace
    {
        const char* const DeviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code";
        constexpr int MinimumPollIntervalSeconds = 5;
        constexpr int SlowDownIncrementSeconds = 5;
        constexpr int MaxTransientBackoffSeconds = 60;
        constexpr int MaxPollIntervalSeconds = 3600;
        constexpr double MaxTokenLifetimeSeconds = 86400;

        using FieldList = std::vector<std::pair<std::string, std::string>>;

        bool IsAlnum(char Character)
        {
            return (Character >= 'A' && Character <= 'Z') || (Character >= 'a' && Character <= 'z') ||
                   (Character >= '0' && Character <= '9');
        }

        /// prefix followed by MinLength..MaxLength characters; bUrlSafe also allows - and _.
        bool MatchesId(const std::string& Value, const char* Prefix, size_t MinLength, size_t MaxLength, bool bUrlSafe)
        {
            const std::string Head(Prefix);
            if (Value.size() < Head.size() || Value.compare(0, Head.size(), Head) != 0)
            {
                return false;
            }

            const size_t Length = Value.size() - Head.size();
            if (Length < MinLength || Length > MaxLength)
            {
                return false;
            }

            for (size_t Index = Head.size(); Index < Value.size(); ++Index)
            {
                const char Character = Value[Index];
                if (!IsAlnum(Character) && !(bUrlSafe && (Character == '-' || Character == '_')))
                {
                    return false;
                }
            }

            return true;
        }

        Error MakeError(ErrorKind Kind, std::string Code, std::string Description = std::string(), int StatusCode = 0)
        {
            Error Out;
            Out.Kind = Kind;
            Out.Code = std::move(Code);
            Out.Description = std::move(Description);
            Out.StatusCode = StatusCode;
            return Out;
        }

        Error InvalidResponse(int StatusCode, const char* Description)
        {
            return MakeError(ErrorKind::InvalidResponse, "invalid_response", Description, StatusCode);
        }

        Error ErrorFrom(const HttpResponse& Response, const Json::Object* Body)
        {
            auto Code = Json::GetString(Body, "error");
            if (!Code || Code->empty())
            {
                Code = Response.StatusCode >= 500 ? "server_error" : "invalid_response";
            }

            return MakeError(
                ErrorKind::Protocol,
                *Code,
                Json::GetString(Body, "error_description").value_or(std::string()),
                Response.StatusCode);
        }

        int PollInterval(double Seconds)
        {
            return std::min(MaxPollIntervalSeconds, std::max(MinimumPollIntervalSeconds, static_cast<int>(std::ceil(Seconds))));
        }

        int Backoff(int Interval)
        {
            return std::max(Interval, std::min(Interval * 2, MaxTransientBackoffSeconds));
        }

        std::optional<std::string> NormalizeScope(const std::string& Scope)
        {
            std::vector<std::string> Values;
            std::string Current;
            for (size_t Index = 0; Index <= Scope.size(); ++Index)
            {
                const char Character = Index < Scope.size() ? Scope[Index] : ' ';
                if (Character == ' ' || Character == '\t' || Character == '\n' || Character == '\r')
                {
                    if (!Current.empty() && std::find(Values.begin(), Values.end(), Current) == Values.end())
                    {
                        Values.push_back(Current);
                    }

                    Current.clear();
                }
                else
                {
                    Current.push_back(Character);
                }
            }

            if (std::find(Values.begin(), Values.end(), "openid") == Values.end())
            {
                return std::nullopt;
            }

            std::string Out;
            for (const auto& Value : Values)
            {
                Out += (Out.empty() ? "" : " ") + Value;
            }

            return Out;
        }

        /// The hosted pages' name for a provider.
        const char* ProviderName(Provider Value)
        {
            switch (Value)
            {
            case Provider::Discord: return "discord";
            case Provider::Steam: return "steam";
            case Provider::Epic: return "epic";
            case Provider::Google: return "google";
            case Provider::Apple: return "apple";
            case Provider::Microsoft: return "microsoft";
            }
            return "";
        }

        bool IsSuccess(int StatusCode)
        {
            return StatusCode >= 200 && StatusCode <= 299;
        }
    }

    struct TokenState
    {
        std::string AccessToken;
        double AccessTokenExpiresAt = 0;
        std::string RefreshToken;
        std::string IdToken;
        std::string Scope;
        std::string SessionId;
        std::string UserId;
        bool bIsGuest = false;

        Session ToSession(bool bPersistent) const
        {
            Session Out;
            Out.UserId = UserId;
            Out.SessionId = SessionId;
            Out.Scope = Scope;
            Out.bIsGuest = bIsGuest;
            Out.AccessTokenExpiresAt = AccessTokenExpiresAt;
            Out.bCanRefresh = !RefreshToken.empty();
            Out.bIsRefreshPersistent = bPersistent && !RefreshToken.empty();
            return Out;
        }
    };

    class ClientImpl : public std::enable_shared_from_this<ClientImpl>
    {
    public:
        template <typename T>
        using Callback = Client::Callback<T>;

        std::string TenantId;
        std::string ClientId;
        std::string AuthOrigin;
        std::string DefaultScope;
        std::shared_ptr<ITransport> Transport;
        std::shared_ptr<IScheduler> Scheduler;
        std::shared_ptr<ISecureStorage> Storage;
        std::shared_ptr<IBrowserLauncher> Launcher;
        std::string StorageKey;
        double RefreshMargin = 30;
        int MaxPollAttempts = 240;
        int MaxTransientFailures = 5;

        bool bDisposed = false;
        std::optional<TokenState> State;
        /// Incremented on every sign-out, so late results from an earlier session are discarded.
        unsigned SignOutGeneration = 0;
        bool bRefreshing = false;
        std::vector<Callback<Session>> RefreshWaiters;
        bool bRestoring = false;
        std::vector<Callback<bool>> RestoreWaiters;
        bool bUpgradeInFlight = false;
        std::function<void(const Session*)> SessionListener;

        /// Storage operations run one at a time and in order, so the stored and live tokens agree.
        std::deque<std::function<void(std::function<void()>)>> StorageJobs;
        bool bStorageBusy = false;

        bool IsPersistent() const { return Storage != nullptr; }

        // ----- Device authorization -----

        void StartDeviceAuthorization(const std::string& Scope, Callback<DeviceAuthorizationPtr> Done)
        {
            if (State)
            {
                Done(Result<DeviceAuthorizationPtr>::Failure(AlreadySignedIn()));
                return;
            }

            const auto RequestedScope = Scope.empty() ? std::optional<std::string>(DefaultScope) : NormalizeScope(Scope);
            if (!RequestedScope)
            {
                Done(Result<DeviceAuthorizationPtr>::Failure(
                    MakeError(ErrorKind::InvalidArgument, "invalid_scope", "The scope must include openid.")));
                return;
            }

            auto Self = shared_from_this();
            Send(
                FormRequest(Endpoint("/device/authorization?tenant_id=" + Url::Escape(TenantId)), {{"client_id", ClientId}, {"scope", *RequestedScope}}),
                [Self, RequestedScope, Done](const Result<HttpResponse>& Sent)
                {
                    if (!Sent.Ok())
                    {
                        Done(Result<DeviceAuthorizationPtr>::Failure(Sent.GetError()));
                        return;
                    }

                    const HttpResponse& Response = Sent.Value();
                    const auto Body = Json::ParseObject(Response.Body);
                    if (Response.StatusCode != 200)
                    {
                        Done(Result<DeviceAuthorizationPtr>::Failure(ErrorFrom(Response, Body.get())));
                        return;
                    }

                    const auto DeviceCode = Json::GetString(Body.get(), "device_code");
                    const auto UserCode = Json::GetString(Body.get(), "user_code");
                    const auto VerificationUri = Json::GetString(Body.get(), "verification_uri");
                    const auto Complete = Json::GetString(Body.get(), "verification_uri_complete");
                    const auto ExpiresIn = Json::GetNumber(Body.get(), "expires_in");
                    const double Interval = Json::GetNumber(Body.get(), "interval").value_or(MinimumPollIntervalSeconds);
                    if (!DeviceCode || DeviceCode->empty() || !UserCode || UserCode->empty() || !VerificationUri ||
                        !Url::IsSameOrigin(*VerificationUri, Self->AuthOrigin) ||
                        (Complete && !Url::IsSameOrigin(*Complete, Self->AuthOrigin)) || !ExpiresIn || *ExpiresIn <= 0 ||
                        *ExpiresIn > MaxTokenLifetimeSeconds || Interval > MaxPollIntervalSeconds)
                    {
                        Done(Result<DeviceAuthorizationPtr>::Failure(
                            InvalidResponse(Response.StatusCode, "The device authorization response is malformed.")));
                        return;
                    }

                    auto Authorization = std::make_shared<DeviceAuthorization>();
                    Authorization->DeviceCode = *DeviceCode;
                    Authorization->UserCode = *UserCode;
                    Authorization->VerificationUri = *VerificationUri;
                    Authorization->VerificationUriComplete = Complete.value_or(std::string());
                    Authorization->ExpiresAt = Self->Scheduler->Now() + *ExpiresIn;
                    Authorization->IntervalSeconds = std::max(MinimumPollIntervalSeconds, static_cast<int>(std::ceil(Interval)));
                    Authorization->Scope = *RequestedScope;
                    Done(Result<DeviceAuthorizationPtr>::Success(Authorization));
                });
        }

        struct DevicePoll
        {
            DeviceAuthorizationPtr Authorization;
            CancellationToken Cancel;
            Callback<Session> Done;
            int Interval = MinimumPollIntervalSeconds;
            int TransientFailures = 0;
            int Attempt = 0;
        };

        void PollDeviceAuthorization(DeviceAuthorizationPtr Authorization, CancellationToken Cancel, Callback<Session> Done)
        {
            if (!Authorization)
            {
                Done(Result<Session>::Failure(MakeError(ErrorKind::InvalidArgument, "invalid_argument", "An authorization is required.")));
                return;
            }

            if (Authorization->PollState == 2)
            {
                Done(Result<Session>::Failure(
                    MakeError(ErrorKind::InvalidState, "invalid_state", "This device authorization has already finished.")));
                return;
            }

            if (Authorization->PollState == 1)
            {
                Done(Result<Session>::Failure(
                    MakeError(ErrorKind::InvalidState, "invalid_state", "This device authorization is already being polled.")));
                return;
            }

            Authorization->PollState = 1;
            auto Poll = std::make_shared<DevicePoll>();
            Poll->Authorization = Authorization;
            Poll->Cancel = Cancel;
            Poll->Interval = Authorization->IntervalSeconds;
            Poll->Done = std::move(Done);
            DevicePollStep(Poll);
        }

        void FinishDevicePoll(const std::shared_ptr<DevicePoll>& Poll, bool bCompleted, const Result<Session>& Outcome)
        {
            Poll->Authorization->PollState = bCompleted ? 2 : 0;
            Poll->Done(Outcome);
        }

        void DevicePollStep(std::shared_ptr<DevicePoll> Poll)
        {
            ++Poll->Attempt;
            if (Poll->Attempt > MaxPollAttempts || Scheduler->Now() >= Poll->Authorization->ExpiresAt)
            {
                FinishDevicePoll(Poll, true, Result<Session>::Failure(MakeError(ErrorKind::DeviceExpired, "expired_token")));
                return;
            }

            auto Self = shared_from_this();
            Delay(Poll->Interval, Poll->Cancel, [Self, Poll](bool bCancelled)
            {
                if (bCancelled)
                {
                    Self->FinishDevicePoll(Poll, false, Result<Session>::Failure(MakeError(ErrorKind::Cancelled, "cancelled")));
                    return;
                }

                if (Self->Scheduler->Now() >= Poll->Authorization->ExpiresAt)
                {
                    Self->FinishDevicePoll(Poll, true, Result<Session>::Failure(MakeError(ErrorKind::DeviceExpired, "expired_token")));
                    return;
                }

                Self->Send(
                    Self->FormRequest(
                        Self->TokenEndpoint(),
                        {{"grant_type", DeviceCodeGrant}, {"client_id", Self->ClientId}, {"device_code", Poll->Authorization->DeviceCode}}),
                    [Self, Poll](const Result<HttpResponse>& Sent) { Self->OnDevicePollResponse(Poll, Sent); });
            });
        }

        void OnDevicePollResponse(const std::shared_ptr<DevicePoll>& Poll, const Result<HttpResponse>& Sent)
        {
            if (!Sent.Ok())
            {
                if (Sent.GetError().IsTransient() && Poll->TransientFailures < MaxTransientFailures)
                {
                    ++Poll->TransientFailures;
                    Poll->Interval = Backoff(Poll->Interval);
                    DevicePollStep(Poll);
                    return;
                }

                FinishDevicePoll(Poll, false, Result<Session>::Failure(Sent.GetError()));
                return;
            }

            const HttpResponse& Response = Sent.Value();
            const auto Body = Json::ParseObject(Response.Body);
            if (Response.StatusCode == 200)
            {
                auto Tokens = ReadTokens(Response, Body.get());
                if (!Tokens.Ok())
                {
                    FinishDevicePoll(Poll, true, Result<Session>::Failure(Tokens.GetError()));
                    return;
                }

                auto Self = shared_from_this();
                AdoptNewSession(Tokens.Value(), [Self, Poll](const Result<Session>& Adopted)
                {
                    Self->FinishDevicePoll(Poll, true, Adopted);
                });
                return;
            }

            const Error Failure = ErrorFrom(Response, Body.get());
            if (Failure.Code == "authorization_pending")
            {
                Poll->TransientFailures = 0;
                DevicePollStep(Poll);
                return;
            }

            if (Failure.Code == "slow_down")
            {
                Poll->TransientFailures = 0;
                Poll->Interval += SlowDownIncrementSeconds;
                DevicePollStep(Poll);
                return;
            }

            if (Failure.Code == "access_denied")
            {
                FinishDevicePoll(Poll, true, Result<Session>::Failure(
                    MakeError(ErrorKind::DeviceDenied, Failure.Code, std::string(), Response.StatusCode)));
                return;
            }

            if (Failure.Code == "expired_token")
            {
                FinishDevicePoll(Poll, true, Result<Session>::Failure(
                    MakeError(ErrorKind::DeviceExpired, Failure.Code, std::string(), Response.StatusCode)));
                return;
            }

            if (Failure.IsTransient() && Poll->TransientFailures < MaxTransientFailures)
            {
                ++Poll->TransientFailures;
                Poll->Interval = Backoff(Poll->Interval);
                DevicePollStep(Poll);
                return;
            }

            FinishDevicePoll(Poll, !Failure.IsTransient(), Result<Session>::Failure(Failure));
        }

        // ----- Guests -----

        void SignInAsGuest(Callback<Session> Done)
        {
            if (State)
            {
                Done(Result<Session>::Failure(AlreadySignedIn()));
                return;
            }

            auto Self = shared_from_this();
            Send(
                JsonRequest(GuestEndpoint(""), {{"client_id", ClientId}, {"browser_flow_id", NewBrowserFlowId()}}),
                [Self, Done](const Result<HttpResponse>& Sent)
                {
                    if (!Sent.Ok())
                    {
                        Done(Result<Session>::Failure(Sent.GetError()));
                        return;
                    }

                    const HttpResponse& Response = Sent.Value();
                    const auto Body = Json::ParseObject(Response.Body);
                    if (!IsSuccess(Response.StatusCode))
                    {
                        Done(Result<Session>::Failure(ErrorFrom(Response, Body.get())));
                        return;
                    }

                    const auto UserId = Json::GetString(Body.get(), "user_id");
                    if (!UserId || UserId->empty())
                    {
                        Done(Result<Session>::Failure(InvalidResponse(Response.StatusCode, "The guest response has no user ID.")));
                        return;
                    }

                    auto Tokens = Self->ReadTokens(Response, Body.get());
                    if (!Tokens.Ok())
                    {
                        Done(Result<Session>::Failure(Tokens.GetError()));
                        return;
                    }

                    TokenState Next = Tokens.Value();
                    Next.UserId = *UserId;
                    Next.bIsGuest = true;
                    Self->AdoptNewSession(Next, Done);
                });
        }

        struct UpgradePoll
        {
            std::string GuestUserId;
            unsigned Generation = 0;
            std::string Intent;
            std::string PollSecret;
            std::string UpgradeUri;
            double ExpiresAt = 0;
            int Interval = MinimumPollIntervalSeconds;
            int TransientFailures = 0;
            int Attempt = 0;
            CancellationToken Cancel;
            std::function<void(const UpgradeProgress&)> OnProgress;
            Callback<UpgradeResult> Done;
        };

        void UpgradeGuest(
            std::optional<Provider> PreferredProvider,
            std::function<void(const UpgradeProgress&)> OnProgress,
            CancellationToken Cancel,
            Callback<UpgradeResult> Done)
        {
            if (!Launcher || !Launcher->IsSupported())
            {
                Done(Result<UpgradeResult>::Failure(MakeError(
                    ErrorKind::NotSupported, "not_supported", "UpgradeGuest needs a browser launcher on this platform.")));
                return;
            }

            if (bUpgradeInFlight)
            {
                Done(Result<UpgradeResult>::Failure(
                    MakeError(ErrorKind::InvalidState, "invalid_state", "A guest upgrade is already in progress.")));
                return;
            }

            bUpgradeInFlight = true;
            auto Self = shared_from_this();
            auto Poll = std::make_shared<UpgradePoll>();
            Poll->Cancel = Cancel;
            Poll->OnProgress = std::move(OnProgress);
            Poll->Done = [Self, Done](const Result<UpgradeResult>& Outcome)
            {
                Self->bUpgradeInFlight = false;
                Done(Outcome);
            };

            GetAccessToken([Self, Poll, PreferredProvider](const Result<std::string>& Token)
            {
                if (!Token.Ok())
                {
                    Poll->Done(Result<UpgradeResult>::Failure(Token.GetError()));
                    return;
                }

                if (Poll->Cancel.IsCancelled())
                {
                    Poll->Done(Result<UpgradeResult>::Failure(MakeError(ErrorKind::Cancelled, "cancelled")));
                    return;
                }

                if (!Self->State || !Self->State->bIsGuest || Self->State->UserId.empty())
                {
                    Poll->Done(Result<UpgradeResult>::Failure(
                        MakeError(ErrorKind::InvalidState, "invalid_state", "Only an active guest session can be upgraded.")));
                    return;
                }

                Poll->GuestUserId = Self->State->UserId;
                Poll->Generation = Self->SignOutGeneration;
                HttpRequest Request = Self->JsonRequest(Self->GuestEndpoint("/upgrade-intent"), {{"client_id", Self->ClientId}});
                Request.Headers.emplace_back("Authorization", "Bearer " + Token.Value());
                Self->Send(Request, [Self, Poll, PreferredProvider](const Result<HttpResponse>& Sent)
                {
                    Self->OnUpgradeIntentCreated(Poll, PreferredProvider, Sent);
                });
            });
        }

        void ReportProgress(const std::shared_ptr<UpgradePoll>& Poll, UpgradeStage Stage, int Attempts)
        {
            if (!Poll->OnProgress)
            {
                return;
            }

            UpgradeProgress Progress;
            Progress.Stage = Stage;
            Progress.UpgradeUri = Poll->UpgradeUri;
            Progress.ExpiresAt = Poll->ExpiresAt;
            Progress.IntervalSeconds = Poll->Interval;
            Progress.PollAttempts = Attempts;
            Poll->OnProgress(Progress);
        }

        void OnUpgradeIntentCreated(
            const std::shared_ptr<UpgradePoll>& Poll,
            std::optional<Provider> PreferredProvider,
            const Result<HttpResponse>& Sent)
        {
            if (!Sent.Ok())
            {
                Poll->Done(Result<UpgradeResult>::Failure(Sent.GetError()));
                return;
            }

            const HttpResponse& Response = Sent.Value();
            const auto Body = Json::ParseObject(Response.Body);
            if (!IsSuccess(Response.StatusCode))
            {
                Poll->Done(Result<UpgradeResult>::Failure(ErrorFrom(Response, Body.get())));
                return;
            }

            const auto Intent = Json::GetString(Body.get(), "intent");
            const auto PollSecret = Json::GetString(Body.get(), "poll_secret");
            const auto UpgradeUri = Json::GetString(Body.get(), "upgrade_uri");
            const auto ExpiresIn = Json::GetNumber(Body.get(), "expires_in");
            const double Interval = Json::GetNumber(Body.get(), "interval").value_or(MinimumPollIntervalSeconds);
            const auto Parsed = UpgradeUri ? Url::Parse(*UpgradeUri) : std::nullopt;
            if (!Intent || !MatchesId(*Intent, "gui_", 32, 64, true) || !PollSecret ||
                !MatchesId(*PollSecret, "gps_", 43, 86, true) || !Parsed || !Url::IsSameOrigin(*UpgradeUri, AuthOrigin) ||
                Parsed->Path != "/login/upgrade" || !ExpiresIn || *ExpiresIn <= 0 ||
                *ExpiresIn > MaxTokenLifetimeSeconds || Interval > MaxPollIntervalSeconds)
            {
                Poll->Done(Result<UpgradeResult>::Failure(InvalidResponse(Response.StatusCode, "The upgrade intent response is malformed.")));
                return;
            }

            Poll->Intent = *Intent;
            Poll->PollSecret = *PollSecret;
            Poll->UpgradeUri = *UpgradeUri;
            if (PreferredProvider)
            {
                // AUTH4D-343: the hint joins the query; the verifier stays in the fragment after it.
                const size_t FragmentAt = UpgradeUri->find('#');
                Poll->UpgradeUri = UpgradeUri->substr(0, FragmentAt) + (Parsed->bHasQuery ? "&" : "?") + "provider=" +
                                   ProviderName(*PreferredProvider) +
                                   (FragmentAt == std::string::npos ? std::string() : UpgradeUri->substr(FragmentAt));
            }

            Poll->ExpiresAt = Scheduler->Now() + *ExpiresIn;
            Poll->Interval = PollInterval(Interval);
            ReportProgress(Poll, UpgradeStage::OpeningBrowser, 0);
            Launcher->Open(Poll->UpgradeUri);
            UpgradePollStep(Poll);
        }

        void UpgradePollStep(std::shared_ptr<UpgradePoll> Poll)
        {
            ++Poll->Attempt;
            ReportProgress(Poll, UpgradeStage::WaitingForPlayer, Poll->Attempt - 1);
            if (Poll->Attempt > MaxPollAttempts || Scheduler->Now() >= Poll->ExpiresAt)
            {
                Poll->Done(Result<UpgradeResult>::Failure(MakeError(ErrorKind::UpgradeExpired, "expired_token")));
                return;
            }

            auto Self = shared_from_this();
            Delay(Poll->Interval, Poll->Cancel, [Self, Poll](bool bCancelled)
            {
                if (bCancelled)
                {
                    Poll->Done(Result<UpgradeResult>::Failure(MakeError(ErrorKind::Cancelled, "cancelled")));
                    return;
                }

                if (Self->Scheduler->Now() >= Poll->ExpiresAt)
                {
                    Poll->Done(Result<UpgradeResult>::Failure(MakeError(ErrorKind::UpgradeExpired, "expired_token")));
                    return;
                }

                // Not cancellable once sent: the token set is released exactly once, and the guest
                // session has already been revoked when it is.
                Self->Send(
                    Self->JsonRequest(
                        Self->GuestEndpoint("/upgrade-intent/token"),
                        {{"client_id", Self->ClientId}, {"intent", Poll->Intent}, {"poll_secret", Poll->PollSecret}}),
                    [Self, Poll](const Result<HttpResponse>& Sent) { Self->OnUpgradePollResponse(Poll, Sent); });
            });
        }

        void OnUpgradePollResponse(const std::shared_ptr<UpgradePoll>& Poll, const Result<HttpResponse>& Sent)
        {
            if (!Sent.Ok())
            {
                if (Sent.GetError().IsTransient() && Poll->TransientFailures < MaxTransientFailures)
                {
                    ++Poll->TransientFailures;
                    Poll->Interval = Backoff(Poll->Interval);
                    UpgradePollStep(Poll);
                    return;
                }

                Poll->Done(Result<UpgradeResult>::Failure(Sent.GetError()));
                return;
            }

            const HttpResponse& Response = Sent.Value();
            const auto Body = Json::ParseObject(Response.Body);
            if (Response.StatusCode == 200)
            {
                const auto Committed = CommitUpgrade(Response, Body.get(), Poll->GuestUserId, Poll->Generation);
                if (Committed.Ok())
                {
                    ReportProgress(Poll, UpgradeStage::Completed, Poll->Attempt);
                }

                Poll->Done(Committed);
                return;
            }

            const Error Failure = ErrorFrom(Response, Body.get());
            const auto ServerInterval = Json::GetNumber(Body.get(), "interval");
            if (Failure.Code == "authorization_pending")
            {
                Poll->TransientFailures = 0;
                if (ServerInterval)
                {
                    Poll->Interval = std::max(Poll->Interval, PollInterval(*ServerInterval));
                }

                UpgradePollStep(Poll);
                return;
            }

            if (Failure.Code == "slow_down")
            {
                Poll->TransientFailures = 0;
                Poll->Interval = std::min(
                    MaxPollIntervalSeconds,
                    std::max(Poll->Interval + SlowDownIncrementSeconds, ServerInterval ? PollInterval(*ServerInterval) : 0));
                UpgradePollStep(Poll);
                return;
            }

            const ErrorKind Terminal = Failure.Code == "identity_in_use" ? ErrorKind::UpgradeConflict
                                       : Failure.Code == "access_denied" ? ErrorKind::UpgradeDenied
                                       : Failure.Code == "expired_token" ? ErrorKind::UpgradeExpired
                                                                         : ErrorKind::None;
            if (Terminal != ErrorKind::None)
            {
                Poll->Done(Result<UpgradeResult>::Failure(MakeError(Terminal, Failure.Code, std::string(), Response.StatusCode)));
                return;
            }

            if (Failure.IsTransient() && Poll->TransientFailures < MaxTransientFailures)
            {
                ++Poll->TransientFailures;
                Poll->Interval = Backoff(Poll->Interval);
                UpgradePollStep(Poll);
                return;
            }

            Poll->Done(Result<UpgradeResult>::Failure(Failure));
        }

        /// Replaces the guest token set with the upgraded one. The local guest session may already be
        /// gone if a refresh hit the revoked guest token meanwhile; it is replaced all the same. An
        /// explicit sign-out wins.
        Result<UpgradeResult> CommitUpgrade(
            const HttpResponse& Response,
            const Json::Object* Body,
            const std::string& GuestUserId,
            unsigned Generation)
        {
            auto Tokens = ReadTokens(Response, Body);
            if (!Tokens.Ok())
            {
                return Result<UpgradeResult>::Failure(Tokens.GetError());
            }

            TokenState Next = Tokens.Value();
            const Json::Object* Identity = Json::GetObject(Body, "identity");
            const auto UserId = Json::GetString(Body, "user_id");
            if (SignOutGeneration != Generation || (State && State->UserId != GuestUserId))
            {
                RevokeQuietly(Next, nullptr);
                return Result<UpgradeResult>::Failure(MakeError(
                    ErrorKind::InvalidState,
                    "invalid_state",
                    "The guest signed out before the upgrade finished; sign in with the linked account."));
            }

            if (!UserId || *UserId != GuestUserId || Identity == nullptr)
            {
                RevokeQuietly(Next, nullptr);
                ClearLocal();
                return Result<UpgradeResult>::Failure(InvalidResponse(Response.StatusCode, "The upgrade did not preserve the guest user."));
            }

            Next.UserId = *UserId;
            Next.bIsGuest = false;
            UpgradeResult Out;
            Out.NewSession = Commit(Next);
            Out.Identity.IdentityId = Json::GetString(Identity, "identity_id").value_or(std::string());
            Out.Identity.Provider = Json::GetString(Identity, "provider").value_or(std::string());
            return Result<UpgradeResult>::Success(Out);
        }

        // ----- Tokens -----

        void GetAccessToken(Callback<std::string> Done)
        {
            if (!State)
            {
                Done(Result<std::string>::Failure(MakeError(ErrorKind::LoginRequired, "login_required", "No session is active.")));
                return;
            }

            if (!State->AccessToken.empty() && State->AccessTokenExpiresAt - RefreshMargin > Scheduler->Now())
            {
                Done(Result<std::string>::Success(State->AccessToken));
                return;
            }

            if (State->RefreshToken.empty())
            {
                Done(Result<std::string>::Failure(MakeError(
                    ErrorKind::LoginRequired, "login_required", "The access token expired and the session cannot be refreshed.")));
                return;
            }

            auto Self = shared_from_this();
            Refresh([Self, Done](const Result<Session>& Refreshed)
            {
                if (!Refreshed.Ok())
                {
                    Done(Result<std::string>::Failure(Refreshed.GetError()));
                    return;
                }

                if (!Self->State || Self->State->AccessToken.empty())
                {
                    Done(Result<std::string>::Failure(MakeError(ErrorKind::LoginRequired, "login_required", "No session is active.")));
                    return;
                }

                Done(Result<std::string>::Success(Self->State->AccessToken));
            });
        }

        void Refresh(Callback<Session> Done)
        {
            RefreshWaiters.push_back(std::move(Done));
            if (bRefreshing)
            {
                return;
            }

            if (!State || State->RefreshToken.empty())
            {
                FinishRefresh(Result<Session>::Failure(
                    MakeError(ErrorKind::LoginRequired, "login_required", "No refresh credential is available.")));
                return;
            }

            bRefreshing = true;
            const TokenState Presented = *State;
            const unsigned Generation = SignOutGeneration;
            auto Self = shared_from_this();
            Send(
                FormRequest(
                    TokenEndpoint(),
                    {{"grant_type", "refresh_token"}, {"client_id", ClientId}, {"refresh_token", Presented.RefreshToken}}),
                [Self, Presented, Generation](const Result<HttpResponse>& Sent)
                {
                    Self->bRefreshing = false;
                    Self->FinishRefresh(Self->OnRefreshResponse(Presented, Generation, Sent));
                });
        }

        Result<Session> OnRefreshResponse(const TokenState& Presented, unsigned Generation, const Result<HttpResponse>& Sent)
        {
            if (!Sent.Ok())
            {
                return Result<Session>::Failure(Sent.GetError());
            }

            const HttpResponse& Response = Sent.Value();
            const auto Body = Json::ParseObject(Response.Body);
            // The session this refresh started from is gone (sign-out) or was replaced (upgrade).
            const bool bStale = SignOutGeneration != Generation || !State || State->RefreshToken != Presented.RefreshToken;
            if (Response.StatusCode == 200)
            {
                auto Tokens = ReadTokens(Response, Body.get());
                if (!Tokens.Ok())
                {
                    return Result<Session>::Failure(Tokens.GetError());
                }

                TokenState Next = Tokens.Value();
                if (bStale)
                {
                    RevokeQuietly(Next, nullptr);
                    return State ? Result<Session>::Success(State->ToSession(IsPersistent()))
                                 : Result<Session>::Failure(MakeError(ErrorKind::LoginRequired, "login_required", "No session is active."));
                }

                Next.UserId = Presented.UserId;
                Next.bIsGuest = Presented.bIsGuest;
                if (Next.SessionId.empty())
                {
                    Next.SessionId = Presented.SessionId;
                }

                return Result<Session>::Success(Commit(Next));
            }

            const Error Failure = ErrorFrom(Response, Body.get());
            if (Failure.Code == "invalid_grant")
            {
                if (!bStale)
                {
                    ClearLocal();
                }

                return Result<Session>::Failure(
                    MakeError(ErrorKind::SessionExpired, Failure.Code, Failure.Description, Failure.StatusCode));
            }

            return Result<Session>::Failure(Failure);
        }

        void FinishRefresh(const Result<Session>& Outcome)
        {
            auto Waiters = std::move(RefreshWaiters);
            RefreshWaiters.clear();
            for (auto& Waiter : Waiters)
            {
                Waiter(Outcome);
            }
        }

        void TryRestoreSession(Callback<bool> Done)
        {
            // A refresh-only state is an incomplete restoration, not a usable session.
            if (State && !State->AccessToken.empty())
            {
                Done(Result<bool>::Success(true));
                return;
            }

            if (!State && !Storage)
            {
                Done(Result<bool>::Success(false));
                return;
            }

            RestoreWaiters.push_back(std::move(Done));
            if (bRestoring)
            {
                return;
            }

            bRestoring = true;
            const unsigned Generation = SignOutGeneration;
            if (State)
            {
                // A transient failure left the stored credential loaded; retry the refresh without reloading.
                RefreshForRestore(Generation);
                return;
            }

            auto Self = shared_from_this();
            EnqueueStorage([Self, Generation](std::function<void()> Next)
            {
                Self->Storage->Read(Self->StorageKey, [Self, Generation, Next](bool bOk, bool bFound, std::string Value)
                {
                    Next();
                    if (Self->bDisposed)
                    {
                        return;
                    }

                    if (!bOk)
                    {
                        Self->FinishRestore(Result<bool>::Failure(
                            MakeError(ErrorKind::InvalidState, "storage_unavailable", "Secure storage could not be read.")));
                        return;
                    }

                    Self->RestoreFrom(bFound ? Json::ParseObject(Value) : nullptr, bFound, Generation);
                });
            });
        }

        void RestoreFrom(const std::shared_ptr<Json::Object>& Stored, bool bFound, unsigned Generation)
        {
            if (SignOutGeneration != Generation)
            {
                // Signed out while the record was being read: do not resurrect the session.
                FinishRestore(Result<bool>::Success(false));
                return;
            }

            if (State)
            {
                RefreshForRestore(Generation);
                return;
            }

            const auto RefreshToken = Json::GetString(Stored.get(), "refresh_token");
            if (!RefreshToken || RefreshToken->empty())
            {
                if (bFound)
                {
                    DeleteStored();
                }

                FinishRestore(Result<bool>::Success(false));
                return;
            }

            TokenState Restored;
            Restored.RefreshToken = *RefreshToken;
            Restored.UserId = Json::GetString(Stored.get(), "user_id").value_or(std::string());
            Restored.bIsGuest = Json::GetString(Stored.get(), "guest").value_or(std::string()) == "true";
            State = Restored;
            RefreshForRestore(Generation);
        }

        void RefreshForRestore(unsigned Generation)
        {
            auto Self = shared_from_this();
            Refresh([Self, Generation](const Result<Session>& Refreshed)
            {
                if (Self->SignOutGeneration != Generation)
                {
                    Self->FinishRestore(Result<bool>::Success(false));
                }
                else if (Refreshed.Ok())
                {
                    Self->FinishRestore(Result<bool>::Success(true));
                }
                else if (Refreshed.GetError().Kind == ErrorKind::SessionExpired)
                {
                    Self->FinishRestore(Result<bool>::Success(false));
                }
                else
                {
                    Self->FinishRestore(Result<bool>::Failure(Refreshed.GetError()));
                }
            });
        }

        void FinishRestore(const Result<bool>& Outcome)
        {
            bRestoring = false;
            auto Waiters = std::move(RestoreWaiters);
            RestoreWaiters.clear();
            for (auto& Waiter : Waiters)
            {
                Waiter(Outcome);
            }
        }

        void SignOut(Callback<bool> Done)
        {
            const std::optional<TokenState> Current = State;
            ClearLocal();
            ++SignOutGeneration;
            if (!Current)
            {
                Done(Result<bool>::Success(true));
                return;
            }

            RevokeQuietly(*Current, [Done](bool bRevoked) { Done(Result<bool>::Success(bRevoked)); });
        }

        // ----- Internals -----

        static Error AlreadySignedIn()
        {
            return MakeError(
                ErrorKind::InvalidState,
                "invalid_state",
                "A session is already active. Upgrade the guest or sign out before signing in again.");
        }

        void AdoptNewSession(const TokenState& Tokens, const Callback<Session>& Done)
        {
            if (State)
            {
                RevokeQuietly(Tokens, nullptr);
                Done(Result<Session>::Failure(MakeError(
                    ErrorKind::InvalidState, "invalid_state", "Another session became active; sign out before signing in again.")));
                return;
            }

            Done(Result<Session>::Success(Commit(Tokens)));
        }

        Session Commit(const TokenState& Next)
        {
            State = Next;
            if (Storage)
            {
                if (Next.RefreshToken.empty())
                {
                    DeleteStored();
                }
                else
                {
                    const std::string Record = Json::SerializeStrings({
                        {"v", "1"},
                        {"refresh_token", Next.RefreshToken},
                        {"user_id", Next.UserId},
                        {"guest", Next.bIsGuest ? "true" : "false"},
                    });
                    auto Self = shared_from_this();
                    EnqueueStorage([Self, Record](std::function<void()> Done)
                    {
                        Self->Storage->Write(Self->StorageKey, Record, [Self, Done](bool bOk)
                        {
                            if (!bOk)
                            {
                                // A stale stored token would be replayed after restart and revoke the family; drop it.
                                Self->DeleteStored();
                            }

                            Done();
                        });
                    });
                }
            }

            const Session Out = Next.ToSession(IsPersistent());
            RaiseSessionChanged(&Out);
            return Out;
        }

        void ClearLocal()
        {
            const bool bHadSession = State.has_value();
            State.reset();
            if (Storage)
            {
                DeleteStored();
            }

            if (bHadSession)
            {
                RaiseSessionChanged(nullptr);
            }
        }

        void DeleteStored()
        {
            auto Self = shared_from_this();
            EnqueueStorage([Self](std::function<void()> Done)
            {
                Self->Storage->Delete(Self->StorageKey, [Done](bool) { Done(); });
            });
        }

        void EnqueueStorage(std::function<void(std::function<void()>)> Job)
        {
            StorageJobs.push_back(std::move(Job));
            if (!bStorageBusy)
            {
                RunNextStorageJob();
            }
        }

        void RunNextStorageJob()
        {
            if (StorageJobs.empty())
            {
                bStorageBusy = false;
                return;
            }

            bStorageBusy = true;
            auto Job = std::move(StorageJobs.front());
            StorageJobs.pop_front();
            auto Self = shared_from_this();
            auto bFinished = std::make_shared<bool>(false);
            Job([Self, bFinished]()
            {
                if (!*bFinished)
                {
                    *bFinished = true;
                    Self->RunNextStorageJob();
                }
            });
        }

        void RaiseSessionChanged(const Session* Value)
        {
            if (SessionListener && !bDisposed)
            {
                SessionListener(Value);
            }
        }

        /// Revokes the refresh token, or the access token when there is none. Done gets false when
        /// the server did not confirm.
        void RevokeQuietly(const TokenState& Tokens, std::function<void(bool)> Done)
        {
            const bool bRefresh = !Tokens.RefreshToken.empty();
            const std::string& Token = bRefresh ? Tokens.RefreshToken : Tokens.AccessToken;
            if (Token.empty())
            {
                if (Done)
                {
                    Done(true);
                }

                return;
            }

            Send(
                FormRequest(
                    Endpoint("/oauth/revoke?tenant_id=" + Url::Escape(TenantId)),
                    {{"client_id", ClientId}, {"token", Token}, {"token_type_hint", bRefresh ? "refresh_token" : "access_token"}}),
                [Done](const Result<HttpResponse>& Sent)
                {
                    if (Done)
                    {
                        Done(Sent.Ok() && IsSuccess(Sent.Value().StatusCode));
                    }
                });
        }

        Result<TokenState> ReadTokens(const HttpResponse& Response, const Json::Object* Body) const
        {
            const auto AccessToken = Json::GetString(Body, "access_token");
            const auto TokenType = Json::GetString(Body, "token_type");
            const auto ExpiresIn = Json::GetNumber(Body, "expires_in");
            std::string LowerType = TokenType.value_or(std::string());
            for (char& Character : LowerType)
            {
                Character = (Character >= 'A' && Character <= 'Z') ? static_cast<char>(Character - 'A' + 'a') : Character;
            }

            if (!AccessToken || AccessToken->empty() || LowerType != "bearer" || !ExpiresIn || *ExpiresIn <= 0 ||
                *ExpiresIn > MaxTokenLifetimeSeconds)
            {
                return Result<TokenState>::Failure(InvalidResponse(Response.StatusCode, "The token response is malformed."));
            }

            TokenState Out;
            Out.AccessToken = *AccessToken;
            Out.AccessTokenExpiresAt = Scheduler->Now() + *ExpiresIn;
            Out.RefreshToken = Json::GetString(Body, "refresh_token").value_or(std::string());
            Out.IdToken = Json::GetString(Body, "id_token").value_or(std::string());
            Out.Scope = Json::GetString(Body, "scope").value_or(std::string());
            Out.SessionId = Json::GetString(Body, "session_id").value_or(std::string());
            return Result<TokenState>::Success(Out);
        }

        /// Sends a request. Results for a destroyed client are dropped.
        void Send(const HttpRequest& Request, std::function<void(const Result<HttpResponse>&)> Done)
        {
            if (bDisposed)
            {
                return;
            }

            auto Self = shared_from_this();
            Transport->Send(Request, [Self, Done](HttpResponse Response)
            {
                if (Self->bDisposed)
                {
                    return;
                }

                if (Response.bNetworkError)
                {
                    Done(Result<HttpResponse>::Failure(
                        MakeError(ErrorKind::Network, "network_error", "The auth4.dev API could not be reached.")));
                    return;
                }

                Done(Result<HttpResponse>::Success(std::move(Response)));
            });
        }

        /// Waits, or reports cancellation as soon as the token fires.
        void Delay(int Seconds, const CancellationToken& Cancel, std::function<void(bool bCancelled)> Done)
        {
            if (Cancel.IsCancelled())
            {
                Done(true);
                return;
            }

            auto bFired = std::make_shared<bool>(false);
            auto Registration = std::make_shared<int>(0);
            auto Self = shared_from_this();
            *Registration = Cancel.Register([Self, bFired, Done]()
            {
                if (!*bFired && !Self->bDisposed)
                {
                    *bFired = true;
                    Done(true);
                }
            });
            Scheduler->After(Seconds, [Self, bFired, Registration, Cancel, Done]()
            {
                Cancel.Unregister(*Registration);
                if (!*bFired && !Self->bDisposed)
                {
                    *bFired = true;
                    Done(false);
                }
            });
        }

        HttpRequest FormRequest(const std::string& Uri, const FieldList& Fields) const
        {
            HttpRequest Request;
            Request.Url = Uri;
            Request.Headers = {{"Content-Type", "application/x-www-form-urlencoded"}, {"Accept", "application/json"}};
            Request.Body = Url::FormEncode(Fields);
            return Request;
        }

        HttpRequest JsonRequest(const std::string& Uri, const FieldList& Fields) const
        {
            HttpRequest Request;
            Request.Url = Uri;
            Request.Headers = {{"Content-Type", "application/json"}, {"Accept", "application/json"}};
            Request.Body = Json::SerializeStrings(Fields);
            return Request;
        }

        std::string TokenEndpoint() const { return Endpoint("/oauth/token?tenant_id=" + Url::Escape(TenantId)); }

        std::string GuestEndpoint(const std::string& Suffix) const { return Endpoint("/t/" + Url::Escape(TenantId) + "/guest" + Suffix); }

        std::string Endpoint(const std::string& PathAndQuery) const { return AuthOrigin + PathAndQuery; }

        static std::string NewBrowserFlowId()
        {
            static const char Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            std::random_device Random;
            std::string Out = "flw_";
            for (int Index = 0; Index < 32; ++Index)
            {
                Out.push_back(Alphabet[Random() & 63]);
            }

            return Out;
        }
    };

    Result<std::shared_ptr<Client>> Client::Create(const ClientOptions& Options)
    {
        const auto Invalid = [](const char* Description)
        {
            return Result<std::shared_ptr<Client>>::Failure(MakeError(ErrorKind::InvalidArgument, "invalid_argument", Description));
        };

        if (!MatchesId(Options.TenantId, "ten_", 16, 64, false))
        {
            return Invalid("A valid tenant ID (ten_...) is required.");
        }

        if (!MatchesId(Options.ClientId, "cli_", 16, 64, false))
        {
            return Invalid("A valid client ID (cli_...) is required.");
        }

        const auto Origin = Url::NormalizeOrigin(Options.AuthOrigin);
        if (!Origin)
        {
            return Invalid("AuthOrigin must be an https origin without a path (http is allowed only for loopback hosts).");
        }

        const auto Scope = NormalizeScope(Options.DefaultScope);
        if (!Scope)
        {
            return Invalid("The default scope must include openid.");
        }

        if (!Options.Transport || !Options.Scheduler)
        {
            return Invalid("A transport and a scheduler are required.");
        }

        if (Options.MaxPollAttempts < 1 || Options.MaxConsecutiveTransientPollFailures < 0 ||
            Options.AccessTokenRefreshMarginSeconds < 0)
        {
            return Invalid("Polling and refresh limits must be positive.");
        }

        auto Impl = std::make_shared<ClientImpl>();
        Impl->TenantId = Options.TenantId;
        Impl->ClientId = Options.ClientId;
        Impl->AuthOrigin = *Origin;
        Impl->DefaultScope = *Scope;
        Impl->Transport = Options.Transport;
        Impl->Scheduler = Options.Scheduler;
        Impl->Storage = Options.SecureStorage;
        Impl->Launcher = Options.BrowserLauncher;
        Impl->StorageKey = "auth4." + Options.TenantId + "." + Options.ClientId + ".session";
        Impl->RefreshMargin = Options.AccessTokenRefreshMarginSeconds;
        Impl->MaxPollAttempts = Options.MaxPollAttempts;
        Impl->MaxTransientFailures = Options.MaxConsecutiveTransientPollFailures;
        return Result<std::shared_ptr<Client>>::Success(std::shared_ptr<Client>(new Client(Impl)));
    }

    Client::Client(std::shared_ptr<ClientImpl> InImpl) : Impl(std::move(InImpl)) {}

    Client::~Client()
    {
        Impl->bDisposed = true;
        Impl->SessionListener = nullptr;
    }

    const std::string& Client::TenantId() const { return Impl->TenantId; }

    const std::string& Client::ClientId() const { return Impl->ClientId; }

    const std::string& Client::AuthOrigin() const { return Impl->AuthOrigin; }

    bool Client::IsRefreshPersistent() const { return Impl->IsPersistent(); }

    std::optional<Session> Client::CurrentSession() const
    {
        if (!Impl->State || Impl->State->AccessToken.empty())
        {
            return std::nullopt;
        }

        return Impl->State->ToSession(Impl->IsPersistent());
    }

    void Client::SetSessionChangedListener(std::function<void(const Session*)> Listener)
    {
        Impl->SessionListener = std::move(Listener);
    }

    void Client::StartDeviceAuthorization(const std::string& Scope, Callback<DeviceAuthorizationPtr> Done)
    {
        Impl->StartDeviceAuthorization(Scope, std::move(Done));
    }

    void Client::PollDeviceAuthorization(DeviceAuthorizationPtr Authorization, CancellationToken Cancel, Callback<Session> Done)
    {
        Impl->PollDeviceAuthorization(std::move(Authorization), std::move(Cancel), std::move(Done));
    }

    void Client::SignInWithDevice(
        std::function<void(const DeviceAuthorization&)> ShowUserCode,
        const std::string& Scope,
        CancellationToken Cancel,
        Callback<Session> Done)
    {
        auto Self = Impl;
        Impl->StartDeviceAuthorization(Scope, [Self, ShowUserCode, Cancel, Done](const Result<DeviceAuthorizationPtr>& Started)
        {
            if (!Started.Ok())
            {
                Done(Result<Session>::Failure(Started.GetError()));
                return;
            }

            if (ShowUserCode)
            {
                ShowUserCode(*Started.Value());
            }

            Self->PollDeviceAuthorization(Started.Value(), Cancel, Done);
        });
    }

    void Client::SignInAsGuest(Callback<Session> Done) { Impl->SignInAsGuest(std::move(Done)); }

    void Client::UpgradeGuest(
        std::optional<Provider> PreferredProvider,
        std::function<void(const UpgradeProgress&)> OnProgress,
        CancellationToken Cancel,
        Callback<UpgradeResult> Done)
    {
        Impl->UpgradeGuest(PreferredProvider, std::move(OnProgress), std::move(Cancel), std::move(Done));
    }

    void Client::GetAccessToken(Callback<std::string> Done) { Impl->GetAccessToken(std::move(Done)); }

    void Client::Refresh(Callback<Session> Done) { Impl->Refresh(std::move(Done)); }

    void Client::TryRestoreSession(Callback<bool> Done) { Impl->TryRestoreSession(std::move(Done)); }

    void Client::SignOut(Callback<bool> Done) { Impl->SignOut(std::move(Done)); }
}
