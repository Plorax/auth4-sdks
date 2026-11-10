// Protocol tests with a scripted transport and virtual time. They pin the behaviour the Unity SDK
// tests pin (packages/sdk-unity/Tests~): polling rules, refresh rotation, storage and upgrade safety.
#include <algorithm>

#include "Auth4Json.h"
#include "Auth4Url.h"
#include "TestSupport.h"

using namespace Auth4;
using namespace Auth4Tests;

namespace
{
    const char* const Origin = "https://auth.example.test";

    struct Harness
    {
        EventLoop Loop;
        std::shared_ptr<FakeTransport> Transport = std::make_shared<FakeTransport>(Loop);
        std::shared_ptr<MemoryStorage> Storage = std::make_shared<MemoryStorage>(Loop);
        std::shared_ptr<RecordingLauncher> Launcher = std::make_shared<RecordingLauncher>();
        std::shared_ptr<Client> Instance;
        std::vector<bool> SessionEvents;

        explicit Harness(bool bWithStorage = false, bool bWithLauncher = true)
        {
            ClientOptions Options;
            Options.TenantId = TestTenant;
            Options.ClientId = TestClient;
            Options.AuthOrigin = Origin;
            Options.Transport = Transport;
            Options.Scheduler = std::shared_ptr<IScheduler>(&Loop, [](IScheduler*) {});
            Options.SecureStorage = bWithStorage ? Storage : nullptr;
            Options.BrowserLauncher = bWithLauncher ? Launcher : nullptr;
            Instance = Client::Create(Options).Value();
            Instance->SetSessionChangedListener([this](const Session* Value) { SessionEvents.push_back(Value != nullptr); });
        }

        /// Signs in as a guest whose access token expires in five minutes.
        bool SignInGuest(const std::string& RefreshToken = "rt_guest")
        {
            auto Previous = Transport->Handler;
            Transport->Handler = [RefreshToken](const RecordedRequest&)
            {
                return Respond(201, TokenJson("at_guest", RefreshToken, "\"user_id\":\"usr_guest\""));
            };
            Captured<Session> Result;
            Instance->SignInAsGuest(Result.Callback());
            Loop.RunUntil([&Result]() { return Result.Done(); });
            Transport->Handler = Previous;
            return Result.Ok();
        }

        bool NoTokensInUrls() const
        {
            return std::none_of(Transport->Requests.begin(), Transport->Requests.end(), [](const RecordedRequest& Entry)
            {
                return Entry.Request.Url.find("at_") != std::string::npos || Entry.Request.Url.find("rt_") != std::string::npos ||
                       Entry.Request.Url.find("gps_") != std::string::npos;
            });
        }
    };

    std::string DeviceAuthorizationJson(const std::string& VerificationUri, int ExpiresIn = 600)
    {
        return "{\"device_code\":\"dc_1\",\"user_code\":\"BCDF-GHJK\",\"verification_uri\":\"" + VerificationUri +
               "\",\"expires_in\":" + std::to_string(ExpiresIn) + ",\"interval\":5}";
    }

    std::string IntentJson(const std::string& UpgradeUri)
    {
        return "{\"intent\":\"gui_" + std::string(40, 'a') + "\",\"poll_secret\":\"gps_" + std::string(43, 'b') +
               "\",\"upgrade_uri\":\"" + UpgradeUri + "\",\"expires_in\":600,\"interval\":5}";
    }
}

// ----- Options -----

AUTH4_TEST(CreateRejectsInvalidOptions)
{
    EventLoop Loop;
    const auto Make = [&Loop](const char* Tenant, const char* ClientValue, const char* AuthOrigin, const char* Scope)
    {
        ClientOptions Options;
        Options.TenantId = Tenant;
        Options.ClientId = ClientValue;
        Options.AuthOrigin = AuthOrigin;
        Options.DefaultScope = Scope;
        Options.Transport = std::make_shared<FakeTransport>(Loop);
        Options.Scheduler = std::shared_ptr<IScheduler>(&Loop, [](IScheduler*) {});
        return Client::Create(Options);
    };

    EXPECT_TRUE(Make(TestTenant, TestClient, Origin, "openid").Ok());
    EXPECT_TRUE(Make(TestTenant, TestClient, "http://127.0.0.1:8787", "openid").Ok());
    EXPECT_TRUE(!Make("ten_short", TestClient, Origin, "openid").Ok());
    EXPECT_TRUE(!Make(TestTenant, "cli_has-dash000000000", Origin, "openid").Ok());
    EXPECT_TRUE(!Make(TestTenant, TestClient, "http://auth.example.test", "openid").Ok());
    EXPECT_TRUE(!Make(TestTenant, TestClient, "https://auth.example.test/path", "openid").Ok());
    EXPECT_TRUE(!Make(TestTenant, TestClient, "https://user@auth.example.test", "openid").Ok());
    EXPECT_TRUE(!Make(TestTenant, TestClient, Origin, "profile offline_access").Ok());
    EXPECT_EQ(ErrorKind::InvalidArgument, Make(TestTenant, TestClient, Origin, "").GetError().Kind);

    ClientOptions Missing;
    Missing.TenantId = TestTenant;
    Missing.ClientId = TestClient;
    Missing.AuthOrigin = Origin;
    EXPECT_TRUE(!Client::Create(Missing).Ok());
}

// ----- Device authorization -----

AUTH4_TEST(DeviceAuthorizationRejectsCrossOriginVerificationUri)
{
    Harness Test;
    Test.Transport->Handler = [](const RecordedRequest&) { return Respond(200, DeviceAuthorizationJson("https://evil.example/device")); };
    Captured<DeviceAuthorizationPtr> Result;
    Test.Instance->StartDeviceAuthorization("", Result.Callback());
    Test.Loop.RunUntil([&Result]() { return Result.Done(); });
    EXPECT_EQ(ErrorKind::InvalidResponse, Result.Kind());
}

AUTH4_TEST(DevicePollingFollowsPendingAndSlowDown)
{
    Harness Test;
    std::vector<std::string> Script = {"authorization_pending", "slow_down", "approve"};
    Test.Transport->Handler = [&Script](const RecordedRequest& Request)
    {
        if (Request.Path() == "/device/authorization")
        {
            return Respond(200, DeviceAuthorizationJson(std::string(Origin) + "/device"));
        }

        const std::string Step = Script.front();
        Script.erase(Script.begin());
        return Step == "approve" ? Respond(200, TokenJson("at_device", "rt_device"))
                                 : Respond(400, "{\"error\":\"" + Step + "\"}");
    };

    std::string ShownCode;
    Captured<Session> Result;
    Test.Instance->SignInWithDevice(
        [&ShownCode](const DeviceAuthorization& Authorization) { ShownCode = Authorization.UserCode; },
        "openid offline_access openid",
        CancellationToken(),
        Result.Callback());
    Test.Loop.RunUntil([&Result]() { return Result.Done(); });

    REQUIRE_TRUE(Result.Ok());
    EXPECT_EQ(std::string("BCDF-GHJK"), ShownCode);
    EXPECT_EQ(std::string("openid offline_access"), Test.Transport->Requests[0].Field("scope"));
    REQUIRE_TRUE(Test.Transport->Requests.size() == 4);
    const auto& Requests = Test.Transport->Requests;
    EXPECT_EQ(5.0, Requests[1].SentAt - Requests[0].SentAt);
    EXPECT_EQ(5.0, Requests[2].SentAt - Requests[1].SentAt);
    // slow_down adds five seconds to the interval.
    EXPECT_EQ(10.0, Requests[3].SentAt - Requests[2].SentAt);
    EXPECT_EQ(std::string("urn:ietf:params:oauth:grant-type:device_code"), Requests[1].Field("grant_type"));
    EXPECT_TRUE(Result.Value->Value().bCanRefresh);
    EXPECT_TRUE(!Result.Value->Value().bIsRefreshPersistent);
    EXPECT_TRUE(Test.NoTokensInUrls());
}

AUTH4_TEST(DevicePollingBacksOffOnTransientFailures)
{
    Harness Test;
    int Polls = 0;
    Test.Transport->Handler = [&Polls](const RecordedRequest& Request)
    {
        if (Request.Path() == "/device/authorization")
        {
            return Respond(200, DeviceAuthorizationJson(std::string(Origin) + "/device"));
        }

        ++Polls;
        if (Polls == 1)
        {
            Auth4::HttpResponse Failed;
            Failed.bNetworkError = true;
            return Failed;
        }

        return Polls == 2 ? Respond(503, "{\"error\":\"temporarily_unavailable\"}") : Respond(200, TokenJson("at_d", "rt_d"));
    };

    Captured<Session> Result;
    Test.Instance->SignInWithDevice(nullptr, "", CancellationToken(), Result.Callback());
    Test.Loop.RunUntil([&Result]() { return Result.Done(); });
    REQUIRE_TRUE(Result.Ok());
    const auto& Requests = Test.Transport->Requests;
    EXPECT_EQ(10.0, Requests[2].SentAt - Requests[1].SentAt);
    EXPECT_EQ(20.0, Requests[3].SentAt - Requests[2].SentAt);
}

AUTH4_TEST(DevicePollingStopsAtExpiryAndOnDenial)
{
    {
        Harness Test;
        Test.Transport->Handler = [](const RecordedRequest& Request)
        {
            return Request.Path() == "/device/authorization" ? Respond(200, DeviceAuthorizationJson(std::string(Origin) + "/device", 12))
                                                              : Respond(400, "{\"error\":\"authorization_pending\"}");
        };
        Captured<Session> Result;
        Test.Instance->SignInWithDevice(nullptr, "", CancellationToken(), Result.Callback());
        Test.Loop.RunUntil([&Result]() { return Result.Done(); });
        EXPECT_EQ(ErrorKind::DeviceExpired, Result.Kind());
        EXPECT_EQ(static_cast<size_t>(3), Test.Transport->Requests.size());
    }

    {
        Harness Test;
        Test.Transport->Handler = [](const RecordedRequest& Request)
        {
            return Request.Path() == "/device/authorization" ? Respond(200, DeviceAuthorizationJson(std::string(Origin) + "/device"))
                                                              : Respond(400, "{\"error\":\"access_denied\"}");
        };
        Captured<Session> Result;
        Test.Instance->SignInWithDevice(nullptr, "", CancellationToken(), Result.Callback());
        Test.Loop.RunUntil([&Result]() { return Result.Done(); });
        EXPECT_EQ(ErrorKind::DeviceDenied, Result.Kind());
        EXPECT_TRUE(!Test.Instance->CurrentSession().has_value());
    }
}

AUTH4_TEST(DevicePollingCancelsPromptlyAndCanResume)
{
    Harness Test;
    bool bApprove = false;
    Test.Transport->Handler = [&bApprove](const RecordedRequest& Request)
    {
        if (Request.Path() == "/device/authorization")
        {
            return Respond(200, DeviceAuthorizationJson(std::string(Origin) + "/device"));
        }

        return bApprove ? Respond(200, TokenJson("at_d", "rt_d")) : Respond(400, "{\"error\":\"authorization_pending\"}");
    };

    Captured<DeviceAuthorizationPtr> Started;
    Test.Instance->StartDeviceAuthorization("", Started.Callback());
    Test.Loop.RunUntil([&Started]() { return Started.Done(); });
    REQUIRE_TRUE(Started.Ok());
    auto Authorization = Started.Value->Value();

    CancellationSource Cancel;
    Captured<Session> First;
    Test.Instance->PollDeviceAuthorization(Authorization, Cancel.Token(), First.Callback());

    Captured<Session> Concurrent;
    Test.Instance->PollDeviceAuthorization(Authorization, CancellationToken(), Concurrent.Callback());
    EXPECT_EQ(ErrorKind::InvalidState, Concurrent.Kind());

    const double CancelledAt = Test.Loop.Clock + 1;
    Test.Loop.After(1, [&Cancel]() { Cancel.Cancel(); });
    Test.Loop.RunUntil([&First]() { return First.Done(); });
    EXPECT_EQ(ErrorKind::Cancelled, First.Kind());
    EXPECT_EQ(CancelledAt, Test.Loop.Clock);
    EXPECT_TRUE(!Authorization->IsCompleted());

    bApprove = true;
    Captured<Session> Resumed;
    Test.Instance->PollDeviceAuthorization(Authorization, CancellationToken(), Resumed.Callback());
    Test.Loop.RunUntil([&Resumed]() { return Resumed.Done(); });
    EXPECT_TRUE(Resumed.Ok());
    EXPECT_TRUE(Authorization->IsCompleted());
}

// ----- Guests and sessions -----

AUTH4_TEST(GuestSignInRefusesToReplaceAnActiveSession)
{
    Harness Test;
    REQUIRE_TRUE(Test.SignInGuest());
    const auto Current = Test.Instance->CurrentSession();
    REQUIRE_TRUE(Current.has_value());
    EXPECT_EQ(std::string("usr_guest"), Current->UserId);
    EXPECT_TRUE(Current->bIsGuest);
    EXPECT_TRUE(Test.Transport->Requests[0].Field("browser_flow_id").rfind("flw_", 0) == 0);

    Captured<Session> Again;
    Test.Instance->SignInAsGuest(Again.Callback());
    EXPECT_EQ(ErrorKind::InvalidState, Again.Kind());

    Captured<DeviceAuthorizationPtr> Device;
    Test.Instance->StartDeviceAuthorization("", Device.Callback());
    EXPECT_EQ(ErrorKind::InvalidState, Device.Kind());
}

AUTH4_TEST(ConcurrentCallersShareOneRefresh)
{
    Harness Test;
    REQUIRE_TRUE(Test.SignInGuest());
    Test.Transport->Handler = [](const RecordedRequest& Request)
    {
        return Request.Field("refresh_token") == "rt_guest" ? Respond(200, TokenJson("at_next", "rt_next"))
                                                            : Respond(400, "{\"error\":\"invalid_grant\"}");
    };

    Test.Loop.Advance(290);
    Captured<std::string> First;
    Captured<std::string> Second;
    Captured<Session> Third;
    Test.Instance->GetAccessToken(First.Callback());
    Test.Instance->GetAccessToken(Second.Callback());
    Test.Instance->Refresh(Third.Callback());
    Test.Loop.RunUntil([&]() { return First.Done() && Second.Done() && Third.Done(); });

    EXPECT_EQ(static_cast<size_t>(1), Test.Transport->Count("/oauth/token"));
    REQUIRE_TRUE(First.Ok() && Second.Ok() && Third.Ok());
    EXPECT_EQ(std::string("at_next"), First.Value->Value());
    EXPECT_EQ(std::string("at_next"), Second.Value->Value());
    EXPECT_EQ(std::string("usr_guest"), Third.Value->Value().UserId);
    EXPECT_TRUE(Third.Value->Value().bIsGuest);
    EXPECT_TRUE(Test.NoTokensInUrls());
}

AUTH4_TEST(RejectedRefreshClearsTheSessionAndStorage)
{
    Harness Test(true);
    REQUIRE_TRUE(Test.SignInGuest());
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });
    EXPECT_EQ(static_cast<size_t>(1), Test.Storage->Values.size());

    Test.Transport->Handler = [](const RecordedRequest&) { return Respond(400, "{\"error\":\"invalid_grant\"}"); };
    Captured<Session> Result;
    Test.Instance->Refresh(Result.Callback());
    Test.Loop.RunUntil([&Result]() { return Result.Done(); });
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });

    EXPECT_EQ(ErrorKind::SessionExpired, Result.Kind());
    EXPECT_TRUE(!Test.Instance->CurrentSession().has_value());
    EXPECT_TRUE(Test.Storage->Values.empty());
    REQUIRE_TRUE(Test.SessionEvents.size() == 2);
    EXPECT_TRUE(Test.SessionEvents[0]);
    EXPECT_TRUE(!Test.SessionEvents[1]);

    Captured<std::string> Token;
    Test.Instance->GetAccessToken(Token.Callback());
    EXPECT_EQ(ErrorKind::LoginRequired, Token.Kind());
}

AUTH4_TEST(StorageHoldsOnlyTheLatestRefreshToken)
{
    Harness Test(true);
    REQUIRE_TRUE(Test.SignInGuest());
    Test.Transport->Handler = [](const RecordedRequest&) { return Respond(200, TokenJson("at_2", "rt_2")); };
    Captured<Session> Refreshed;
    Test.Instance->Refresh(Refreshed.Callback());
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });
    REQUIRE_TRUE(Refreshed.Ok());
    EXPECT_TRUE(Refreshed.Value->Value().bIsRefreshPersistent);

    const std::string Key = std::string("auth4.") + TestTenant + "." + TestClient + ".session";
    const auto Stored = Json::ParseObject(Test.Storage->Values[Key]);
    EXPECT_EQ(std::string("rt_2"), Json::GetString(Stored.get(), "refresh_token").value_or(""));
    EXPECT_EQ(std::string("usr_guest"), Json::GetString(Stored.get(), "user_id").value_or(""));
    EXPECT_EQ(std::string("true"), Json::GetString(Stored.get(), "guest").value_or(""));
    // The stored record never includes the access token.
    EXPECT_TRUE(Test.Storage->Values[Key].find("at_2") == std::string::npos);

    Test.Storage->bFailWrites = true;
    Test.Transport->Handler = [](const RecordedRequest&) { return Respond(200, TokenJson("at_3", "rt_3")); };
    Captured<Session> Again;
    Test.Instance->Refresh(Again.Callback());
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });
    // A failed write deletes the stale record rather than leaving rt_2 to be replayed.
    EXPECT_TRUE(Test.Storage->Values.empty());
}

AUTH4_TEST(RestoreHandlesMissingAndCorruptRecords)
{
    Harness Test(true);
    Captured<bool> Empty;
    Test.Instance->TryRestoreSession(Empty.Callback());
    Test.Loop.RunUntil([&Empty]() { return Empty.Done(); });
    REQUIRE_TRUE(Empty.Ok());
    EXPECT_TRUE(!Empty.Value->Value());

    const std::string Key = std::string("auth4.") + TestTenant + "." + TestClient + ".session";
    Test.Storage->Values[Key] = "not json";
    Captured<bool> Corrupt;
    Test.Instance->TryRestoreSession(Corrupt.Callback());
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });
    REQUIRE_TRUE(Corrupt.Ok());
    EXPECT_TRUE(!Corrupt.Value->Value());
    EXPECT_TRUE(Test.Storage->Values.empty());

    Test.Storage->Values[Key] = "{\"v\":\"1\",\"refresh_token\":\"rt_saved\",\"user_id\":\"usr_saved\",\"guest\":\"false\"}";
    Test.Transport->Handler = [](const RecordedRequest& Request)
    {
        return Request.Field("refresh_token") == "rt_saved" ? Respond(200, TokenJson("at_r", "rt_r")) : Respond(400, "{\"error\":\"invalid_grant\"}");
    };
    Captured<bool> Restored;
    Test.Instance->TryRestoreSession(Restored.Callback());
    Test.Loop.RunUntil([&Restored]() { return Restored.Done(); });
    REQUIRE_TRUE(Restored.Ok());
    EXPECT_TRUE(Restored.Value->Value());
    EXPECT_EQ(std::string("usr_saved"), Test.Instance->CurrentSession()->UserId);
    EXPECT_TRUE(!Test.Instance->CurrentSession()->bIsGuest);
}

AUTH4_TEST(RestoreRetriesRefreshAfterATransientFailure)
{
    Harness Test(true);
    const std::string Key = std::string("auth4.") + TestTenant + "." + TestClient + ".session";
    Test.Storage->Values[Key] = "{\"v\":\"1\",\"refresh_token\":\"rt_saved\",\"user_id\":\"usr_saved\",\"guest\":\"false\"}";
    Test.Transport->Handler = [](const RecordedRequest&) { return Respond(503, "{\"error\":\"temporarily_unavailable\"}"); };
    Captured<bool> Failed;
    Test.Instance->TryRestoreSession(Failed.Callback());
    Test.Loop.RunUntil([&Failed]() { return Failed.Done(); });
    REQUIRE_TRUE(!Failed.Ok());
    EXPECT_TRUE(!Test.Instance->CurrentSession().has_value());
    EXPECT_TRUE(Test.Storage->Values.count(Key) == 1);

    Test.Transport->Handler = [](const RecordedRequest& Request)
    {
        return Request.Field("refresh_token") == "rt_saved" ? Respond(200, TokenJson("at_r", "rt_r")) : Respond(400, "{\"error\":\"invalid_grant\"}");
    };
    Captured<bool> Retried;
    Test.Instance->TryRestoreSession(Retried.Callback());
    Test.Loop.RunUntil([&Retried]() { return Retried.Done(); });
    REQUIRE_TRUE(Retried.Ok());
    EXPECT_TRUE(Retried.Value->Value());
    REQUIRE_TRUE(Test.Instance->CurrentSession().has_value());
    EXPECT_EQ(std::string("usr_saved"), Test.Instance->CurrentSession()->UserId);
    EXPECT_EQ(static_cast<size_t>(2), Test.Transport->Count("/oauth/token"));
    EXPECT_TRUE(Test.Storage->Values[Key].find("rt_r") != std::string::npos);
}

AUTH4_TEST(ConcurrentRestoreCallersShareOneRefreshOutcome)
{
    Harness Test(true);
    const std::string Key = std::string("auth4.") + TestTenant + "." + TestClient + ".session";
    Test.Storage->Values[Key] = "{\"v\":\"1\",\"refresh_token\":\"rt_saved\",\"user_id\":\"usr_saved\",\"guest\":\"false\"}";
    Test.Transport->Handler = [](const RecordedRequest&) { return Respond(200, TokenJson("at_r", "rt_r")); };
    Captured<bool> First;
    Captured<bool> Second;
    Test.Instance->TryRestoreSession(First.Callback());
    Test.Instance->TryRestoreSession(Second.Callback());
    EXPECT_TRUE(!First.Done() && !Second.Done());
    EXPECT_TRUE(!Test.Instance->CurrentSession().has_value());
    Test.Loop.RunUntil([&]() { return First.Done() && Second.Done(); });
    REQUIRE_TRUE(First.Ok() && Second.Ok());
    EXPECT_TRUE(First.Value->Value() && Second.Value->Value());
    EXPECT_EQ(static_cast<size_t>(1), Test.Transport->Count("/oauth/token"));
}

AUTH4_TEST(RestoreWithARevokedCredentialClearsItForEveryCaller)
{
    Harness Test(true);
    const std::string Key = std::string("auth4.") + TestTenant + "." + TestClient + ".session";
    Test.Storage->Values[Key] = "{\"v\":\"1\",\"refresh_token\":\"rt_saved\",\"user_id\":\"usr_saved\",\"guest\":\"false\"}";
    Test.Transport->Handler = [](const RecordedRequest&) { return Respond(400, "{\"error\":\"invalid_grant\"}"); };
    Captured<bool> First;
    Captured<bool> Second;
    Test.Instance->TryRestoreSession(First.Callback());
    Test.Instance->TryRestoreSession(Second.Callback());
    Test.Loop.RunUntil([&]() { return First.Done() && Second.Done(); });
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });
    REQUIRE_TRUE(First.Ok() && Second.Ok());
    EXPECT_TRUE(!First.Value->Value() && !Second.Value->Value());
    EXPECT_TRUE(!Test.Instance->CurrentSession().has_value());
    EXPECT_TRUE(Test.Storage->Values.empty());
}

AUTH4_TEST(SignOutDuringRestoreCannotResurrectTheSession)
{
    Harness Test(true);
    const std::string Key = std::string("auth4.") + TestTenant + "." + TestClient + ".session";
    Test.Storage->Values[Key] = "{\"v\":\"1\",\"refresh_token\":\"rt_saved\",\"user_id\":\"usr_saved\",\"guest\":\"false\"}";
    Test.Transport->Handler = [](const RecordedRequest& Request)
    {
        return Request.Path() == "/oauth/token" ? Respond(200, TokenJson("at_late", "rt_late")) : Respond(200, "{}");
    };

    // Signed out while the stored record is still being read.
    Captured<bool> EarlyRestore;
    Test.Instance->TryRestoreSession(EarlyRestore.Callback());
    Captured<bool> EarlySignOut;
    Test.Instance->SignOut(EarlySignOut.Callback());
    Test.Loop.RunUntil([&]() { return EarlyRestore.Done() && EarlySignOut.Done(); });
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });
    REQUIRE_TRUE(EarlyRestore.Ok());
    EXPECT_TRUE(!EarlyRestore.Value->Value());
    EXPECT_TRUE(!Test.Instance->CurrentSession().has_value());
    EXPECT_TRUE(Test.Storage->Values.empty());

    // Signed out while the refresh request is in flight.
    Test.Storage->Values[Key] = "{\"v\":\"1\",\"refresh_token\":\"rt_saved\",\"user_id\":\"usr_saved\",\"guest\":\"false\"}";
    Captured<bool> LateRestore;
    Test.Instance->TryRestoreSession(LateRestore.Callback());
    Test.Loop.RunUntil([&Test]() { return Test.Transport->Count("/oauth/token") == 1; });
    Captured<bool> LateSignOut;
    Test.Instance->SignOut(LateSignOut.Callback());
    Test.Loop.RunUntil([&]() { return LateRestore.Done() && LateSignOut.Done(); });
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });
    REQUIRE_TRUE(LateRestore.Ok());
    EXPECT_TRUE(!LateRestore.Value->Value());
    EXPECT_TRUE(!Test.Instance->CurrentSession().has_value());
    EXPECT_TRUE(Test.Storage->Values.empty());
}

AUTH4_TEST(SignOutRevokesTheRefreshToken)
{
    Harness Test;
    REQUIRE_TRUE(Test.SignInGuest());
    Test.Transport->Handler = [](const RecordedRequest&) { return Respond(200, "{}"); };
    Captured<bool> Result;
    Test.Instance->SignOut(Result.Callback());
    EXPECT_TRUE(!Test.Instance->CurrentSession().has_value());
    Test.Loop.RunUntil([&Result]() { return Result.Done(); });
    REQUIRE_TRUE(Result.Ok());
    EXPECT_TRUE(Result.Value->Value());
    const auto& Revoke = Test.Transport->Requests.back();
    EXPECT_EQ(std::string("/oauth/revoke"), Revoke.Path());
    EXPECT_EQ(std::string("rt_guest"), Revoke.Field("token"));
    EXPECT_EQ(std::string("refresh_token"), Revoke.Field("token_type_hint"));
}

AUTH4_TEST(SignOutDuringRefreshDiscardsTheRotatedTokens)
{
    Harness Test;
    REQUIRE_TRUE(Test.SignInGuest());
    Test.Transport->Handler = [](const RecordedRequest& Request)
    {
        return Request.Path() == "/oauth/token" ? Respond(200, TokenJson("at_late", "rt_late")) : Respond(200, "{}");
    };
    Captured<Session> Refreshed;
    Test.Instance->Refresh(Refreshed.Callback());
    Captured<bool> SignedOut;
    Test.Instance->SignOut(SignedOut.Callback());
    Test.Loop.RunUntil([&]() { return Refreshed.Done() && SignedOut.Done(); });
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });

    EXPECT_EQ(ErrorKind::LoginRequired, Refreshed.Kind());
    EXPECT_TRUE(!Test.Instance->CurrentSession().has_value());
    const bool bRevokedLate = std::any_of(Test.Transport->Requests.begin(), Test.Transport->Requests.end(), [](const RecordedRequest& Entry)
    {
        return Entry.Path() == "/oauth/revoke" && Entry.Field("token") == "rt_late";
    });
    EXPECT_TRUE(bRevokedLate);
}

// ----- Guest upgrade intents -----

AUTH4_TEST(UpgradeNeedsALauncherAndAGuest)
{
    {
        Harness Test(false, false);
        Captured<UpgradeResult> Result;
        Test.Instance->UpgradeGuest(std::nullopt, nullptr, CancellationToken(), Result.Callback());
        EXPECT_EQ(ErrorKind::NotSupported, Result.Kind());
    }

    {
        Harness Test;
        Captured<UpgradeResult> Result;
        Test.Instance->UpgradeGuest(std::nullopt, nullptr, CancellationToken(), Result.Callback());
        EXPECT_EQ(ErrorKind::LoginRequired, Result.Kind());
    }
}

AUTH4_TEST(UpgradeOpensTheHostedPageAndReplacesTheGuest)
{
    Harness Test;
    REQUIRE_TRUE(Test.SignInGuest());
    std::vector<std::string> Script = {"authorization_pending", "approve"};
    Test.Transport->Handler = [&Script](const RecordedRequest& Request)
    {
        if (Request.Path() == "/t/" + std::string(TestTenant) + "/guest/upgrade-intent")
        {
            // AUTH4D-343: the page URI carries the browser verifier in its fragment.
            return Respond(200, IntentJson(std::string(Origin) + "/login/upgrade?tenant_id=x&intent=gui_" + std::string(40, 'a') +
                                           "#verifier=" + std::string(43, 'v')));
        }

        const std::string Step = Script.front();
        Script.erase(Script.begin());
        return Step == "approve"
                   ? Respond(200, TokenJson("at_up", "rt_up", "\"user_id\":\"usr_guest\",\"identity\":{\"identity_id\":\"idn_1\",\"provider\":\"steam\"}"))
                   : Respond(400, "{\"error\":\"authorization_pending\",\"interval\":7}");
    };

    std::vector<UpgradeStage> Stages;
    Captured<UpgradeResult> Result;
    Test.Instance->UpgradeGuest(
        Provider::Steam,
        [&Stages](const UpgradeProgress& Progress) { Stages.push_back(Progress.Stage); },
        CancellationToken(),
        Result.Callback());
    Test.Loop.RunUntil([&Result]() { return Result.Done(); });

    REQUIRE_TRUE(Result.Ok());
    EXPECT_EQ(std::string("usr_guest"), Result.Value->Value().NewSession.UserId);
    EXPECT_TRUE(!Result.Value->Value().NewSession.bIsGuest);
    EXPECT_EQ(std::string("steam"), Result.Value->Value().Identity.Provider);
    REQUIRE_TRUE(Test.Launcher->Opened.size() == 1);
    EXPECT_EQ(std::string(Origin) + "/login/upgrade?tenant_id=x&intent=gui_" + std::string(40, 'a') +
                  "&provider=steam#verifier=" + std::string(43, 'v'),
              Test.Launcher->Opened[0]);
    EXPECT_TRUE(Test.Launcher->Opened[0].find("gps_") == std::string::npos);

    const auto& Requests = Test.Transport->Requests;
    const auto& Create = Requests[1];
    EXPECT_EQ(std::string("Bearer at_guest"), Create.Header("Authorization"));
    EXPECT_EQ(std::string("gps_") + std::string(43, 'b'), Requests[2].Field("poll_secret"));
    EXPECT_TRUE(Requests[2].Header("Authorization").empty());
    // The server's interval (7 s) replaces the minimum after authorization_pending.
    EXPECT_EQ(5.0, Requests[2].SentAt - Create.SentAt);
    EXPECT_EQ(7.0, Requests[3].SentAt - Requests[2].SentAt);

    REQUIRE_TRUE(Stages.size() >= 3);
    EXPECT_TRUE(Stages.front() == UpgradeStage::OpeningBrowser);
    EXPECT_TRUE(Stages.back() == UpgradeStage::Completed);

    Captured<std::string> Token;
    Test.Instance->GetAccessToken(Token.Callback());
    EXPECT_EQ(std::string("at_up"), Token.Value->Value());
    EXPECT_TRUE(Test.NoTokensInUrls());
}

AUTH4_TEST(UpgradeRejectsAnUpgradePageOnAnotherOrigin)
{
    Harness Test;
    REQUIRE_TRUE(Test.SignInGuest());
    Test.Transport->Handler = [](const RecordedRequest&)
    {
        return Respond(200, IntentJson("https://auth.example.test@evil.example/login/upgrade?intent=x"));
    };
    Captured<UpgradeResult> Result;
    Test.Instance->UpgradeGuest(std::nullopt, nullptr, CancellationToken(), Result.Callback());
    Test.Loop.RunUntil([&Result]() { return Result.Done(); });
    EXPECT_EQ(ErrorKind::InvalidResponse, Result.Kind());
    EXPECT_TRUE(Test.Launcher->Opened.empty());
}

AUTH4_TEST(UpgradeConflictKeepsTheGuest)
{
    Harness Test;
    REQUIRE_TRUE(Test.SignInGuest());
    Test.Transport->Handler = [](const RecordedRequest& Request)
    {
        return Request.Path().find("/token") == std::string::npos
                   ? Respond(200, IntentJson(std::string(Origin) + "/login/upgrade?intent=x"))
                   : Respond(400, "{\"error\":\"identity_in_use\"}");
    };
    Captured<UpgradeResult> Result;
    Test.Instance->UpgradeGuest(std::nullopt, nullptr, CancellationToken(), Result.Callback());
    Test.Loop.RunUntil([&Result]() { return Result.Done(); });
    EXPECT_EQ(ErrorKind::UpgradeConflict, Result.Kind());
    EXPECT_TRUE(Test.Instance->CurrentSession()->bIsGuest);

    // The in-flight guard is released, so the player can try another account.
    Captured<UpgradeResult> Retry;
    Test.Instance->UpgradeGuest(std::nullopt, nullptr, CancellationToken(), Retry.Callback());
    Test.Loop.RunUntil([&Retry]() { return Retry.Done(); });
    EXPECT_EQ(ErrorKind::UpgradeConflict, Retry.Kind());
}

AUTH4_TEST(UpgradeThatChangesTheUserIsRevoked)
{
    Harness Test;
    REQUIRE_TRUE(Test.SignInGuest());
    Test.Transport->Handler = [](const RecordedRequest& Request)
    {
        if (Request.Path() == "/oauth/revoke")
        {
            return Respond(200, "{}");
        }

        return Request.Path().find("/token") == std::string::npos
                   ? Respond(200, IntentJson(std::string(Origin) + "/login/upgrade?intent=x"))
                   : Respond(200, TokenJson("at_other", "rt_other", "\"user_id\":\"usr_other\",\"identity\":{\"identity_id\":\"idn_1\",\"provider\":\"email\"}"));
    };
    Captured<UpgradeResult> Result;
    Test.Instance->UpgradeGuest(std::nullopt, nullptr, CancellationToken(), Result.Callback());
    Test.Loop.RunUntil([&Result]() { return Result.Done(); });
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });

    EXPECT_EQ(ErrorKind::InvalidResponse, Result.Kind());
    EXPECT_TRUE(!Test.Instance->CurrentSession().has_value());
    EXPECT_EQ(std::string("rt_other"), Test.Transport->Requests.back().Field("token"));
}

AUTH4_TEST(SignOutDuringUpgradeWins)
{
    Harness Test;
    REQUIRE_TRUE(Test.SignInGuest());
    Test.Transport->Handler = [](const RecordedRequest& Request)
    {
        if (Request.Path() == "/oauth/revoke")
        {
            return Respond(200, "{}");
        }

        return Request.Path().find("/token") == std::string::npos
                   ? Respond(200, IntentJson(std::string(Origin) + "/login/upgrade?intent=x"))
                   : Respond(200, TokenJson("at_up", "rt_up", "\"user_id\":\"usr_guest\",\"identity\":{\"identity_id\":\"idn_1\",\"provider\":\"email\"}"));
    };
    Captured<UpgradeResult> Result;
    Test.Instance->UpgradeGuest(std::nullopt, nullptr, CancellationToken(), Result.Callback());
    Test.Loop.RunUntil([&Test]() { return !Test.Launcher->Opened.empty(); });
    Captured<bool> SignedOut;
    Test.Instance->SignOut(SignedOut.Callback());
    Test.Loop.RunUntil([&Result]() { return Result.Done(); });
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });

    EXPECT_EQ(ErrorKind::InvalidState, Result.Kind());
    EXPECT_TRUE(!Test.Instance->CurrentSession().has_value());
    EXPECT_EQ(std::string("rt_up"), Test.Transport->Requests.back().Field("token"));
}

AUTH4_TEST(UpgradeCancellationStopsPolling)
{
    Harness Test;
    REQUIRE_TRUE(Test.SignInGuest());
    Test.Transport->Handler = [](const RecordedRequest& Request)
    {
        return Request.Path().find("/token") == std::string::npos
                   ? Respond(200, IntentJson(std::string(Origin) + "/login/upgrade?intent=x"))
                   : Respond(400, "{\"error\":\"authorization_pending\"}");
    };
    CancellationSource Cancel;
    Captured<UpgradeResult> Result;
    Test.Instance->UpgradeGuest(std::nullopt, nullptr, Cancel.Token(), Result.Callback());
    Test.Loop.Advance(12);
    Cancel.Cancel();
    Test.Loop.RunUntil([&Result]() { return Result.Done(); });
    EXPECT_EQ(ErrorKind::Cancelled, Result.Kind());
    EXPECT_TRUE(Test.Instance->CurrentSession()->bIsGuest);
}

AUTH4_TEST(DestroyedClientDropsCallbacks)
{
    Harness Test;
    Test.Transport->Handler = [](const RecordedRequest&) { return Respond(201, TokenJson("at_g", "rt_g", "\"user_id\":\"usr_g\"")); };
    bool bCalled = false;
    Test.Instance->SignInAsGuest([&bCalled](const Result<Session>&) { bCalled = true; });
    Test.Instance.reset();
    Test.Loop.RunUntil([&Test]() { return Test.Loop.Pending() == 0; });
    EXPECT_TRUE(!bCalled);
}

// ----- JSON and URLs -----

AUTH4_TEST(JsonParsesTheWireShapes)
{
    const auto Parsed = Json::ParseObject(
        "{ \"a\" : \"x\\\"y\\u00e9\\ud83d\\ude00\", \"n\": 300, \"f\": -1.5e2, \"o\": {\"p\": \"q\"}, \"arr\": [1, {\"k\": []}], \"b\": true, \"z\": null }");
    REQUIRE_TRUE(Parsed != nullptr);
    EXPECT_EQ(std::string("x\"y\xC3\xA9\xF0\x9F\x98\x80"), Json::GetString(Parsed.get(), "a").value_or(""));
    EXPECT_EQ(300.0, Json::GetNumber(Parsed.get(), "n").value_or(0));
    EXPECT_EQ(-150.0, Json::GetNumber(Parsed.get(), "f").value_or(0));
    EXPECT_EQ(std::string("q"), Json::GetString(Json::GetObject(Parsed.get(), "o"), "p").value_or(""));
    EXPECT_TRUE(!Json::GetString(Parsed.get(), "n").has_value());

    EXPECT_TRUE(Json::ParseObject("") == nullptr);
    EXPECT_TRUE(Json::ParseObject("[]") == nullptr);
    EXPECT_TRUE(Json::ParseObject("{\"a\":1,}") == nullptr);
    EXPECT_TRUE(Json::ParseObject("{\"a\":\"\\ud83d\"}") == nullptr);
    EXPECT_TRUE(Json::ParseObject("{\"a\":01x}") == nullptr);
    EXPECT_TRUE(Json::ParseObject("{} trailing") == nullptr);

    const auto RoundTrip = Json::ParseObject(Json::SerializeStrings({{"k", "a\"b\\c\n"}}));
    EXPECT_EQ(std::string("a\"b\\c\n"), Json::GetString(RoundTrip.get(), "k").value_or(""));
}

AUTH4_TEST(UrlChecksOrigins)
{
    EXPECT_EQ(std::string("https://auth.example.test"), Url::NormalizeOrigin("HTTPS://Auth.Example.Test:443/").value_or(""));
    EXPECT_EQ(std::string("http://127.0.0.1:8787"), Url::NormalizeOrigin("http://127.0.0.1:8787").value_or(""));
    EXPECT_EQ(std::string("http://localhost:8787"), Url::NormalizeOrigin("http://localhost:8787").value_or(""));
    EXPECT_TRUE(!Url::NormalizeOrigin("http://auth.example.test").has_value());
    EXPECT_TRUE(!Url::NormalizeOrigin("https://auth.example.test?x=1").has_value());
    EXPECT_TRUE(!Url::NormalizeOrigin("https://auth.example.test#x").has_value());
    EXPECT_TRUE(!Url::NormalizeOrigin("ftp://auth.example.test").has_value());

    EXPECT_TRUE(Url::IsSameOrigin("https://auth.example.test/device?x=1", "https://auth.example.test"));
    EXPECT_TRUE(!Url::IsSameOrigin("https://auth.example.test.evil.example/device", "https://auth.example.test"));
    EXPECT_TRUE(!Url::IsSameOrigin("https://auth.example.test@evil.example/device", "https://auth.example.test"));
    EXPECT_TRUE(!Url::IsSameOrigin("https://auth.example.test:444/device", "https://auth.example.test"));
    EXPECT_TRUE(!Url::IsSameOrigin("https://auth.example.test/de vice", "https://auth.example.test"));

    EXPECT_EQ(std::string("a%20b%2Bc%3D~"), Url::Escape("a b+c=~"));
    EXPECT_EQ(std::string("x=1&y=a%26b"), Url::FormEncode({{"x", "1"}, {"y", "a&b"}}));
}
