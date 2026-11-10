// End-to-end protocol tests over real HTTP against the local mock server (Tests/mock-server.mjs).
// The mock enforces the wire contract (content types, tenant scoping, no tokens in URLs, refresh
// rotation with reuse detection) and answers with a scripted sequence of outcomes per test.
#include "Auth4Json.h"
#include "TestSupport.h"

#include <utility>

using namespace Auth4;
using namespace Auth4Tests;

namespace
{
    struct MockHarness
    {
        EventLoop Loop;
        std::string Origin;
        std::shared_ptr<LoopbackTransport> Transport = std::make_shared<LoopbackTransport>(Loop);
        std::shared_ptr<RecordingLauncher> Launcher = std::make_shared<RecordingLauncher>();

        explicit MockHarness(const std::string& InOrigin) : Origin(InOrigin) {}

        std::shared_ptr<Client> NewClient(std::shared_ptr<ISecureStorage> Storage = nullptr)
        {
            ClientOptions Options;
            Options.TenantId = TestTenant;
            Options.ClientId = TestClient;
            Options.AuthOrigin = Origin;
            Options.DefaultScope = "openid profile offline_access";
            Options.Transport = Transport;
            Options.Scheduler = std::shared_ptr<IScheduler>(&Loop, [](IScheduler*) {});
            Options.SecureStorage = std::move(Storage);
            Options.BrowserLauncher = Launcher;
            return Client::Create(Options).Value();
        }

        /// Resets the mock and sets the scripted outcomes for this test.
        bool Reset(const std::string& ScriptJson)
        {
            return Control("/__mock/reset", ScriptJson).StatusCode == 200;
        }

        std::shared_ptr<Json::Object> State()
        {
            return Json::ParseObject(Control("/__mock/state", "{}").Body);
        }

        double StateNumber(const char* Key) { return Json::GetNumber(State().get(), Key).value_or(-1); }

        HttpResponse Control(const std::string& Path, const std::string& Body)
        {
            HttpRequest Request;
            Request.Url = Origin + Path;
            Request.Headers = {{"Content-Type", "application/json"}};
            Request.Body = Body;
            return LoopbackExchange(Request);
        }

        template <typename T>
        bool Wait(Captured<T>& Result)
        {
            return Loop.RunUntil([&Result]() { return Result.Done(); });
        }
    };
}

AUTH4_MOCK_TEST(MockDeviceSignInRefreshAndSignOut)
{
    MockHarness Mock(Context.MockOrigin);
    REQUIRE_TRUE(Mock.Reset("{\"device\":[\"authorization_pending\",\"slow_down\",\"approve\"]}"));
    auto Instance = Mock.NewClient();

    std::string VerificationUri;
    Captured<Session> SignedIn;
    Instance->SignInWithDevice(
        [&VerificationUri](const DeviceAuthorization& Authorization) { VerificationUri = Authorization.VerificationUri; },
        "",
        CancellationToken(),
        SignedIn.Callback());
    REQUIRE_TRUE(Mock.Wait(SignedIn));
    REQUIRE_TRUE(SignedIn.Ok());
    EXPECT_EQ(Mock.Origin + "/device", VerificationUri);
    EXPECT_EQ(std::string("openid profile offline_access"), SignedIn.Value->Value().Scope);
    EXPECT_EQ(4.0, Mock.StateNumber("requests"));

    Captured<Session> Refreshed;
    Instance->Refresh(Refreshed.Callback());
    REQUIRE_TRUE(Mock.Wait(Refreshed));
    EXPECT_TRUE(Refreshed.Ok());

    Captured<std::string> Token;
    Instance->GetAccessToken(Token.Callback());
    REQUIRE_TRUE(Mock.Wait(Token));
    EXPECT_TRUE(Token.Ok());

    Captured<bool> SignedOut;
    Instance->SignOut(SignedOut.Callback());
    REQUIRE_TRUE(Mock.Wait(SignedOut));
    EXPECT_TRUE(SignedOut.Ok() && SignedOut.Value->Value());
    EXPECT_EQ(1.0, Mock.StateNumber("revokedFamilies"));
    EXPECT_EQ(0.0, Mock.StateNumber("violations"));
}

AUTH4_MOCK_TEST(MockDeviceDenied)
{
    MockHarness Mock(Context.MockOrigin);
    REQUIRE_TRUE(Mock.Reset("{\"device\":[\"authorization_pending\",\"access_denied\"]}"));
    auto Instance = Mock.NewClient();
    Captured<Session> Result;
    Instance->SignInWithDevice(nullptr, "", CancellationToken(), Result.Callback());
    REQUIRE_TRUE(Mock.Wait(Result));
    EXPECT_EQ(ErrorKind::DeviceDenied, Result.Kind());
    EXPECT_EQ(0.0, Mock.StateNumber("violations"));
}

AUTH4_MOCK_TEST(MockGuestRefreshRotationAndReuseDetection)
{
    MockHarness Mock(Context.MockOrigin);
    REQUIRE_TRUE(Mock.Reset("{}"));
    auto Instance = Mock.NewClient();
    Captured<Session> Guest;
    Instance->SignInAsGuest(Guest.Callback());
    REQUIRE_TRUE(Mock.Wait(Guest));
    REQUIRE_TRUE(Guest.Ok());
    EXPECT_TRUE(Guest.Value->Value().bIsGuest);
    const std::string UserId = Guest.Value->Value().UserId;
    EXPECT_TRUE(UserId.rfind("usr_", 0) == 0);

    // Three concurrent callers present the refresh token once; a second presentation would be
    // treated as reuse and revoke the family.
    Mock.Loop.Advance(290);
    Captured<std::string> First;
    Captured<std::string> Second;
    Captured<Session> Third;
    Instance->GetAccessToken(First.Callback());
    Instance->GetAccessToken(Second.Callback());
    Instance->Refresh(Third.Callback());
    REQUIRE_TRUE(Mock.Loop.RunUntil([&]() { return First.Done() && Second.Done() && Third.Done(); }));
    EXPECT_TRUE(First.Ok() && Second.Ok() && Third.Ok());
    EXPECT_EQ(1.0, Mock.StateNumber("refreshes"));
    EXPECT_EQ(UserId, Third.Value->Value().UserId);

    // Another party replays a rotated token: the mock revokes the family, so the next rotation by
    // the game fails and clears the session.
    REQUIRE_TRUE(Mock.Control("/__mock/replay-rotated", "{}").StatusCode == 200);
    Captured<Session> AfterReplay;
    Instance->Refresh(AfterReplay.Callback());
    REQUIRE_TRUE(Mock.Wait(AfterReplay));
    EXPECT_EQ(ErrorKind::SessionExpired, AfterReplay.Kind());
    EXPECT_TRUE(!Instance->CurrentSession().has_value());
    EXPECT_EQ(0.0, Mock.StateNumber("violations"));
}

AUTH4_MOCK_TEST(MockGuestUpgradeThroughAnIntent)
{
    MockHarness Mock(Context.MockOrigin);
    REQUIRE_TRUE(Mock.Reset("{\"upgrade\":[\"authorization_pending\",\"slow_down\",\"approve\"],\"upgradeProvider\":\"steam\"}"));
    auto Instance = Mock.NewClient();
    Captured<Session> Guest;
    Instance->SignInAsGuest(Guest.Callback());
    REQUIRE_TRUE(Mock.Wait(Guest));
    REQUIRE_TRUE(Guest.Ok());

    Captured<UpgradeResult> Upgraded;
    Instance->UpgradeGuest(Provider::Steam, nullptr, CancellationToken(), Upgraded.Callback());
    REQUIRE_TRUE(Mock.Wait(Upgraded));
    REQUIRE_TRUE(Upgraded.Ok());
    EXPECT_EQ(Guest.Value->Value().UserId, Upgraded.Value->Value().NewSession.UserId);
    EXPECT_TRUE(!Upgraded.Value->Value().NewSession.bIsGuest);
    EXPECT_EQ(std::string("steam"), Upgraded.Value->Value().Identity.Provider);
    REQUIRE_TRUE(Mock.Launcher->Opened.size() == 1);
    EXPECT_TRUE(Mock.Launcher->Opened[0].rfind(Mock.Origin + "/login/upgrade?", 0) == 0);
    EXPECT_TRUE(Mock.Launcher->Opened[0].find("provider=steam") != std::string::npos);
    // The upgrade revoked the guest session's refresh family on the server.
    EXPECT_EQ(1.0, Mock.StateNumber("revokedFamilies"));

    Captured<Session> Refreshed;
    Instance->Refresh(Refreshed.Callback());
    REQUIRE_TRUE(Mock.Wait(Refreshed));
    EXPECT_TRUE(Refreshed.Ok() && !Refreshed.Value->Value().bIsGuest);
    EXPECT_EQ(0.0, Mock.StateNumber("violations"));
}

AUTH4_MOCK_TEST(MockGuestUpgradeProviderHints)
{
    for (const auto& [ProviderValue, Name] : std::vector<std::pair<Provider, std::string>>{
             {Provider::Epic, "epic"},
             {Provider::Google, "google"},
             {Provider::Apple, "apple"},
             {Provider::Microsoft, "microsoft"},
         })
    {
        MockHarness Mock(Context.MockOrigin);
        REQUIRE_TRUE(Mock.Reset("{\"upgrade\":[\"approve\"]}"));
        auto Instance = Mock.NewClient();
        Captured<Session> Guest;
        Instance->SignInAsGuest(Guest.Callback());
        REQUIRE_TRUE(Mock.Wait(Guest));
        REQUIRE_TRUE(Guest.Ok());

        Captured<UpgradeResult> Upgraded;
        Instance->UpgradeGuest(ProviderValue, nullptr, CancellationToken(), Upgraded.Callback());
        REQUIRE_TRUE(Mock.Wait(Upgraded));
        REQUIRE_TRUE(Upgraded.Ok());
        REQUIRE_TRUE(Mock.Launcher->Opened.size() == 1);
        EXPECT_TRUE(Mock.Launcher->Opened[0].find("provider=" + Name) != std::string::npos);
    }
}

AUTH4_MOCK_TEST(MockGuestUpgradeConflict)
{
    MockHarness Mock(Context.MockOrigin);
    REQUIRE_TRUE(Mock.Reset("{\"upgrade\":[\"identity_in_use\"]}"));
    auto Instance = Mock.NewClient();
    Captured<Session> Guest;
    Instance->SignInAsGuest(Guest.Callback());
    REQUIRE_TRUE(Mock.Wait(Guest));
    Captured<UpgradeResult> Upgraded;
    Instance->UpgradeGuest(std::nullopt, nullptr, CancellationToken(), Upgraded.Callback());
    REQUIRE_TRUE(Mock.Wait(Upgraded));
    EXPECT_EQ(ErrorKind::UpgradeConflict, Upgraded.Kind());
    REQUIRE_TRUE(Instance->CurrentSession().has_value());
    EXPECT_TRUE(Instance->CurrentSession()->bIsGuest);
    EXPECT_EQ(0.0, Mock.StateNumber("violations"));
}

AUTH4_MOCK_TEST(MockSessionSurvivesARestartWithSecureStorage)
{
    MockHarness Mock(Context.MockOrigin);
    REQUIRE_TRUE(Mock.Reset("{}"));
    auto Storage = std::make_shared<MemoryStorage>(Mock.Loop);
    std::string UserId;
    {
        auto First = Mock.NewClient(Storage);
        Captured<Session> Guest;
        First->SignInAsGuest(Guest.Callback());
        REQUIRE_TRUE(Mock.Wait(Guest));
        REQUIRE_TRUE(Guest.Ok());
        EXPECT_TRUE(Guest.Value->Value().bIsRefreshPersistent);
        UserId = Guest.Value->Value().UserId;
        Mock.Loop.RunUntil([&Mock]() { return Mock.Loop.Pending() == 0; });
    }

    auto Second = Mock.NewClient(Storage);
    Captured<bool> Restored;
    Second->TryRestoreSession(Restored.Callback());
    REQUIRE_TRUE(Mock.Wait(Restored));
    REQUIRE_TRUE(Restored.Ok());
    EXPECT_TRUE(Restored.Value->Value());
    EXPECT_EQ(UserId, Second->CurrentSession()->UserId);
    EXPECT_TRUE(Second->CurrentSession()->bIsGuest);

    Captured<bool> SignedOut;
    Second->SignOut(SignedOut.Callback());
    REQUIRE_TRUE(Mock.Wait(SignedOut));
    Mock.Loop.RunUntil([&Mock]() { return Mock.Loop.Pending() == 0; });

    auto Third = Mock.NewClient(Storage);
    Captured<bool> Nothing;
    Third->TryRestoreSession(Nothing.Callback());
    REQUIRE_TRUE(Mock.Wait(Nothing));
    REQUIRE_TRUE(Nothing.Ok());
    EXPECT_TRUE(!Nothing.Value->Value());
    EXPECT_EQ(0.0, Mock.StateNumber("violations"));
}
