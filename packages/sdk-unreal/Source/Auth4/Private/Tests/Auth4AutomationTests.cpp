// In-engine automation tests for the Unreal layer (AUTH4D-218). They run in the editor under
// Session Frontend > Automation, or headless through Tests/run-engine-tests.mjs, which builds the
// plugin with RunUAT and passes -Auth4MockOrigin so the transport test can reach Tests/mock-server.mjs.
// The protocol itself is covered outside the engine by Tests/run-tests.mjs.
#include "Misc/AutomationTest.h"

#if WITH_DEV_AUTOMATION_TESTS

#include "Auth4Core/Auth4Client.h"
#include "Auth4Settings.h"
#include "Auth4Types.h"
#include "Auth4UnrealPlatform.h"
#include "Misc/CommandLine.h"
#include "Misc/Parse.h"
#include "Tests/AutomationCommon.h"

namespace
{
	constexpr EAutomationTestFlags Auth4TestFlags = EAutomationTestFlags::EditorContext | EAutomationTestFlags::EngineFilter;

	// Must match TENANT and CLIENT in Tests/mock-server.mjs.
	constexpr const char* MockTenant = "ten_mockTenant0000000001";
	constexpr const char* MockClient = "cli_mockNative000000001";

	Auth4::ClientOptions EngineOptions(const std::string& Origin)
	{
		Auth4::ClientOptions Options;
		Options.TenantId = MockTenant;
		Options.ClientId = MockClient;
		Options.AuthOrigin = Origin;
		Options.Transport = std::make_shared<FAuth4HttpTransport>();
		Options.Scheduler = std::make_shared<FAuth4TickerScheduler>();
		return Options;
	}
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FAuth4ErrorConversionTest, "Auth4.Types.ErrorConversion", Auth4TestFlags)

bool FAuth4ErrorConversionTest::RunTest(const FString& Parameters)
{
	Auth4::Error Conflict;
	Conflict.Kind = Auth4::ErrorKind::UpgradeConflict;
	Conflict.Code = "identity_already_linked";
	Conflict.Description = "server text that players never see";
	Conflict.StatusCode = 409;
	const FAuth4Error Converted = FAuth4Error::From(Conflict);
	TestEqual(TEXT("Kind"), Converted.Kind, EAuth4ErrorKind::UpgradeConflict);
	TestEqual(TEXT("Code"), Converted.Code, FString(TEXT("identity_already_linked")));
	TestEqual(TEXT("StatusCode"), Converted.StatusCode, 409);
	TestFalse(TEXT("A conflict is not transient"), Converted.bIsTransient);

	Auth4::Error Unavailable;
	Unavailable.Kind = Auth4::ErrorKind::Protocol;
	Unavailable.Code = "temporarily_unavailable";
	Unavailable.StatusCode = 503;
	TestTrue(TEXT("A 503 is transient"), FAuth4Error::From(Unavailable).bIsTransient);

	// Every core kind has a Blueprint kind with the same name.
	const Auth4::ErrorKind Kinds[] = {
		Auth4::ErrorKind::None, Auth4::ErrorKind::Protocol, Auth4::ErrorKind::Network, Auth4::ErrorKind::InvalidResponse,
		Auth4::ErrorKind::InvalidArgument, Auth4::ErrorKind::InvalidState, Auth4::ErrorKind::LoginRequired,
		Auth4::ErrorKind::SessionExpired, Auth4::ErrorKind::DeviceDenied, Auth4::ErrorKind::DeviceExpired,
		Auth4::ErrorKind::UpgradeConflict, Auth4::ErrorKind::UpgradeExpired, Auth4::ErrorKind::UpgradeDenied,
		Auth4::ErrorKind::Cancelled, Auth4::ErrorKind::NotSupported,
	};
	for (const Auth4::ErrorKind Kind : Kinds)
	{
		Auth4::Error Error;
		Error.Kind = Kind;
		TestEqual(TEXT("Kind index"), static_cast<int32>(FAuth4Error::From(Error).Kind), static_cast<int32>(Kind));
	}

	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FAuth4ConversionsTest, "Auth4.Types.Conversions", Auth4TestFlags)

bool FAuth4ConversionsTest::RunTest(const FString& Parameters)
{
	const FString Text = TEXT("Spieler éè 你好");
	TestEqual(TEXT("UTF-8 round trip"), Auth4Unreal::ToFString(Auth4Unreal::ToStdString(Text)), Text);

	TestEqual(TEXT("Unix time"), Auth4Unreal::ToDateTime(1700000000.0), FDateTime::FromUnixTimestamp(1700000000));
	TestEqual(TEXT("Negative time clamps to the epoch"), Auth4Unreal::ToDateTime(-5.0), FDateTime(1970, 1, 1));
	TestEqual(TEXT("No deadline reports the maximum"), Auth4Unreal::ToDateTime(1e18), FDateTime::MaxValue());

	Auth4::Session Session;
	Session.UserId = "usr_1";
	Session.SessionId = "ses_1";
	Session.Scope = "openid offline_access";
	Session.bIsGuest = true;
	Session.AccessTokenExpiresAt = 1700000300.0;
	Session.bCanRefresh = true;
	const FAuth4Session Converted = FAuth4Session::From(Session);
	TestEqual(TEXT("UserId"), Converted.UserId, FString(TEXT("usr_1")));
	TestEqual(TEXT("SessionId"), Converted.SessionId, FString(TEXT("ses_1")));
	TestTrue(TEXT("Guest"), Converted.bIsGuest);
	TestTrue(TEXT("Can refresh"), Converted.bCanRefresh);
	TestFalse(TEXT("Not persistent without storage"), Converted.bIsRefreshPersistent);
	TestEqual(TEXT("Expiry"), Converted.AccessTokenExpiresAt, FDateTime::FromUnixTimestamp(1700000300));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FAuth4SettingsTest, "Auth4.Settings.Registration", Auth4TestFlags)

bool FAuth4SettingsTest::RunTest(const FString& Parameters)
{
	// The values themselves come from the project's DefaultGame.ini, so only the shape is checked.
	const UClass* Class = UAuth4Settings::StaticClass();
	const UAuth4Settings* Settings = GetDefault<UAuth4Settings>();
	TestEqual(TEXT("Shown under Plugins"), Settings->GetCategoryName(), FName(TEXT("Plugins")));
	TestTrue(TEXT("Stored in DefaultGame.ini"), Class->HasAllClassFlags(CLASS_Config | CLASS_DefaultConfig));
	TestEqual(TEXT("Config file"), Class->ClassConfigName, FName(TEXT("Game")));
	for (const TCHAR* Name : {TEXT("TenantId"), TEXT("ClientId"), TEXT("AuthOrigin"), TEXT("DefaultScope"), TEXT("AccessTokenRefreshMarginSeconds"), TEXT("MaxPollAttempts")})
	{
		const FProperty* Property = Class->FindPropertyByName(Name);
		TestTrue(FString::Printf(TEXT("%s is a config property"), Name), Property && Property->HasAnyPropertyFlags(CPF_Config));
	}

	TestTrue(TEXT("Default scope includes openid"), Settings->DefaultScope.Contains(TEXT("openid")));
	return true;
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FAuth4ClientOptionsTest, "Auth4.Client.Options", Auth4TestFlags)

bool FAuth4ClientOptionsTest::RunTest(const FString& Parameters)
{
	TestTrue(TEXT("HTTPS origin"), Auth4::Client::Create(EngineOptions("https://auth.auth4.dev")).Ok());
	TestTrue(TEXT("Loopback HTTP origin"), Auth4::Client::Create(EngineOptions("http://127.0.0.1:8787")).Ok());

	const auto PlainHttp = Auth4::Client::Create(EngineOptions("http://auth.example.test"));
	TestFalse(TEXT("Plain HTTP to a remote host"), PlainHttp.Ok());
	TestEqual(TEXT("Kind"), FAuth4Error::From(PlainHttp.GetError()).Kind, EAuth4ErrorKind::InvalidArgument);

	Auth4::ClientOptions NoTenant = EngineOptions("https://auth.auth4.dev");
	NoTenant.TenantId.clear();
	TestFalse(TEXT("Missing tenant"), Auth4::Client::Create(NoTenant).Ok());

	const double Now = FAuth4TickerScheduler().Now();
	TestTrue(TEXT("Scheduler uses Unix seconds"), FMath::Abs(Now - static_cast<double>(FDateTime::UtcNow().ToUnixTimestamp())) < 5.0);
	return true;
}

namespace
{
	/** Shared by the latent steps of the transport test. Lives until the last step finishes. */
	struct FAuth4MockRun
	{
		std::shared_ptr<Auth4::Client> Client;
		std::shared_ptr<FAuth4HttpTransport> Transport = std::make_shared<FAuth4HttpTransport>();
		FString Origin;
		bool bDone = false;
		FString Failure;
		FString MockState;
		double Deadline = 0;
	};

	void Control(const TSharedRef<FAuth4MockRun>& Run, const char* Path, std::function<void(const Auth4::HttpResponse&)> Done)
	{
		Auth4::HttpRequest Request;
		Request.Url = Auth4Unreal::ToStdString(Run->Origin) + Path;
		Request.Headers = {{"Content-Type", "application/json"}};
		Request.Body = "{}";
		Run->Transport->Send(Request, [Done](Auth4::HttpResponse Response) { Done(Response); });
	}

	void Fail(const TSharedRef<FAuth4MockRun>& Run, const FString& Step, const Auth4::Error& Error)
	{
		// The code only: server descriptions stay out of logs and reports.
		Run->Failure = FString::Printf(TEXT("%s failed: %s (%d)"), *Step, *Auth4Unreal::ToFString(Error.Code), Error.StatusCode);
		Run->bDone = true;
	}
}

IMPLEMENT_SIMPLE_AUTOMATION_TEST(FAuth4EngineTransportTest, "Auth4.Engine.GuestRefreshSignOut", Auth4TestFlags)

bool FAuth4EngineTransportTest::RunTest(const FString& Parameters)
{
	FString Origin;
	if (!FParse::Value(FCommandLine::Get(), TEXT("Auth4MockOrigin="), Origin) || Origin.IsEmpty())
	{
		AddWarning(TEXT("Skipped: start Tests/mock-server.mjs and pass -Auth4MockOrigin=http://127.0.0.1:<port>, or use Tests/run-engine-tests.mjs."));
		return true;
	}

	TSharedRef<FAuth4MockRun> Run = MakeShared<FAuth4MockRun>();
	Run->Origin = Origin;
	Run->Deadline = FPlatformTime::Seconds() + 30.0;
	auto Created = Auth4::Client::Create(EngineOptions(Auth4Unreal::ToStdString(Origin)));
	if (!TestTrue(TEXT("Client created"), Created.Ok()))
	{
		return false;
	}
	Run->Client = Created.Value();

	// Guest sign-in, a refresh rotation, an access token and sign-out, all through FHttpModule and
	// the core ticker. Each step continues from the previous callback on the game thread.
	Control(Run, "/__mock/reset", [Run](const Auth4::HttpResponse& Reset)
	{
		if (Reset.StatusCode != 200)
		{
			Run->Failure = TEXT("The mock server did not answer the reset.");
			Run->bDone = true;
			return;
		}

		Run->Client->SignInAsGuest([Run](const Auth4::Result<Auth4::Session>& Guest)
		{
			if (!Guest.Ok() || !Guest.Value().bIsGuest || Guest.Value().UserId.empty())
			{
				return Fail(Run, TEXT("SignInAsGuest"), Guest.GetError());
			}

			Run->Client->Refresh([Run, UserId = Guest.Value().UserId](const Auth4::Result<Auth4::Session>& Refreshed)
			{
				if (!Refreshed.Ok() || Refreshed.Value().UserId != UserId)
				{
					return Fail(Run, TEXT("Refresh"), Refreshed.GetError());
				}

				Run->Client->GetAccessToken([Run](const Auth4::Result<std::string>& Token)
				{
					if (!Token.Ok() || Token.Value().empty())
					{
						return Fail(Run, TEXT("GetAccessToken"), Token.GetError());
					}

					Run->Client->SignOut([Run](const Auth4::Result<bool>& SignedOut)
					{
						if (!SignedOut.Ok() || !SignedOut.Value() || Run->Client->CurrentSession().has_value())
						{
							return Fail(Run, TEXT("SignOut"), SignedOut.GetError());
						}

						Control(Run, "/__mock/state", [Run](const Auth4::HttpResponse& State)
						{
							Run->MockState = Auth4Unreal::ToFString(State.Body);
							Run->bDone = true;
						});
					});
				});
			});
		});
	});

	ADD_LATENT_AUTOMATION_COMMAND(FFunctionLatentCommand([this, Run]()
	{
		if (!Run->bDone && FPlatformTime::Seconds() < Run->Deadline)
		{
			return false;
		}

		if (!Run->bDone)
		{
			AddError(TEXT("Timed out waiting for the mock server."));
		}
		else if (!Run->Failure.IsEmpty())
		{
			AddError(Run->Failure);
		}
		else
		{
			// The mock counts contract violations: content types, tenant scoping, tokens in URLs.
			TestTrue(TEXT("No contract violations"), Run->MockState.Contains(TEXT("\"violations\":0")));
			TestTrue(TEXT("One refresh"), Run->MockState.Contains(TEXT("\"refreshes\":1")));
			TestTrue(TEXT("Sign-out revoked the family"), Run->MockState.Contains(TEXT("\"revokedFamilies\":1")));
		}

		Run->Client.reset();
		return true;
	}));
	return true;
}

#endif
