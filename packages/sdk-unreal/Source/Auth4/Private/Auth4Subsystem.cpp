#include "Auth4Subsystem.h"

#include "Auth4Settings.h"
#include "Auth4UnrealPlatform.h"
#include "Engine/Engine.h"
#include "Engine/GameInstance.h"
#include "Engine/World.h"

void UAuth4Subsystem::Deinitialize()
{
	CancelPendingOperations();
	// Pending callbacks are dropped once the client is gone.
	Client.reset();
	Super::Deinitialize();
}

UAuth4Subsystem* UAuth4Subsystem::Get(const UObject* WorldContextObject)
{
	const UWorld* World = GEngine ? GEngine->GetWorldFromContextObject(WorldContextObject, EGetWorldErrorMode::ReturnNull) : nullptr;
	const UGameInstance* GameInstance = World ? World->GetGameInstance() : nullptr;
	return GameInstance ? GameInstance->GetSubsystem<UAuth4Subsystem>() : nullptr;
}

bool UAuth4Subsystem::SetSecureStorage(TSharedPtr<IAuth4SecureStorage> Storage)
{
	if (Client)
	{
		return false;
	}

	SecureStorage = Storage;
	return true;
}

std::shared_ptr<Auth4::Client> UAuth4Subsystem::GetClient(Auth4::Error& OutError)
{
	if (Client)
	{
		return Client;
	}

	const UAuth4Settings* Settings = GetDefault<UAuth4Settings>();
	Auth4::ClientOptions Options;
	Options.TenantId = Auth4Unreal::ToStdString(Settings->TenantId.TrimStartAndEnd());
	Options.ClientId = Auth4Unreal::ToStdString(Settings->ClientId.TrimStartAndEnd());
	Options.AuthOrigin = Auth4Unreal::ToStdString(Settings->AuthOrigin.TrimStartAndEnd());
	Options.DefaultScope = Auth4Unreal::ToStdString(Settings->DefaultScope);
	Options.AccessTokenRefreshMarginSeconds = Settings->AccessTokenRefreshMarginSeconds;
	Options.MaxPollAttempts = Settings->MaxPollAttempts;
	Options.Transport = std::make_shared<FAuth4HttpTransport>();
	Options.Scheduler = std::make_shared<FAuth4TickerScheduler>();
	Options.BrowserLauncher = std::make_shared<FAuth4PlatformBrowserLauncher>();
	if (SecureStorage.IsValid())
	{
		Options.SecureStorage = std::make_shared<FAuth4SecureStorageBridge>(SecureStorage.ToSharedRef());
	}

	auto Created = Auth4::Client::Create(Options);
	if (!Created.Ok())
	{
		OutError = Created.GetError();
		return nullptr;
	}

	Client = Created.Value();
	TWeakObjectPtr<UAuth4Subsystem> WeakThis(this);
	Client->SetSessionChangedListener([WeakThis](const Auth4::Session* Session)
	{
		if (UAuth4Subsystem* Self = WeakThis.Get())
		{
			Self->OnSessionChanged.Broadcast(Session != nullptr, Session ? FAuth4Session::From(*Session) : FAuth4Session());
		}
	});
	return Client;
}

Auth4::CancellationToken UAuth4Subsystem::OperationToken() const
{
	if (!Cancellation)
	{
		Cancellation = MakeUnique<Auth4::CancellationSource>();
	}

	return Cancellation->Token();
}

bool UAuth4Subsystem::IsSignedIn() const
{
	return Client && Client->CurrentSession().has_value();
}

bool UAuth4Subsystem::GetCurrentSession(FAuth4Session& Session) const
{
	const auto Current = Client ? Client->CurrentSession() : std::nullopt;
	if (!Current)
	{
		Session = FAuth4Session();
		return false;
	}

	Session = FAuth4Session::From(*Current);
	return true;
}

bool UAuth4Subsystem::IsRefreshPersistent() const
{
	return SecureStorage.IsValid();
}

void UAuth4Subsystem::CancelPendingOperations()
{
	if (Cancellation)
	{
		// A fresh source for later operations; the old one fails everything that holds its token.
		TUniquePtr<Auth4::CancellationSource> Previous = MoveTemp(Cancellation);
		Previous->Cancel();
	}
}
