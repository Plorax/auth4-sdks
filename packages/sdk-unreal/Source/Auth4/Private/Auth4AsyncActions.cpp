#include "Auth4AsyncActions.h"

#include "Auth4Subsystem.h"

namespace
{
	/** Creates a node that stays alive with the game instance until it fires a result pin. */
	template <typename T>
	T* NewAuth4Action(UObject* WorldContextObject)
	{
		T* Action = NewObject<T>();
		Action->RegisterWithGameInstance(WorldContextObject);
		return Action;
	}
}

UAuth4Subsystem* UAuth4AsyncAction::Begin()
{
	UAuth4Subsystem* Subsystem = UAuth4Subsystem::Get(WorldContext.Get());
	if (Subsystem == nullptr)
	{
		FAuth4Error Error;
		Error.Kind = EAuth4ErrorKind::InvalidState;
		Error.Code = TEXT("no_game_instance");
		Fail(Error);
		return nullptr;
	}

	Auth4::Error Invalid;
	if (!Subsystem->GetClient(Invalid))
	{
		Fail(FAuth4Error::From(Invalid));
		return nullptr;
	}

	return Subsystem;
}

// ----- Sign in with device -----

UAuth4SignInWithDeviceAction* UAuth4SignInWithDeviceAction::SignInWithDevice(UObject* WorldContextObject, const FString& Scope)
{
	auto* Action = NewAuth4Action<UAuth4SignInWithDeviceAction>(WorldContextObject);
	Action->WorldContext = WorldContextObject;
	Action->Scope = Scope;
	return Action;
}

void UAuth4SignInWithDeviceAction::Activate()
{
	UAuth4Subsystem* Subsystem = Begin();
	if (Subsystem == nullptr)
	{
		return;
	}

	Auth4::Error Unused;
	TWeakObjectPtr<UAuth4SignInWithDeviceAction> WeakThis(this);
	Subsystem->GetClient(Unused)->SignInWithDevice(
		[WeakThis](const Auth4::DeviceAuthorization& Authorization)
		{
			if (UAuth4SignInWithDeviceAction* Self = WeakThis.Get())
			{
				FAuth4DeviceCode Code;
				Code.UserCode = Auth4Unreal::ToFString(Authorization.UserCode);
				Code.VerificationUri = Auth4Unreal::ToFString(Authorization.VerificationUri);
				Code.VerificationUriComplete = Auth4Unreal::ToFString(Authorization.VerificationUriComplete);
				Code.ExpiresAt = Auth4Unreal::ToDateTime(Authorization.ExpiresAt);
				Self->OnUserCode.Broadcast(Code);
			}
		},
		Auth4Unreal::ToStdString(Scope.TrimStartAndEnd()),
		Subsystem->OperationToken(),
		[WeakThis](const Auth4::Result<Auth4::Session>& Result)
		{
			UAuth4SignInWithDeviceAction* Self = WeakThis.Get();
			if (Self == nullptr)
			{
				return;
			}

			if (Result.Ok())
			{
				Self->OnSuccess.Broadcast(FAuth4Session::From(Result.Value()));
				Self->SetReadyToDestroy();
			}
			else
			{
				Self->Fail(FAuth4Error::From(Result.GetError()));
			}
		});
}

void UAuth4SignInWithDeviceAction::Fail(const FAuth4Error& Error)
{
	OnFailure.Broadcast(Error);
	SetReadyToDestroy();
}

// ----- Sign in as guest -----

UAuth4SignInAsGuestAction* UAuth4SignInAsGuestAction::SignInAsGuest(UObject* WorldContextObject)
{
	auto* Action = NewAuth4Action<UAuth4SignInAsGuestAction>(WorldContextObject);
	Action->WorldContext = WorldContextObject;
	return Action;
}

void UAuth4SignInAsGuestAction::Activate()
{
	UAuth4Subsystem* Subsystem = Begin();
	if (Subsystem == nullptr)
	{
		return;
	}

	Auth4::Error Unused;
	TWeakObjectPtr<UAuth4SignInAsGuestAction> WeakThis(this);
	Subsystem->GetClient(Unused)->SignInAsGuest([WeakThis](const Auth4::Result<Auth4::Session>& Result)
	{
		UAuth4SignInAsGuestAction* Self = WeakThis.Get();
		if (Self == nullptr)
		{
			return;
		}

		if (Result.Ok())
		{
			Self->OnSuccess.Broadcast(FAuth4Session::From(Result.Value()));
			Self->SetReadyToDestroy();
		}
		else
		{
			Self->Fail(FAuth4Error::From(Result.GetError()));
		}
	});
}

void UAuth4SignInAsGuestAction::Fail(const FAuth4Error& Error)
{
	OnFailure.Broadcast(Error);
	SetReadyToDestroy();
}

// ----- Upgrade guest -----

UAuth4UpgradeGuestAction* UAuth4UpgradeGuestAction::UpgradeGuest(UObject* WorldContextObject, EAuth4Provider PreferredProvider)
{
	auto* Action = NewAuth4Action<UAuth4UpgradeGuestAction>(WorldContextObject);
	Action->WorldContext = WorldContextObject;
	Action->PreferredProvider = PreferredProvider;
	return Action;
}

void UAuth4UpgradeGuestAction::Activate()
{
	UAuth4Subsystem* Subsystem = Begin();
	if (Subsystem == nullptr)
	{
		return;
	}

	std::optional<Auth4::Provider> Hint;
	if (PreferredProvider == EAuth4Provider::Discord)
	{
		Hint = Auth4::Provider::Discord;
	}
	else if (PreferredProvider == EAuth4Provider::Steam)
	{
		Hint = Auth4::Provider::Steam;
	}
	else if (PreferredProvider == EAuth4Provider::Epic)
	{
		Hint = Auth4::Provider::Epic;
	}
	else if (PreferredProvider == EAuth4Provider::Google)
	{
		Hint = Auth4::Provider::Google;
	}
	else if (PreferredProvider == EAuth4Provider::Apple)
	{
		Hint = Auth4::Provider::Apple;
	}
	else if (PreferredProvider == EAuth4Provider::Microsoft)
	{
		Hint = Auth4::Provider::Microsoft;
	}

	Auth4::Error Unused;
	TWeakObjectPtr<UAuth4UpgradeGuestAction> WeakThis(this);
	Subsystem->GetClient(Unused)->UpgradeGuest(
		Hint,
		[WeakThis](const Auth4::UpgradeProgress& Progress)
		{
			if (UAuth4UpgradeGuestAction* Self = WeakThis.Get())
			{
				FAuth4UpgradeProgress Out;
				Out.Stage = Progress.Stage == Auth4::UpgradeStage::OpeningBrowser   ? EAuth4UpgradeStage::OpeningBrowser
				            : Progress.Stage == Auth4::UpgradeStage::WaitingForPlayer ? EAuth4UpgradeStage::WaitingForPlayer
				                                                                      : EAuth4UpgradeStage::Completed;
				Out.UpgradeUri = Auth4Unreal::ToFString(Progress.UpgradeUri);
				Out.ExpiresAt = Auth4Unreal::ToDateTime(Progress.ExpiresAt);
				Self->OnProgress.Broadcast(Out);
			}
		},
		Subsystem->OperationToken(),
		[WeakThis](const Auth4::Result<Auth4::UpgradeResult>& Result)
		{
			UAuth4UpgradeGuestAction* Self = WeakThis.Get();
			if (Self == nullptr)
			{
				return;
			}

			if (Result.Ok())
			{
				FAuth4LinkedIdentity Identity;
				Identity.IdentityId = Auth4Unreal::ToFString(Result.Value().Identity.IdentityId);
				Identity.Provider = Auth4Unreal::ToFString(Result.Value().Identity.Provider);
				Self->OnSuccess.Broadcast(FAuth4Session::From(Result.Value().NewSession), Identity);
				Self->SetReadyToDestroy();
			}
			else
			{
				Self->Fail(FAuth4Error::From(Result.GetError()));
			}
		});
}

void UAuth4UpgradeGuestAction::Fail(const FAuth4Error& Error)
{
	OnFailure.Broadcast(Error);
	SetReadyToDestroy();
}

// ----- Get access token -----

UAuth4GetAccessTokenAction* UAuth4GetAccessTokenAction::GetAccessToken(UObject* WorldContextObject)
{
	auto* Action = NewAuth4Action<UAuth4GetAccessTokenAction>(WorldContextObject);
	Action->WorldContext = WorldContextObject;
	return Action;
}

void UAuth4GetAccessTokenAction::Activate()
{
	UAuth4Subsystem* Subsystem = Begin();
	if (Subsystem == nullptr)
	{
		return;
	}

	Auth4::Error Unused;
	TWeakObjectPtr<UAuth4GetAccessTokenAction> WeakThis(this);
	Subsystem->GetClient(Unused)->GetAccessToken([WeakThis](const Auth4::Result<std::string>& Result)
	{
		UAuth4GetAccessTokenAction* Self = WeakThis.Get();
		if (Self == nullptr)
		{
			return;
		}

		if (Result.Ok())
		{
			Self->OnSuccess.Broadcast(Auth4Unreal::ToFString(Result.Value()));
			Self->SetReadyToDestroy();
		}
		else
		{
			Self->Fail(FAuth4Error::From(Result.GetError()));
		}
	});
}

void UAuth4GetAccessTokenAction::Fail(const FAuth4Error& Error)
{
	OnFailure.Broadcast(Error);
	SetReadyToDestroy();
}

// ----- Refresh session -----

UAuth4RefreshSessionAction* UAuth4RefreshSessionAction::RefreshSession(UObject* WorldContextObject)
{
	auto* Action = NewAuth4Action<UAuth4RefreshSessionAction>(WorldContextObject);
	Action->WorldContext = WorldContextObject;
	return Action;
}

void UAuth4RefreshSessionAction::Activate()
{
	UAuth4Subsystem* Subsystem = Begin();
	if (Subsystem == nullptr)
	{
		return;
	}

	Auth4::Error Unused;
	TWeakObjectPtr<UAuth4RefreshSessionAction> WeakThis(this);
	Subsystem->GetClient(Unused)->Refresh([WeakThis](const Auth4::Result<Auth4::Session>& Result)
	{
		UAuth4RefreshSessionAction* Self = WeakThis.Get();
		if (Self == nullptr)
		{
			return;
		}

		if (Result.Ok())
		{
			Self->OnSuccess.Broadcast(FAuth4Session::From(Result.Value()));
			Self->SetReadyToDestroy();
		}
		else
		{
			Self->Fail(FAuth4Error::From(Result.GetError()));
		}
	});
}

void UAuth4RefreshSessionAction::Fail(const FAuth4Error& Error)
{
	OnFailure.Broadcast(Error);
	SetReadyToDestroy();
}

// ----- Restore session -----

UAuth4RestoreSessionAction* UAuth4RestoreSessionAction::RestoreSession(UObject* WorldContextObject)
{
	auto* Action = NewAuth4Action<UAuth4RestoreSessionAction>(WorldContextObject);
	Action->WorldContext = WorldContextObject;
	return Action;
}

void UAuth4RestoreSessionAction::Activate()
{
	UAuth4Subsystem* Subsystem = Begin();
	if (Subsystem == nullptr)
	{
		return;
	}

	Auth4::Error Unused;
	auto Client = Subsystem->GetClient(Unused);
	TWeakObjectPtr<UAuth4RestoreSessionAction> WeakThis(this);
	std::weak_ptr<Auth4::Client> WeakClient = Client;
	Client->TryRestoreSession([WeakThis, WeakClient](const Auth4::Result<bool>& Result)
	{
		UAuth4RestoreSessionAction* Self = WeakThis.Get();
		const auto Live = WeakClient.lock();
		if (Self == nullptr || !Live)
		{
			return;
		}

		const auto Current = Live->CurrentSession();
		if (!Result.Ok())
		{
			Self->Fail(FAuth4Error::From(Result.GetError()));
			return;
		}

		if (Result.Value() && Current)
		{
			Self->OnRestored.Broadcast(FAuth4Session::From(*Current));
		}
		else
		{
			Self->OnNothingStored.Broadcast();
		}

		Self->SetReadyToDestroy();
	});
}

void UAuth4RestoreSessionAction::Fail(const FAuth4Error& Error)
{
	OnFailure.Broadcast(Error);
	SetReadyToDestroy();
}

// ----- Sign out -----

UAuth4SignOutAction* UAuth4SignOutAction::SignOut(UObject* WorldContextObject)
{
	auto* Action = NewAuth4Action<UAuth4SignOutAction>(WorldContextObject);
	Action->WorldContext = WorldContextObject;
	return Action;
}

void UAuth4SignOutAction::Activate()
{
	UAuth4Subsystem* Subsystem = Begin();
	if (Subsystem == nullptr)
	{
		// Without a client there is no session to end.
		OnCompleted.Broadcast(true);
		SetReadyToDestroy();
		return;
	}

	Auth4::Error Unused;
	TWeakObjectPtr<UAuth4SignOutAction> WeakThis(this);
	Subsystem->GetClient(Unused)->SignOut([WeakThis](const Auth4::Result<bool>& Result)
	{
		if (UAuth4SignOutAction* Self = WeakThis.Get())
		{
			Self->OnCompleted.Broadcast(Result.Ok() && Result.Value());
			Self->SetReadyToDestroy();
		}
	});
}
