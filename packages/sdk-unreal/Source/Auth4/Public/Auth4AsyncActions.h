// Blueprint latent nodes for the auth4.dev client. Each node runs one operation and fires exactly
// one of its result pins. Failure pins carry an FAuth4Error: branch on Kind and show your own text.
#pragma once

#include "CoreMinimal.h"
#include "Auth4Types.h"
#include "Kismet/BlueprintAsyncActionBase.h"

#include "Auth4AsyncActions.generated.h"

DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAuth4SessionPin, const FAuth4Session&, Session);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAuth4ErrorPin, const FAuth4Error&, Error);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAuth4DeviceCodePin, const FAuth4DeviceCode&, DeviceCode);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAuth4UpgradeProgressPin, const FAuth4UpgradeProgress&, Progress);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_TwoParams(FAuth4UpgradePin, const FAuth4Session&, Session, const FAuth4LinkedIdentity&, Identity);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAuth4AccessTokenPin, const FString&, AccessToken);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FAuth4SignedOutPin, bool, bRevoked);
DECLARE_DYNAMIC_MULTICAST_DELEGATE(FAuth4EmptyPin);

class UAuth4Subsystem;

/** Shared lifetime handling: the node stays alive until it fires a result pin. */
UCLASS(Abstract)
class AUTH4_API UAuth4AsyncAction : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()

protected:
	/** The subsystem, or null after firing Fail with InvalidArgument. */
	UAuth4Subsystem* Begin();
	virtual void Fail(const FAuth4Error& Error) {}

	TWeakObjectPtr<UObject> WorldContext;
};

/** Device sign-in (RFC 8628): shows a code the player enters on another device. */
UCLASS()
class AUTH4_API UAuth4SignInWithDeviceAction : public UAuth4AsyncAction
{
	GENERATED_BODY()

public:
	/** Scope may be empty to use the project default. Show the code from On User Code. */
	UFUNCTION(BlueprintCallable, Category = "auth4.dev", meta = (BlueprintInternalUseOnly = "true", WorldContext = "WorldContextObject"))
	static UAuth4SignInWithDeviceAction* SignInWithDevice(UObject* WorldContextObject, const FString& Scope);

	UPROPERTY(BlueprintAssignable)
	FAuth4DeviceCodePin OnUserCode;

	UPROPERTY(BlueprintAssignable)
	FAuth4SessionPin OnSuccess;

	UPROPERTY(BlueprintAssignable)
	FAuth4ErrorPin OnFailure;

	virtual void Activate() override;

protected:
	virtual void Fail(const FAuth4Error& Error) override;

private:
	FString Scope;
};

/** Starts playing as a new guest. Fails with InvalidState when a session is already active. */
UCLASS()
class AUTH4_API UAuth4SignInAsGuestAction : public UAuth4AsyncAction
{
	GENERATED_BODY()

public:
	UFUNCTION(BlueprintCallable, Category = "auth4.dev", meta = (BlueprintInternalUseOnly = "true", WorldContext = "WorldContextObject"))
	static UAuth4SignInAsGuestAction* SignInAsGuest(UObject* WorldContextObject);

	UPROPERTY(BlueprintAssignable)
	FAuth4SessionPin OnSuccess;

	UPROPERTY(BlueprintAssignable)
	FAuth4ErrorPin OnFailure;

	virtual void Activate() override;

protected:
	virtual void Fail(const FAuth4Error& Error) override;
};

/**
 * Saves a guest's progress: opens the hosted page in the system browser, where the player links an
 * email address or an enabled social provider, and waits for them to finish. The user ID stays the same.
 */
UCLASS()
class AUTH4_API UAuth4UpgradeGuestAction : public UAuth4AsyncAction
{
	GENERATED_BODY()

public:
	/** PreferredProvider makes the page offer that provider first; Any shows every method. */
	UFUNCTION(BlueprintCallable, Category = "auth4.dev", meta = (BlueprintInternalUseOnly = "true", WorldContext = "WorldContextObject"))
	static UAuth4UpgradeGuestAction* UpgradeGuest(UObject* WorldContextObject, EAuth4Provider PreferredProvider);

	UPROPERTY(BlueprintAssignable)
	FAuth4UpgradeProgressPin OnProgress;

	UPROPERTY(BlueprintAssignable)
	FAuth4UpgradePin OnSuccess;

	UPROPERTY(BlueprintAssignable)
	FAuth4ErrorPin OnFailure;

	virtual void Activate() override;

protected:
	virtual void Fail(const FAuth4Error& Error) override;

private:
	EAuth4Provider PreferredProvider = EAuth4Provider::Any;
};

/**
 * A valid access token for your game server, refreshed first when it is about to expire. Send it
 * only in an Authorization header; never print, log or save it.
 */
UCLASS()
class AUTH4_API UAuth4GetAccessTokenAction : public UAuth4AsyncAction
{
	GENERATED_BODY()

public:
	UFUNCTION(BlueprintCallable, Category = "auth4.dev", meta = (BlueprintInternalUseOnly = "true", WorldContext = "WorldContextObject"))
	static UAuth4GetAccessTokenAction* GetAccessToken(UObject* WorldContextObject);

	UPROPERTY(BlueprintAssignable)
	FAuth4AccessTokenPin OnSuccess;

	UPROPERTY(BlueprintAssignable)
	FAuth4ErrorPin OnFailure;

	virtual void Activate() override;

protected:
	virtual void Fail(const FAuth4Error& Error) override;
};

/** Rotates the refresh token now. Usually unnecessary: Get Access Token refreshes when needed. */
UCLASS()
class AUTH4_API UAuth4RefreshSessionAction : public UAuth4AsyncAction
{
	GENERATED_BODY()

public:
	UFUNCTION(BlueprintCallable, Category = "auth4.dev", meta = (BlueprintInternalUseOnly = "true", WorldContext = "WorldContextObject"))
	static UAuth4RefreshSessionAction* RefreshSession(UObject* WorldContextObject);

	UPROPERTY(BlueprintAssignable)
	FAuth4SessionPin OnSuccess;

	UPROPERTY(BlueprintAssignable)
	FAuth4ErrorPin OnFailure;

	virtual void Activate() override;

protected:
	virtual void Fail(const FAuth4Error& Error) override;
};

/**
 * Restores the previous session at startup. Needs a secure storage adapter; otherwise always Nothing Stored.
 * Restored fires only once a usable access token exists. A transient failure fires Failure and keeps the
 * stored credential, so run the node again to retry.
 */
UCLASS()
class AUTH4_API UAuth4RestoreSessionAction : public UAuth4AsyncAction
{
	GENERATED_BODY()

public:
	UFUNCTION(BlueprintCallable, Category = "auth4.dev", meta = (BlueprintInternalUseOnly = "true", WorldContext = "WorldContextObject"))
	static UAuth4RestoreSessionAction* RestoreSession(UObject* WorldContextObject);

	UPROPERTY(BlueprintAssignable)
	FAuth4SessionPin OnRestored;

	UPROPERTY(BlueprintAssignable)
	FAuth4EmptyPin OnNothingStored;

	UPROPERTY(BlueprintAssignable)
	FAuth4ErrorPin OnFailure;

	virtual void Activate() override;

protected:
	virtual void Fail(const FAuth4Error& Error) override;
};

/** Revokes the session and clears it locally. bRevoked is false when the server could not confirm. */
UCLASS()
class AUTH4_API UAuth4SignOutAction : public UAuth4AsyncAction
{
	GENERATED_BODY()

public:
	UFUNCTION(BlueprintCallable, Category = "auth4.dev", meta = (BlueprintInternalUseOnly = "true", WorldContext = "WorldContextObject"))
	static UAuth4SignOutAction* SignOut(UObject* WorldContextObject);

	UPROPERTY(BlueprintAssignable)
	FAuth4SignedOutPin OnCompleted;

	virtual void Activate() override;
};
