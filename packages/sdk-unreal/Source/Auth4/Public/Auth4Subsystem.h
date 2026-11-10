#pragma once

#include <memory>

#include "CoreMinimal.h"
#include "Auth4Core/Auth4Client.h"
#include "Auth4SecureStorage.h"
#include "Auth4Types.h"
#include "Subsystems/GameInstanceSubsystem.h"

#include "Auth4Subsystem.generated.h"

DECLARE_DYNAMIC_MULTICAST_DELEGATE_TwoParams(FAuth4SessionChangedEvent, bool, bSignedIn, const FAuth4Session&, Session);

/**
 * Owns the auth4.dev client for the game instance. The client is created on first use from
 * Project Settings > Plugins > auth4.dev, and every callback runs on the game thread. Blueprint
 * graphs use the async nodes in Auth4AsyncActions.h; C++ can call GetClient directly.
 */
UCLASS()
class AUTH4_API UAuth4Subsystem : public UGameInstanceSubsystem
{
	GENERATED_BODY()

public:
	virtual void Deinitialize() override;

	/** The subsystem of the world context's game instance, or null. */
	static UAuth4Subsystem* Get(const UObject* WorldContextObject);

	/**
	 * Persists the refresh credential through Storage. Call before the first auth4.dev call, for
	 * example in your GameInstance's Init. Returns false once the client exists.
	 */
	bool SetSecureStorage(TSharedPtr<IAuth4SecureStorage> Storage);

	/** The client, created on first use. Null with OutError set when the settings are invalid. */
	std::shared_ptr<Auth4::Client> GetClient(Auth4::Error& OutError);

	/** A token that CancelPendingOperations cancels. */
	Auth4::CancellationToken OperationToken() const;

	UFUNCTION(BlueprintPure, Category = "auth4.dev")
	bool IsSignedIn() const;

	/** False when signed out. */
	UFUNCTION(BlueprintPure, Category = "auth4.dev")
	bool GetCurrentSession(FAuth4Session& Session) const;

	/** True only when a secure storage adapter was supplied. */
	UFUNCTION(BlueprintPure, Category = "auth4.dev")
	bool IsRefreshPersistent() const;

	/**
	 * Stops waiting for device sign-ins and guest upgrades that are polling. They fail with
	 * Cancelled. A player may still finish a guest upgrade in the browser.
	 */
	UFUNCTION(BlueprintCallable, Category = "auth4.dev")
	void CancelPendingOperations();

	/** Raised after sign-in, refresh, upgrade or sign-out. */
	UPROPERTY(BlueprintAssignable, Category = "auth4.dev")
	FAuth4SessionChangedEvent OnSessionChanged;

private:
	std::shared_ptr<Auth4::Client> Client;
	TSharedPtr<IAuth4SecureStorage> SecureStorage;
	/** Created on first use; replaced each time pending operations are cancelled. */
	mutable TUniquePtr<Auth4::CancellationSource> Cancellation;
};
