// Secure storage for the refresh credential. The plugin ships no implementation: persistence is
// opt-in, and each platform has its own protected store (iOS Keychain, Android Keystore-backed
// encrypted storage, Windows DPAPI, a console vendor's protected save API). Without an adapter the
// session lives in memory and players sign in again after a restart.
#pragma once

#include "CoreMinimal.h"
#include "Templates/Function.h"

/**
 * Implement in C++ and pass to UAuth4Subsystem::SetSecureStorage before the first auth4.dev call.
 * Implementations must encrypt at rest with an OS-protected key and must never write to SaveGame
 * slots, config files, plain files or logs. Call each Done exactly once, on the game thread.
 */
class AUTH4_API IAuth4SecureStorage
{
public:
	virtual ~IAuth4SecureStorage() = default;

	/** bFound is false when the key is absent; bOk is false when storage is unavailable. */
	virtual void Read(const FString& Key, TFunction<void(bool bOk, bool bFound, const FString& Value)> Done) = 0;

	virtual void Write(const FString& Key, const FString& Value, TFunction<void(bool bOk)> Done) = 0;

	virtual void Delete(const FString& Key, TFunction<void(bool bOk)> Done) = 0;
};
