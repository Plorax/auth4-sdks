// Blueprint-facing value types. They carry no tokens; use the Get Access Token node when calling
// your game server.
#pragma once

#include "CoreMinimal.h"
#include "Auth4Core/Auth4Types.h"

#include "Auth4Types.generated.h"

UENUM(BlueprintType)
enum class EAuth4ErrorKind : uint8
{
	None,
	/** An OAuth error returned by the API; Code holds the error string. */
	Protocol,
	/** The API could not be reached. Retry later. */
	Network,
	InvalidResponse,
	/** A setting or argument is invalid, for example a missing tenant ID in Project Settings. */
	InvalidArgument,
	/** The call does not fit the current session, for example signing in while signed in. */
	InvalidState,
	/** No session is active. */
	LoginRequired,
	/** The refresh credential was rejected; the player must sign in again. */
	SessionExpired,
	DeviceDenied,
	DeviceExpired,
	/** The account already belongs to another player. Nothing was merged; the guest is unchanged. */
	UpgradeConflict,
	UpgradeExpired,
	/** The player chose Not now on the hosted page. */
	UpgradeDenied,
	Cancelled,
	/** No system browser on this platform. */
	NotSupported,
};

/** A failure. Show players your own wording based on Kind; never show server text. */
USTRUCT(BlueprintType)
struct AUTH4_API FAuth4Error
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	EAuth4ErrorKind Kind = EAuth4ErrorKind::None;

	/** OAuth error code or a client code such as network_error. For logs and branching only. */
	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FString Code;

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	int32 StatusCode = 0;

	/** True for failures that may succeed if retried later. */
	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	bool bIsTransient = false;

	static FAuth4Error From(const Auth4::Error& Error);
};

UENUM(BlueprintType)
enum class EAuth4Provider : uint8
{
	/** The hosted page shows every enabled method. */
	Any,
	Discord,
	Steam,
	Epic,
	Google,
	Apple,
	Microsoft,
};

UENUM(BlueprintType)
enum class EAuth4UpgradeStage : uint8
{
	OpeningBrowser,
	WaitingForPlayer,
	Completed,
};

/** A snapshot of the signed-in session. */
USTRUCT(BlueprintType)
struct AUTH4_API FAuth4Session
{
	GENERATED_BODY()

	/** The tenant user ID for guest and upgraded sessions; empty after device sign-in. */
	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FString UserId;

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FString SessionId;

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FString Scope;

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	bool bIsGuest = false;

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FDateTime AccessTokenExpiresAt;

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	bool bCanRefresh = false;

	/** True only when a secure storage adapter holds the refresh credential. */
	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	bool bIsRefreshPersistent = false;

	static FAuth4Session From(const Auth4::Session& Session);
};

/** Show UserCode and VerificationUri to the player. VerificationUriComplete suits a QR code. */
USTRUCT(BlueprintType)
struct AUTH4_API FAuth4DeviceCode
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FString UserCode;

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FString VerificationUri;

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FString VerificationUriComplete;

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FDateTime ExpiresAt;
};

USTRUCT(BlueprintType)
struct AUTH4_API FAuth4UpgradeProgress
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	EAuth4UpgradeStage Stage = EAuth4UpgradeStage::OpeningBrowser;

	/** The hosted page, so the game can offer "Open again" if the player closed it. */
	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FString UpgradeUri;

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FDateTime ExpiresAt;
};

USTRUCT(BlueprintType)
struct AUTH4_API FAuth4LinkedIdentity
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FString IdentityId;

	/** email, discord or steam. */
	UPROPERTY(BlueprintReadOnly, Category = "auth4.dev")
	FString Provider;
};

namespace Auth4Unreal
{
	AUTH4_API FString ToFString(const std::string& Value);
	AUTH4_API std::string ToStdString(const FString& Value);
	AUTH4_API FDateTime ToDateTime(double UnixSeconds);
}
