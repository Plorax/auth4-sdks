#pragma once

#include "CoreMinimal.h"
#include "Engine/DeveloperSettings.h"

#include "Auth4Settings.generated.h"

/**
 * Project Settings > Plugins > auth4.dev. Stored in Config/DefaultGame.ini. These are public values:
 * native clients never hold a client secret, so nothing here needs protecting.
 */
UCLASS(Config = Game, DefaultConfig, meta = (DisplayName = "auth4.dev"))
class AUTH4_API UAuth4Settings : public UDeveloperSettings
{
	GENERATED_BODY()

public:
	UAuth4Settings();

	/** Tenant ID from the console, for example ten_xxxxxxxxxxxxxxxx. */
	UPROPERTY(Config, EditAnywhere, Category = "Client")
	FString TenantId;

	/** Native client ID from the console, for example cli_xxxxxxxxxxxxxxxx. */
	UPROPERTY(Config, EditAnywhere, Category = "Client")
	FString ClientId;

	/** Auth API origin. Plain http is accepted only for loopback hosts during local development. */
	UPROPERTY(Config, EditAnywhere, Category = "Client")
	FString AuthOrigin;

	/** Scopes requested by device sign-in when a node passes none. Must include openid. */
	UPROPERTY(Config, EditAnywhere, Category = "Client")
	FString DefaultScope;

	/** Refresh this many seconds before the access token expires. */
	UPROPERTY(Config, EditAnywhere, Category = "Advanced", meta = (ClampMin = "0"))
	float AccessTokenRefreshMarginSeconds;

	/** Upper bound on token requests for one device code or upgrade. */
	UPROPERTY(Config, EditAnywhere, Category = "Advanced", meta = (ClampMin = "1"))
	int32 MaxPollAttempts;

	virtual FName GetCategoryName() const override { return TEXT("Plugins"); }
};
