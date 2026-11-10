#include "Auth4Settings.h"

UAuth4Settings::UAuth4Settings()
	: AuthOrigin(TEXT("https://auth.auth4.dev"))
	, DefaultScope(TEXT("openid offline_access"))
	, AccessTokenRefreshMarginSeconds(30.0f)
	, MaxPollAttempts(240)
{
}
