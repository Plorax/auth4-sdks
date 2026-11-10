#include "Auth4Types.h"

namespace Auth4Unreal
{
	FString ToFString(const std::string& Value)
	{
		return FString(UTF8_TO_TCHAR(Value.c_str()));
	}

	std::string ToStdString(const FString& Value)
	{
		return std::string(TCHAR_TO_UTF8(*Value));
	}

	FDateTime ToDateTime(double UnixSeconds)
	{
		// FDateTime ends at the year 9999; an upgrade without a deadline reports the maximum.
		constexpr double LastUnixSecond = 253402300799.0;
		if (UnixSeconds >= LastUnixSecond)
		{
			return FDateTime::MaxValue();
		}

		return FDateTime::FromUnixTimestamp(static_cast<int64>(FMath::Max(0.0, UnixSeconds)));
	}
}

namespace
{
	EAuth4ErrorKind ToErrorKind(Auth4::ErrorKind Kind)
	{
		switch (Kind)
		{
		case Auth4::ErrorKind::None: return EAuth4ErrorKind::None;
		case Auth4::ErrorKind::Protocol: return EAuth4ErrorKind::Protocol;
		case Auth4::ErrorKind::Network: return EAuth4ErrorKind::Network;
		case Auth4::ErrorKind::InvalidResponse: return EAuth4ErrorKind::InvalidResponse;
		case Auth4::ErrorKind::InvalidArgument: return EAuth4ErrorKind::InvalidArgument;
		case Auth4::ErrorKind::InvalidState: return EAuth4ErrorKind::InvalidState;
		case Auth4::ErrorKind::LoginRequired: return EAuth4ErrorKind::LoginRequired;
		case Auth4::ErrorKind::SessionExpired: return EAuth4ErrorKind::SessionExpired;
		case Auth4::ErrorKind::DeviceDenied: return EAuth4ErrorKind::DeviceDenied;
		case Auth4::ErrorKind::DeviceExpired: return EAuth4ErrorKind::DeviceExpired;
		case Auth4::ErrorKind::UpgradeConflict: return EAuth4ErrorKind::UpgradeConflict;
		case Auth4::ErrorKind::UpgradeExpired: return EAuth4ErrorKind::UpgradeExpired;
		case Auth4::ErrorKind::UpgradeDenied: return EAuth4ErrorKind::UpgradeDenied;
		case Auth4::ErrorKind::Cancelled: return EAuth4ErrorKind::Cancelled;
		case Auth4::ErrorKind::NotSupported: return EAuth4ErrorKind::NotSupported;
		}

		return EAuth4ErrorKind::Protocol;
	}
}

FAuth4Error FAuth4Error::From(const Auth4::Error& Error)
{
	FAuth4Error Out;
	Out.Kind = ToErrorKind(Error.Kind);
	Out.Code = Auth4Unreal::ToFString(Error.Code);
	Out.StatusCode = Error.StatusCode;
	Out.bIsTransient = Error.IsTransient();
	return Out;
}

FAuth4Session FAuth4Session::From(const Auth4::Session& Session)
{
	FAuth4Session Out;
	Out.UserId = Auth4Unreal::ToFString(Session.UserId);
	Out.SessionId = Auth4Unreal::ToFString(Session.SessionId);
	Out.Scope = Auth4Unreal::ToFString(Session.Scope);
	Out.bIsGuest = Session.bIsGuest;
	Out.AccessTokenExpiresAt = Auth4Unreal::ToDateTime(Session.AccessTokenExpiresAt);
	Out.bCanRefresh = Session.bCanRefresh;
	Out.bIsRefreshPersistent = Session.bIsRefreshPersistent;
	return Out;
}
