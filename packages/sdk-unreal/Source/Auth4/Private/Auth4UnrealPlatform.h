// Engine implementations of the protocol core's platform services.
#pragma once

#include "CoreMinimal.h"
#include "Auth4Core/Auth4Platform.h"
#include "Auth4SecureStorage.h"

/** HTTPS through FHttpModule. Completions run on the game thread. Never logs bodies or headers. */
class FAuth4HttpTransport final : public Auth4::ITransport
{
public:
	virtual void Send(const Auth4::HttpRequest& Request, std::function<void(Auth4::HttpResponse)> Done) override;
};

/** Wall clock and the core ticker, which runs on the game thread even while the game is paused. */
class FAuth4TickerScheduler final : public Auth4::IScheduler
{
public:
	virtual double Now() override;
	virtual void After(double Seconds, std::function<void()> Callback) override;
};

/** The system browser through FPlatformProcess::LaunchURL, on desktop and mobile platforms. */
class FAuth4PlatformBrowserLauncher final : public Auth4::IBrowserLauncher
{
public:
	virtual bool IsSupported() const override;
	virtual void Open(const std::string& Url) override;
};

/** Adapts a game's IAuth4SecureStorage to the core interface. */
class FAuth4SecureStorageBridge final : public Auth4::ISecureStorage
{
public:
	explicit FAuth4SecureStorageBridge(TSharedRef<IAuth4SecureStorage> InStorage) : Storage(InStorage) {}

	virtual void Read(const std::string& Key, std::function<void(bool, bool, std::string)> Done) override;
	virtual void Write(const std::string& Key, const std::string& Value, std::function<void(bool)> Done) override;
	virtual void Delete(const std::string& Key, std::function<void(bool)> Done) override;

private:
	TSharedRef<IAuth4SecureStorage> Storage;
};
