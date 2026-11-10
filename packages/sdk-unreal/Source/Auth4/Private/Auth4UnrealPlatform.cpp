#include "Auth4UnrealPlatform.h"

#include "Auth4Types.h"
#include "Containers/Ticker.h"
#include "HAL/PlatformProcess.h"
#include "HttpModule.h"
#include "Interfaces/IHttpRequest.h"
#include "Interfaces/IHttpResponse.h"

namespace
{
	constexpr float Auth4HttpTimeoutSeconds = 30.0f;
}

void FAuth4HttpTransport::Send(const Auth4::HttpRequest& Request, std::function<void(Auth4::HttpResponse)> Done)
{
	TSharedRef<IHttpRequest, ESPMode::ThreadSafe> HttpRequest = FHttpModule::Get().CreateRequest();
	HttpRequest->SetURL(Auth4Unreal::ToFString(Request.Url));
	HttpRequest->SetVerb(Auth4Unreal::ToFString(Request.Method));
	for (const auto& Header : Request.Headers)
	{
		HttpRequest->SetHeader(Auth4Unreal::ToFString(Header.first), Auth4Unreal::ToFString(Header.second));
	}

	TArray<uint8> Body;
	Body.Append(reinterpret_cast<const uint8*>(Request.Body.data()), static_cast<int32>(Request.Body.size()));
	HttpRequest->SetContent(Body);
	HttpRequest->SetTimeout(Auth4HttpTimeoutSeconds);
	HttpRequest->OnProcessRequestComplete().BindLambda(
		[Done](FHttpRequestPtr, FHttpResponsePtr Response, bool bConnectedSuccessfully)
		{
			Auth4::HttpResponse Out;
			if (!bConnectedSuccessfully || !Response.IsValid())
			{
				Out.bNetworkError = true;
			}
			else
			{
				Out.StatusCode = Response->GetResponseCode();
				const TArray<uint8>& Content = Response->GetContent();
				Out.Body.assign(reinterpret_cast<const char*>(Content.GetData()), static_cast<size_t>(Content.Num()));
			}

			Done(std::move(Out));
		});
	HttpRequest->ProcessRequest();
}

double FAuth4TickerScheduler::Now()
{
	return static_cast<double>((FDateTime::UtcNow() - FDateTime(1970, 1, 1)).GetTotalSeconds());
}

void FAuth4TickerScheduler::After(double Seconds, std::function<void()> Callback)
{
	FTSTicker::GetCoreTicker().AddTicker(
		FTickerDelegate::CreateLambda([Callback](float)
		{
			Callback();
			return false;
		}),
		static_cast<float>(FMath::Max(0.0, Seconds)));
}

bool FAuth4PlatformBrowserLauncher::IsSupported() const
{
	return PLATFORM_DESKTOP || PLATFORM_IOS || PLATFORM_ANDROID;
}

void FAuth4PlatformBrowserLauncher::Open(const std::string& Url)
{
	FString Error;
	FPlatformProcess::LaunchURL(*Auth4Unreal::ToFString(Url), nullptr, &Error);
}

void FAuth4SecureStorageBridge::Read(const std::string& Key, std::function<void(bool, bool, std::string)> Done)
{
	Storage->Read(Auth4Unreal::ToFString(Key), [Done](bool bOk, bool bFound, const FString& Value)
	{
		Done(bOk, bFound, Auth4Unreal::ToStdString(Value));
	});
}

void FAuth4SecureStorageBridge::Write(const std::string& Key, const std::string& Value, std::function<void(bool)> Done)
{
	Storage->Write(Auth4Unreal::ToFString(Key), Auth4Unreal::ToFString(Value), [Done](bool bOk) { Done(bOk); });
}

void FAuth4SecureStorageBridge::Delete(const std::string& Key, std::function<void(bool)> Done)
{
	Storage->Delete(Auth4Unreal::ToFString(Key), [Done](bool bOk) { Done(bOk); });
}
