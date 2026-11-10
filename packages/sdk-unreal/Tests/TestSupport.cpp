#include "TestSupport.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "Auth4Json.h"
#include "Auth4Url.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketHandle = SOCKET;
#define AUTH4_TEST_CLOSE_SOCKET closesocket
#else
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketHandle = int;
#define INVALID_SOCKET (-1)
#define AUTH4_TEST_CLOSE_SOCKET close
#endif

namespace Auth4Tests
{
    namespace
    {
        struct NamedTest
        {
            const char* Name;
            TestFunction Function;
            bool bNeedsMockServer;
        };

        std::vector<NamedTest>& Registry()
        {
            static std::vector<NamedTest> Tests;
            return Tests;
        }

        std::string LowerText(std::string Value)
        {
            for (char& Character : Value)
            {
                if (Character >= 'A' && Character <= 'Z')
                {
                    Character = static_cast<char>(Character - 'A' + 'a');
                }
            }

            return Value;
        }

        std::string UrlDecode(const std::string& Value)
        {
            std::string Out;
            for (size_t Index = 0; Index < Value.size(); ++Index)
            {
                if (Value[Index] == '%' && Index + 2 < Value.size())
                {
                    Out.push_back(static_cast<char>(std::strtol(Value.substr(Index + 1, 2).c_str(), nullptr, 16)));
                    Index += 2;
                }
                else
                {
                    Out.push_back(Value[Index] == '+' ? ' ' : Value[Index]);
                }
            }

            return Out;
        }
    }

    TestRegistration::TestRegistration(const char* Name, TestFunction Function, bool bNeedsMockServer)
    {
        Registry().push_back({Name, Function, bNeedsMockServer});
    }

    void RecordFailure(TestContext& Context, const char* File, int Line, const std::string& Message)
    {
        const char* Base = std::strrchr(File, '/');
        const char* WindowsBase = std::strrchr(File, '\\');
        Base = std::max(Base, WindowsBase);
        Context.Failures.push_back(std::string(Base ? Base + 1 : File) + ":" + std::to_string(Line) + ": " + Message);
    }

    std::string Show(const std::string& Value) { return "\"" + Value + "\""; }

    std::string Show(const char* Value) { return Show(std::string(Value)); }

    std::string Show(Auth4::ErrorKind Value) { return "ErrorKind(" + std::to_string(static_cast<int>(Value)) + ")"; }

    // ----- EventLoop -----

    void EventLoop::After(double Seconds, std::function<void()> Callback)
    {
        Tasks.push_back({Clock + std::max(0.0, Seconds), NextSequence++, std::move(Callback)});
    }

    bool EventLoop::RunOne()
    {
        if (Tasks.empty())
        {
            return false;
        }

        auto Earliest = std::min_element(Tasks.begin(), Tasks.end(), [](const Task& Left, const Task& Right)
        {
            return Left.Due < Right.Due || (Left.Due == Right.Due && Left.Sequence < Right.Sequence);
        });
        Task Next = std::move(*Earliest);
        Tasks.erase(Earliest);
        Clock = std::max(Clock, Next.Due);
        Next.Callback();
        return true;
    }

    bool EventLoop::RunUntil(const std::function<bool()>& Done, int MaxSteps)
    {
        for (int Step = 0; !Done(); ++Step)
        {
            if (Step >= MaxSteps || !RunOne())
            {
                return Done();
            }
        }

        return true;
    }

    void EventLoop::Advance(double Seconds)
    {
        const double Target = Clock + Seconds;
        for (;;)
        {
            auto Earliest = std::min_element(Tasks.begin(), Tasks.end(), [](const Task& Left, const Task& Right)
            {
                return Left.Due < Right.Due || (Left.Due == Right.Due && Left.Sequence < Right.Sequence);
            });
            if (Earliest == Tasks.end() || Earliest->Due > Target)
            {
                break;
            }

            RunOne();
        }

        Clock = std::max(Clock, Target);
    }

    // ----- Requests -----

    std::string RecordedRequest::Path() const
    {
        const auto Parts = Auth4::Url::Parse(Request.Url);
        return Parts ? Parts->Path : std::string();
    }

    std::string RecordedRequest::Header(const std::string& Name) const
    {
        for (const auto& Entry : Request.Headers)
        {
            if (LowerText(Entry.first) == LowerText(Name))
            {
                return Entry.second;
            }
        }

        return std::string();
    }

    std::string RecordedRequest::Field(const std::string& Name) const
    {
        if (Header("Content-Type") == "application/json")
        {
            return Auth4::Json::GetString(Auth4::Json::ParseObject(Request.Body).get(), Name).value_or(std::string());
        }

        size_t Start = 0;
        while (Start <= Request.Body.size())
        {
            size_t End = Request.Body.find('&', Start);
            if (End == std::string::npos)
            {
                End = Request.Body.size();
            }

            const std::string Pair = Request.Body.substr(Start, End - Start);
            const size_t Equals = Pair.find('=');
            if (Equals != std::string::npos && UrlDecode(Pair.substr(0, Equals)) == Name)
            {
                return UrlDecode(Pair.substr(Equals + 1));
            }

            Start = End + 1;
        }

        return std::string();
    }

    Auth4::HttpResponse Respond(int StatusCode, const std::string& Body)
    {
        Auth4::HttpResponse Response;
        Response.StatusCode = StatusCode;
        Response.Body = Body;
        return Response;
    }

    std::string TokenJson(const std::string& AccessToken, const std::string& RefreshToken, const std::string& Extra)
    {
        std::string Out = "{\"access_token\":\"" + AccessToken + "\",\"token_type\":\"Bearer\",\"expires_in\":300";
        if (!RefreshToken.empty())
        {
            Out += ",\"refresh_token\":\"" + RefreshToken + "\"";
        }

        Out += ",\"scope\":\"openid offline_access\",\"session_id\":\"ses_fake\"";
        if (!Extra.empty())
        {
            Out += "," + Extra;
        }

        return Out + "}";
    }

    void FakeTransport::Send(const Auth4::HttpRequest& Request, std::function<void(Auth4::HttpResponse)> Done)
    {
        RecordedRequest Recorded{Request, Loop.Now()};
        Requests.push_back(Recorded);
        auto Response = Handler ? Handler(Recorded) : Respond(404, "{\"error\":\"not_found\"}");
        Loop.Post([Done, Response]() { Done(Response); });
    }

    size_t FakeTransport::Count(const std::string& PathPrefix) const
    {
        return static_cast<size_t>(std::count_if(Requests.begin(), Requests.end(), [&PathPrefix](const RecordedRequest& Entry)
        {
            return Entry.Path().rfind(PathPrefix, 0) == 0;
        }));
    }

    void LoopbackTransport::Send(const Auth4::HttpRequest& Request, std::function<void(Auth4::HttpResponse)> Done)
    {
        Requests.push_back({Request, Loop.Now()});
        auto Response = LoopbackExchange(Request);
        Loop.Post([Done, Response]() { Done(Response); });
    }

    Auth4::HttpResponse LoopbackExchange(const Auth4::HttpRequest& Request)
    {
        Auth4::HttpResponse Failed;
        Failed.bNetworkError = true;
        const auto Parts = Auth4::Url::Parse(Request.Url);
        if (!Parts || Parts->Scheme != "http")
        {
            return Failed;
        }

#ifdef _WIN32
        static const bool bStarted = []()
        {
            WSADATA Data;
            return WSAStartup(MAKEWORD(2, 2), &Data) == 0;
        }();
        if (!bStarted)
        {
            return Failed;
        }
#endif

        addrinfo Hints{};
        Hints.ai_family = AF_UNSPEC;
        Hints.ai_socktype = SOCK_STREAM;
        addrinfo* Addresses = nullptr;
        const std::string Port = Parts->Port.empty() ? "80" : Parts->Port;
        if (getaddrinfo(Parts->Host.c_str(), Port.c_str(), &Hints, &Addresses) != 0 || Addresses == nullptr)
        {
            return Failed;
        }

        SocketHandle Socket = INVALID_SOCKET;
        for (addrinfo* Address = Addresses; Address != nullptr; Address = Address->ai_next)
        {
            Socket = socket(Address->ai_family, Address->ai_socktype, Address->ai_protocol);
            if (Socket == INVALID_SOCKET)
            {
                continue;
            }

            if (connect(Socket, Address->ai_addr, static_cast<int>(Address->ai_addrlen)) == 0)
            {
                break;
            }

            AUTH4_TEST_CLOSE_SOCKET(Socket);
            Socket = INVALID_SOCKET;
        }

        freeaddrinfo(Addresses);
        if (Socket == INVALID_SOCKET)
        {
            return Failed;
        }

        std::string Target = Parts->Path.empty() ? "/" : Parts->Path;
        if (Parts->bHasQuery)
        {
            Target += "?" + Parts->Query;
        }

        std::string Message = Request.Method + " " + Target + " HTTP/1.1\r\nHost: " + Parts->Host + ":" + Port +
                              "\r\nConnection: close\r\nContent-Length: " + std::to_string(Request.Body.size()) + "\r\n";
        for (const auto& Header : Request.Headers)
        {
            Message += Header.first + ": " + Header.second + "\r\n";
        }

        Message += "\r\n" + Request.Body;
        size_t SentBytes = 0;
        while (SentBytes < Message.size())
        {
            const auto Written = send(Socket, Message.data() + SentBytes, static_cast<int>(Message.size() - SentBytes), 0);
            if (Written <= 0)
            {
                AUTH4_TEST_CLOSE_SOCKET(Socket);
                return Failed;
            }

            SentBytes += static_cast<size_t>(Written);
        }

        std::string Raw;
        char Buffer[4096];
        for (;;)
        {
            const auto Received = recv(Socket, Buffer, static_cast<int>(sizeof(Buffer)), 0);
            if (Received <= 0)
            {
                break;
            }

            Raw.append(Buffer, static_cast<size_t>(Received));
        }

        AUTH4_TEST_CLOSE_SOCKET(Socket);
        const size_t HeaderEnd = Raw.find("\r\n\r\n");
        if (Raw.compare(0, 9, "HTTP/1.1 ") != 0 || HeaderEnd == std::string::npos)
        {
            return Failed;
        }

        Auth4::HttpResponse Response;
        Response.StatusCode = std::atoi(Raw.substr(9, 3).c_str());
        Response.Body = Raw.substr(HeaderEnd + 4);
        return Response;
    }

    // ----- Storage -----

    void MemoryStorage::Read(const std::string& Key, std::function<void(bool, bool, std::string)> Done)
    {
        const auto Found = Values.find(Key);
        const bool bFound = Found != Values.end();
        const std::string Value = bFound ? Found->second : std::string();
        Loop.Post([Done, bFound, Value]() { Done(true, bFound, Value); });
    }

    void MemoryStorage::Write(const std::string& Key, const std::string& Value, std::function<void(bool)> Done)
    {
        ++Writes;
        const bool bOk = !bFailWrites;
        if (bOk)
        {
            Values[Key] = Value;
        }

        Loop.Post([Done, bOk]() { Done(bOk); });
    }

    void MemoryStorage::Delete(const std::string& Key, std::function<void(bool)> Done)
    {
        ++Deletes;
        Values.erase(Key);
        Loop.Post([Done]() { Done(true); });
    }
}

int main(int Argc, char** Argv)
{
    std::string MockOrigin;
    std::string Filter;
    for (int Index = 1; Index + 1 < Argc; Index += 2)
    {
        if (std::strcmp(Argv[Index], "--origin") == 0)
        {
            MockOrigin = Argv[Index + 1];
        }
        else if (std::strcmp(Argv[Index], "--filter") == 0)
        {
            Filter = Argv[Index + 1];
        }
    }

    int Passed = 0;
    int Failed = 0;
    int Skipped = 0;
    for (const auto& Test : Auth4Tests::Registry())
    {
        if (!Filter.empty() && std::string(Test.Name).find(Filter) == std::string::npos)
        {
            continue;
        }

        if (Test.bNeedsMockServer && MockOrigin.empty())
        {
            std::printf("SKIP %s (no --origin for the mock server)\n", Test.Name);
            ++Skipped;
            continue;
        }

        Auth4Tests::TestContext Context;
        Context.MockOrigin = MockOrigin;
        Test.Function(Context);
        if (Context.Failures.empty())
        {
            std::printf("PASS %s\n", Test.Name);
            ++Passed;
        }
        else
        {
            std::printf("FAIL %s\n", Test.Name);
            for (const auto& Failure : Context.Failures)
            {
                std::printf("     %s\n", Failure.c_str());
            }

            ++Failed;
        }
    }

    std::printf("%d passed, %d failed, %d skipped\n", Passed, Failed, Skipped);
    return Failed == 0 && Passed > 0 ? 0 : 1;
}
