// Test doubles and a tiny test runner for the Auth4Core suite. Everything runs on one thread in
// virtual time: the EventLoop is the scheduler, and transports post their completions to it.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "Auth4Core/Auth4Client.h"

namespace Auth4Tests
{
    // ----- Runner -----

    struct TestContext
    {
        std::vector<std::string> Failures;
        /// Origin of the local mock server, or empty when the suite runs without one.
        std::string MockOrigin;
    };

    using TestFunction = void (*)(TestContext&);

    struct TestRegistration
    {
        TestRegistration(const char* Name, TestFunction Function, bool bNeedsMockServer);
    };

    void RecordFailure(TestContext& Context, const char* File, int Line, const std::string& Message);

#define AUTH4_TEST(Name) \
    static void Name(Auth4Tests::TestContext& Context); \
    static const Auth4Tests::TestRegistration Name##Registration(#Name, &Name, false); \
    static void Name(Auth4Tests::TestContext& Context)

#define AUTH4_MOCK_TEST(Name) \
    static void Name(Auth4Tests::TestContext& Context); \
    static const Auth4Tests::TestRegistration Name##Registration(#Name, &Name, true); \
    static void Name(Auth4Tests::TestContext& Context)

#define EXPECT_TRUE(Condition) \
    do \
    { \
        if (!(Condition)) \
        { \
            Auth4Tests::RecordFailure(Context, __FILE__, __LINE__, "expected " #Condition); \
        } \
    } while (false)

#define EXPECT_EQ(Expected, Actual) \
    do \
    { \
        const auto ExpectedValue = (Expected); \
        const auto ActualValue = (Actual); \
        if (!(ExpectedValue == ActualValue)) \
        { \
            std::ostringstream Message; \
            Message << "expected " #Actual " == " << Auth4Tests::Show(ExpectedValue) << ", got " \
                    << Auth4Tests::Show(ActualValue); \
            Auth4Tests::RecordFailure(Context, __FILE__, __LINE__, Message.str()); \
        } \
    } while (false)

#define REQUIRE_TRUE(Condition) \
    do \
    { \
        if (!(Condition)) \
        { \
            Auth4Tests::RecordFailure(Context, __FILE__, __LINE__, "required " #Condition); \
            return; \
        } \
    } while (false)

    std::string Show(const std::string& Value);
    std::string Show(const char* Value);
    std::string Show(Auth4::ErrorKind Value);
    template <typename T>
    std::string Show(const T& Value)
    {
        std::ostringstream Out;
        Out << Value;
        return Out.str();
    }

    // ----- Virtual-time scheduler -----

    class EventLoop : public Auth4::IScheduler
    {
    public:
        double Clock = 1700000000;

        double Now() override { return Clock; }
        void After(double Seconds, std::function<void()> Callback) override;
        void Post(std::function<void()> Callback) { After(0, std::move(Callback)); }

        /// Runs the earliest task, advancing virtual time to it. False when nothing is queued.
        bool RunOne();

        /// Runs tasks until Done is true. False when the queue empties or the step limit is hit first.
        bool RunUntil(const std::function<bool()>& Done, int MaxSteps = 100000);

        /// Runs every task due within Seconds, then sets the clock to that time.
        void Advance(double Seconds);

        size_t Pending() const { return Tasks.size(); }

    private:
        struct Task
        {
            double Due;
            uint64_t Sequence;
            std::function<void()> Callback;
        };

        std::vector<Task> Tasks;
        uint64_t NextSequence = 0;
    };

    // ----- Transports -----

    struct RecordedRequest
    {
        Auth4::HttpRequest Request;
        double SentAt = 0;

        std::string Path() const;
        std::string Header(const std::string& Name) const;
        /// A form or JSON body field, or empty.
        std::string Field(const std::string& Name) const;
    };

    Auth4::HttpResponse Respond(int StatusCode, const std::string& Body);

    /// Scripted transport. Handler decides the response for each request.
    class FakeTransport : public Auth4::ITransport
    {
    public:
        explicit FakeTransport(EventLoop& InLoop) : Loop(InLoop) {}

        std::function<Auth4::HttpResponse(const RecordedRequest&)> Handler;
        std::vector<RecordedRequest> Requests;

        void Send(const Auth4::HttpRequest& Request, std::function<void(Auth4::HttpResponse)> Done) override;

        size_t Count(const std::string& PathPrefix) const;

    private:
        EventLoop& Loop;
    };

    /// Real HTTP/1.1 over loopback sockets to the mock server. Blocks while sending, then posts the
    /// completion to the loop, so callbacks never run inside Send.
    class LoopbackTransport : public Auth4::ITransport
    {
    public:
        explicit LoopbackTransport(EventLoop& InLoop) : Loop(InLoop) {}

        std::vector<RecordedRequest> Requests;

        void Send(const Auth4::HttpRequest& Request, std::function<void(Auth4::HttpResponse)> Done) override;

    private:
        EventLoop& Loop;
    };

    /// One blocking HTTP exchange with a loopback server. Used for mock control requests too.
    Auth4::HttpResponse LoopbackExchange(const Auth4::HttpRequest& Request);

    // ----- Storage and launcher -----

    class MemoryStorage : public Auth4::ISecureStorage
    {
    public:
        explicit MemoryStorage(EventLoop& InLoop) : Loop(InLoop) {}

        std::map<std::string, std::string> Values;
        bool bFailWrites = false;
        int Writes = 0;
        int Deletes = 0;

        void Read(const std::string& Key, std::function<void(bool, bool, std::string)> Done) override;
        void Write(const std::string& Key, const std::string& Value, std::function<void(bool)> Done) override;
        void Delete(const std::string& Key, std::function<void(bool)> Done) override;

    private:
        EventLoop& Loop;
    };

    class RecordingLauncher : public Auth4::IBrowserLauncher
    {
    public:
        bool bSupported = true;
        std::vector<std::string> Opened;

        bool IsSupported() const override { return bSupported; }
        void Open(const std::string& Url) override { Opened.push_back(Url); }
    };

    // ----- Helpers -----

    constexpr const char* TestTenant = "ten_mockTenant0000000001";
    constexpr const char* TestClient = "cli_mockNative000000001";

    /// Captures the single result of an asynchronous call.
    template <typename T>
    struct Captured
    {
        std::optional<Auth4::Result<T>> Value;

        std::function<void(const Auth4::Result<T>&)> Callback()
        {
            return [this](const Auth4::Result<T>& Result) { Value = Result; };
        }

        bool Done() const { return Value.has_value(); }
        bool Ok() const { return Value && Value->Ok(); }
        Auth4::ErrorKind Kind() const { return Value ? Value->GetError().Kind : Auth4::ErrorKind::None; }
    };

    std::string TokenJson(const std::string& AccessToken, const std::string& RefreshToken, const std::string& Extra = "");
}
