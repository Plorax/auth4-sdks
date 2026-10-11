using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Auth4;

namespace Auth4.Protocol.Tests
{
    internal static class Fixtures
    {
        public const string TenantId = "ten_TestTenant0000000001";
        public const string ClientId = "cli_TestNativeClient00001";
        public const string Origin = "https://auth.example.test";
        public const string GuestUserId = "usr_GuestPlayer000000001";

        public static string Token(string label)
        {
            return (label + "_").PadRight(48, 'x');
        }

        public static string TokenJson(string access, string refresh, string sessionId = null, string extra = null)
        {
            var builder = new StringBuilder("{");
            builder.Append("\"access_token\":\"").Append(Token(access)).Append("\",");
            builder.Append("\"token_type\":\"Bearer\",\"expires_in\":300,");
            if (refresh != null)
            {
                builder.Append("\"refresh_token\":\"").Append(Token(refresh)).Append("\",");
            }

            if (sessionId != null)
            {
                builder.Append("\"session_id\":\"").Append(sessionId).Append("\",");
            }

            if (extra != null)
            {
                builder.Append(extra).Append(',');
            }

            builder.Append("\"id_token\":\"").Append(Token("id")).Append("\",");
            builder.Append("\"scope\":\"openid offline_access\"}");
            return builder.ToString();
        }

        public static string Error(string error)
        {
            return "{\"error\":\"" + error + "\"}";
        }

        public static string DeviceStart(int expiresIn = 600, string verificationOrigin = Origin)
        {
            return "{\"device_code\":\"" + Token("device") + "\",\"user_code\":\"ABCD2345\"," +
                   "\"verification_uri\":\"" + verificationOrigin + "/device/verify?tenant_id=" + TenantId + "\"," +
                   "\"verification_uri_complete\":\"" + verificationOrigin + "/device/verify?tenant_id=" + TenantId +
                   "&client_id=" + ClientId + "&user_code=ABCD2345\"," +
                   "\"expires_in\":" + expiresIn + ",\"interval\":5}";
        }

        public static string GuestCreated(string access = "guest-access", string refresh = "guest-refresh")
        {
            return TokenJson(
                access,
                refresh,
                "ses_GuestSession00000001",
                "\"user_id\":\"" + GuestUserId + "\",\"upgrade_proof\":{\"proof_id\":\"prf_Initial000000000001\",\"expires_in\":300}");
        }

        public static Auth4Client Client(FakeTransport transport, FakeClock clock, ISecureStorageAdapter storage = null)
        {
            return new Auth4Client(new Auth4ClientOptions
            {
                TenantId = TenantId,
                ClientId = ClientId,
                AuthOrigin = Origin,
                Transport = transport,
                Clock = clock,
                SecureStorage = storage,
            });
        }
    }

    internal sealed class RecordedRequest
    {
        public RecordedRequest(Auth4HttpRequest request)
        {
            Method = request.Method;
            Uri = request.Uri;
            Headers = new Dictionary<string, string>(request.Headers, StringComparer.OrdinalIgnoreCase);
            ContentType = request.ContentType;
            Body = request.Body == null ? string.Empty : Encoding.UTF8.GetString(request.Body);
        }

        public string Method { get; }

        public Uri Uri { get; }

        public Dictionary<string, string> Headers { get; }

        public string ContentType { get; }

        public string Body { get; }

        public string Path => Uri.AbsolutePath;

        public Dictionary<string, string> Form
        {
            get
            {
                return Body.Split('&', StringSplitOptions.RemoveEmptyEntries)
                    .Select(part => part.Split('=', 2))
                    .ToDictionary(pair => Uri.UnescapeDataString(pair[0]), pair => Uri.UnescapeDataString(pair[1]));
            }
        }
    }

    /// <summary>Deterministic transport. Each handler result may complete synchronously or later.</summary>
    internal sealed class FakeTransport : IAuth4HttpTransport
    {
        private readonly Func<RecordedRequest, Task<Auth4HttpResponse>> _handler;
        private readonly List<RecordedRequest> _requests = new List<RecordedRequest>();

        public FakeTransport(Func<RecordedRequest, Task<Auth4HttpResponse>> handler)
        {
            _handler = handler;
        }

        public FakeTransport(Func<RecordedRequest, Auth4HttpResponse> handler)
            : this(request => Task.FromResult(handler(request)))
        {
        }

        public IReadOnlyList<RecordedRequest> Requests
        {
            get
            {
                lock (_requests)
                {
                    return _requests.ToList();
                }
            }
        }

        public IEnumerable<RecordedRequest> To(string path)
        {
            return Requests.Where(request => request.Path == path);
        }

        public Task<Auth4HttpResponse> SendAsync(Auth4HttpRequest request, CancellationToken cancellationToken)
        {
            var recorded = new RecordedRequest(request);
            lock (_requests)
            {
                _requests.Add(recorded);
            }

            return _handler(recorded);
        }

        public static Auth4HttpResponse Json(int status, string body, params string[] setCookies)
        {
            return new Auth4HttpResponse(status, body, setCookies);
        }
    }

    /// <summary>Virtual clock: Delay advances time immediately, so polling tests run without waiting.</summary>
    internal sealed class FakeClock : IAuth4Clock
    {
        private readonly List<TimeSpan> _delays = new List<TimeSpan>();

        public DateTimeOffset UtcNow { get; set; } = new DateTimeOffset(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

        public Action<int> OnDelay { get; set; }

        public IReadOnlyList<TimeSpan> Delays => _delays;

        public Task Delay(TimeSpan delay, CancellationToken cancellationToken)
        {
            _delays.Add(delay);
            OnDelay?.Invoke(_delays.Count);
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled(cancellationToken);
            }

            UtcNow += delay;
            return Task.CompletedTask;
        }

        public void Advance(TimeSpan time)
        {
            UtcNow += time;
        }
    }

    internal sealed class FakeSecureStorage : ISecureStorageAdapter
    {
        public Dictionary<string, string> Values { get; } = new Dictionary<string, string>();

        public int Writes { get; private set; }

        public Task<string> ReadAsync(string key, CancellationToken cancellationToken)
        {
            return Task.FromResult(Values.TryGetValue(key, out var value) ? value : null);
        }

        public Task WriteAsync(string key, string value, CancellationToken cancellationToken)
        {
            Writes++;
            Values[key] = value;
            return Task.CompletedTask;
        }

        public Task DeleteAsync(string key, CancellationToken cancellationToken)
        {
            Values.Remove(key);
            return Task.CompletedTask;
        }
    }
}
