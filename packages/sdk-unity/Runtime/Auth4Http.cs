using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Auth4
{
    /// <summary>Sends one HTTP request. Implementations must not follow redirects or keep cookies.</summary>
    public interface IAuth4HttpTransport
    {
        Task<Auth4HttpResponse> SendAsync(Auth4HttpRequest request, CancellationToken cancellationToken);
    }

    public sealed class Auth4HttpRequest
    {
        public Auth4HttpRequest(string method, Uri uri)
        {
            Method = method ?? throw new ArgumentNullException(nameof(method));
            Uri = uri ?? throw new ArgumentNullException(nameof(uri));
        }

        public string Method { get; }

        public Uri Uri { get; }

        /// <summary>Request headers other than Content-Type.</summary>
        public IDictionary<string, string> Headers { get; } =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public string ContentType { get; set; }

        public byte[] Body { get; set; }
    }

    public sealed class Auth4HttpResponse
    {
        public Auth4HttpResponse(int statusCode, string body, IReadOnlyList<string> setCookieHeaders = null)
        {
            StatusCode = statusCode;
            Body = body ?? string.Empty;
            SetCookieHeaders = setCookieHeaders ?? Array.Empty<string>();
        }

        public int StatusCode { get; }

        public string Body { get; }

        public IReadOnlyList<string> SetCookieHeaders { get; }
    }

    /// <summary>
    /// Default transport built on System.Net.Http. It ignores ambient cookies and redirects so the
    /// client controls every credential it sends. Use UnityWebRequestTransport on WebGL.
    /// </summary>
    public sealed class HttpClientTransport : IAuth4HttpTransport, IDisposable
    {
        private readonly HttpClient _client;
        private readonly bool _ownsClient;

        public HttpClientTransport()
            : this(
                new HttpClient(new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
                {
                    Timeout = TimeSpan.FromSeconds(30),
                },
                true)
        {
        }

        public HttpClientTransport(HttpClient client)
            : this(client, false)
        {
        }

        private HttpClientTransport(HttpClient client, bool ownsClient)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _ownsClient = ownsClient;
        }

        public async Task<Auth4HttpResponse> SendAsync(
            Auth4HttpRequest request,
            CancellationToken cancellationToken)
        {
            using (var message = new HttpRequestMessage(new HttpMethod(request.Method), request.Uri))
            {
                foreach (var header in request.Headers)
                {
                    message.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }

                if (request.Body != null)
                {
                    message.Content = new ByteArrayContent(request.Body);
                    if (request.ContentType != null)
                    {
                        message.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(request.ContentType);
                    }
                }

                using (var response = await _client.SendAsync(message, cancellationToken))
                {
                    var body = response.Content == null ? string.Empty : await response.Content.ReadAsStringAsync();
                    var cookies = response.Headers.TryGetValues("Set-Cookie", out var values)
                        ? new List<string>(values)
                        : new List<string>();
                    return new Auth4HttpResponse((int)response.StatusCode, body, cookies);
                }
            }
        }

        public void Dispose()
        {
            if (_ownsClient)
            {
                _client.Dispose();
            }
        }
    }
}
