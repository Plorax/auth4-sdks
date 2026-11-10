using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Auth4.Server.Internal
{
    internal static class Base64Url
    {
        public static byte[]? TryDecode(string value)
        {
            if (value.Length == 0 || value.Length % 4 == 1) return null;
            var builder = new StringBuilder(value.Length + 3);
            foreach (var character in value)
            {
                if (character == '-') builder.Append('+');
                else if (character == '_') builder.Append('/');
                else if ((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
                         (character >= '0' && character <= '9')) builder.Append(character);
                else return null;
            }
            while (builder.Length % 4 != 0) builder.Append('=');
            try
            {
                return Convert.FromBase64String(builder.ToString());
            }
            catch (FormatException)
            {
                return null;
            }
        }

        public static string Encode(byte[] value) =>
            Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>A compact JWS split into its parts. Nothing here is trusted until the signature is checked.</summary>
    internal sealed class JwtParts : IDisposable
    {
        private JwtParts(JsonDocument header, JsonDocument payload, byte[] signingInput, byte[] signature)
        {
            Header = header;
            Payload = payload;
            SigningInput = signingInput;
            Signature = signature;
        }

        public JsonDocument Header { get; }
        public JsonDocument Payload { get; }
        public byte[] SigningInput { get; }
        public byte[] Signature { get; }

        public static JwtParts? TryParse(string token)
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return null;
            var header = Base64Url.TryDecode(parts[0]);
            var payload = Base64Url.TryDecode(parts[1]);
            var signature = Base64Url.TryDecode(parts[2]);
            if (header == null || payload == null || signature == null) return null;
            JsonDocument? headerJson = null;
            try
            {
                headerJson = JsonDocument.Parse(header);
                var payloadJson = JsonDocument.Parse(payload);
                if (headerJson.RootElement.ValueKind != JsonValueKind.Object ||
                    payloadJson.RootElement.ValueKind != JsonValueKind.Object)
                {
                    headerJson.Dispose();
                    payloadJson.Dispose();
                    return null;
                }
                return new JwtParts(headerJson, payloadJson, Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), signature);
            }
            catch (JsonException)
            {
                headerJson?.Dispose();
                return null;
            }
        }

        public void Dispose()
        {
            Header.Dispose();
            Payload.Dispose();
        }
    }

    internal static class BoundedHttp
    {
        public const int MaxBodyBytes = 256 * 1024;

        /// <summary>
        /// Sends a request whose URL came from the configured issuer and reads a JSON object of at most
        /// 256 KiB. Redirects are refused, like @auth4/sdk-server's <c>redirect: "error"</c>.
        /// </summary>
        public static async Task<JsonDocument> SendForJsonObjectAsync(
            HttpClient client,
            HttpRequestMessage request,
            TimeSpan timeout,
            string what)
        {
            var requested = request.RequestUri;
            using var cancellation = new CancellationTokenSource(timeout);
            using var response = await client
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation.Token)
                .ConfigureAwait(false);
            if (response.RequestMessage?.RequestUri != null && response.RequestMessage.RequestUri != requested)
            {
                throw new HttpRequestException($"{what} was redirected.");
            }
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"{what} returned HTTP {(int)response.StatusCode}.");
            }
            if (response.Content.Headers.ContentLength > MaxBodyBytes)
            {
                throw new HttpRequestException($"{what} exceeded its size limit.");
            }

            using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using var buffer = new MemoryStream();
            var chunk = new byte[16 * 1024];
            while (true)
            {
                var read = await stream.ReadAsync(chunk, 0, chunk.Length, cancellation.Token).ConfigureAwait(false);
                if (read == 0) break;
                if (buffer.Length + read > MaxBodyBytes) throw new HttpRequestException($"{what} exceeded its size limit.");
                buffer.Write(chunk, 0, read);
            }
            var document = JsonDocument.Parse(buffer.ToArray());
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                document.Dispose();
                throw new HttpRequestException($"{what} returned a non-object body.");
            }
            return document;
        }
    }
}
