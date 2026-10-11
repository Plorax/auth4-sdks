using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine.Networking;

namespace Auth4.Unity
{
    /// <summary>
    /// Transport built on UnityWebRequest. Create and await it from the main thread. On WebGL the
    /// browser controls Cookie, Origin and Set-Cookie, so guest upgrades are not supported there.
    /// </summary>
    public sealed class UnityWebRequestTransport : IAuth4HttpTransport
    {
        public int TimeoutSeconds { get; set; } = 30;

        public Task<Auth4HttpResponse> SendAsync(Auth4HttpRequest request, CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return Task.FromCanceled<Auth4HttpResponse>(cancellationToken);
            }

            var completion = new TaskCompletionSource<Auth4HttpResponse>();
            var web = new UnityWebRequest(request.Uri, request.Method)
            {
                downloadHandler = new DownloadHandlerBuffer(),
                timeout = TimeoutSeconds,
                redirectLimit = 0,
            };
            if (request.Body != null)
            {
                web.uploadHandler = new UploadHandlerRaw(request.Body);
                if (request.ContentType != null)
                {
                    web.SetRequestHeader("Content-Type", request.ContentType);
                }
            }

            foreach (var header in request.Headers)
            {
                web.SetRequestHeader(header.Key, header.Value);
            }

            var registration = cancellationToken.Register(web.Abort);
            web.SendWebRequest().completed += _ =>
            {
                registration.Dispose();
                try
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        completion.TrySetCanceled(cancellationToken);
                    }
                    else if (web.result == UnityWebRequest.Result.ConnectionError ||
                             web.result == UnityWebRequest.Result.DataProcessingError)
                    {
                        completion.TrySetException(new IOException(web.error));
                    }
                    else
                    {
                        var cookies = new List<string>();
                        var setCookie = web.GetResponseHeader("Set-Cookie");
                        if (!string.IsNullOrEmpty(setCookie))
                        {
                            cookies.Add(setCookie);
                        }

                        completion.TrySetResult(new Auth4HttpResponse(
                            (int)web.responseCode,
                            web.downloadHandler.text,
                            cookies));
                    }
                }
                catch (Exception error)
                {
                    completion.TrySetException(error);
                }
                finally
                {
                    web.Dispose();
                }
            };
            return completion.Task;
        }
    }
}
