using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using UnityEngine;

namespace Auth4.Unity
{
    /// <summary>
    /// Runs the hosted guest-upgrade page in a browser popup for WebGL builds, through
    /// Plugins/WebGL/Auth4Upgrade.jslib. Set it as Auth4ClientOptions.UpgradeWindow; UpgradeGuestAsync
    /// then uses it on WebGL and the BrowserLauncher elsewhere.
    ///
    /// Browsers open popups only inside an input event, but Unity handles input a frame later. Call
    /// UpgradeGuestAsync from a pointer-down handler (IPointerDownHandler): the popup opens at once
    /// where the browser still counts the press as a gesture, and otherwise when the player releases
    /// the pointer, which is a real browser pointer-up.
    /// </summary>
    public sealed class WebGLUpgradeWindow : IAuth4UpgradeWindow
    {
        private static readonly Dictionary<int, Handle> Handles = new Dictionary<int, Handle>();
        private static int _nextHandle;

        public bool IsSupported => Application.platform == RuntimePlatform.WebGLPlayer && !Application.isEditor;

        public IAuth4UpgradeWindowHandle Open(
            Uri upgradeUri,
            string authOrigin,
            Action<Auth4UpgradeWindowMessage> onMessage)
        {
            if (upgradeUri == null)
            {
                throw new ArgumentNullException(nameof(upgradeUri));
            }

            if (onMessage == null)
            {
                throw new ArgumentNullException(nameof(onMessage));
            }

            if (!IsSupported)
            {
                throw new PlatformNotSupportedException("The upgrade window is available only in WebGL builds.");
            }

            var handle = new Handle(++_nextHandle, onMessage);
            Handles[handle.Id] = handle;
            if (Auth4Upgrade_Open(handle.Id, upgradeUri.AbsoluteUri, authOrigin, OnEvent) == 0)
            {
                Handles.Remove(handle.Id);
                throw new ArgumentException("The upgrade page must be /login/upgrade on the auth origin.", nameof(upgradeUri));
            }

            return handle;
        }

        [AOT.MonoPInvokeCallback(typeof(EventCallback))]
        private static void OnEvent(int id, IntPtr kindPointer, IntPtr dataPointer)
        {
            if (!Handles.TryGetValue(id, out var handle))
            {
                return;
            }

            var data = Marshal.PtrToStringUTF8(dataPointer);
            Auth4UpgradeWindowEvent kind;
            switch (Marshal.PtrToStringUTF8(kindPointer))
            {
                case "opened":
                    kind = Auth4UpgradeWindowEvent.Opened;
                    break;
                case "blocked":
                    kind = Auth4UpgradeWindowEvent.Blocked;
                    break;
                case "ready":
                    kind = Auth4UpgradeWindowEvent.Ready;
                    break;
                case "complete":
                    kind = Auth4UpgradeWindowEvent.Complete;
                    break;
                case "error":
                    kind = Auth4UpgradeWindowEvent.Failed;
                    break;
                case "cancelled":
                    kind = Auth4UpgradeWindowEvent.Cancelled;
                    break;
                case "closed":
                    kind = Auth4UpgradeWindowEvent.Closed;
                    break;
                default:
                    return;
            }

            if (kind == Auth4UpgradeWindowEvent.Blocked || kind == Auth4UpgradeWindowEvent.Closed)
            {
                // The bridge has already stopped listening for this window.
                Handles.Remove(id);
            }

            try
            {
                handle.OnMessage(new Auth4UpgradeWindowMessage(kind, data.Length == 0 ? null : data));
            }
            catch (Exception)
            {
                // An exception must not unwind into the browser's event dispatch.
            }
        }

        private sealed class Handle : IAuth4UpgradeWindowHandle
        {
            public Handle(int id, Action<Auth4UpgradeWindowMessage> onMessage)
            {
                Id = id;
                OnMessage = onMessage;
            }

            public int Id { get; }

            public Action<Auth4UpgradeWindowMessage> OnMessage { get; }

            public void SendAccessToken(string accessToken)
            {
                if (Handles.ContainsKey(Id) && !string.IsNullOrEmpty(accessToken))
                {
                    Auth4Upgrade_SendToken(Id, accessToken);
                }
            }

            public void Close()
            {
                if (Handles.Remove(Id))
                {
                    Auth4Upgrade_Close(Id);
                }
            }

            public void Dispose()
            {
                if (Handles.Remove(Id))
                {
                    Auth4Upgrade_Release(Id);
                }
            }
        }

        private delegate void EventCallback(int id, IntPtr kind, IntPtr data);

#if UNITY_WEBGL && !UNITY_EDITOR
        [DllImport("__Internal")]
        private static extern int Auth4Upgrade_Open(int handle, string url, string authOrigin, EventCallback callback);

        [DllImport("__Internal")]
        private static extern int Auth4Upgrade_SendToken(int handle, string accessToken);

        [DllImport("__Internal")]
        private static extern void Auth4Upgrade_Close(int handle);

        [DllImport("__Internal")]
        private static extern void Auth4Upgrade_Release(int handle);
#else
        // Other platforms never reach these: IsSupported is false and Open throws first.
        private static int Auth4Upgrade_Open(int handle, string url, string authOrigin, EventCallback callback) => 0;

        private static int Auth4Upgrade_SendToken(int handle, string accessToken) => 0;

        private static void Auth4Upgrade_Close(int handle)
        {
        }

        private static void Auth4Upgrade_Release(int handle)
        {
        }
#endif
    }
}
