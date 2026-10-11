using System;
using UnityEngine;

namespace Auth4.Unity
{
    /// <summary>
    /// Opens the guest-upgrade page with Application.OpenURL. Not supported in WebGL builds, where
    /// the game already runs in a browser and the native intent flow does not apply.
    /// </summary>
    public sealed class UnityBrowserLauncher : IAuth4BrowserLauncher
    {
        public bool IsSupported => Application.platform != RuntimePlatform.WebGLPlayer;

        public void Open(Uri uri)
        {
            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            if (!IsSupported)
            {
                throw new PlatformNotSupportedException("Native guest upgrades are not available in WebGL builds.");
            }

            Application.OpenURL(uri.AbsoluteUri);
        }
    }
}
