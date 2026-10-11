using System;

namespace Auth4
{
    /// <summary>
    /// Opens the hosted guest-upgrade page in the player's system browser. In Unity use
    /// Auth4.Unity.UnityBrowserLauncher, which calls Application.OpenURL. The page URL carries only a
    /// non-secret intent handle; tokens are collected by the game, never by the browser.
    /// </summary>
    public interface IAuth4BrowserLauncher
    {
        /// <summary>False where a native upgrade cannot run, for example Unity WebGL builds.</summary>
        bool IsSupported { get; }

        void Open(Uri uri);
    }
}
