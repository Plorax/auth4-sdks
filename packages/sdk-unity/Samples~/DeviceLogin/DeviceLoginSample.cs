using System;
using System.Threading;
using Auth4;
using Auth4.Unity;
using UnityEngine;

namespace Auth4.Samples.DeviceLogin
{
    /// <summary>
    /// Minimal device-login and guest sample, including saving guest progress in the system browser,
    /// or in a popup window in WebGL builds. Configure the tenant, client and auth origin in the
    /// Inspector. Tokens stay in memory because no secure storage adapter is supplied.
    /// </summary>
    public sealed class DeviceLoginSample : MonoBehaviour
    {
        [SerializeField] private string tenantId = "ten_replace_with_tenant";
        [SerializeField] private string clientId = "cli_replace_with_native_client";
        [SerializeField] private string authOrigin = "https://auth.auth4.dev";

        private Auth4Client _client;
        private CancellationTokenSource _cancellation;
        private DeviceAuthorization _pending;
        private bool _upgrading;
        private string _status = "Signed out.";

        private void Start()
        {
            try
            {
                _client = new Auth4Client(new Auth4ClientOptions
                {
                    TenantId = tenantId,
                    ClientId = clientId,
                    AuthOrigin = authOrigin,
                    Transport = new UnityWebRequestTransport(),
                    BrowserLauncher = new UnityBrowserLauncher(), // native platforms
                    UpgradeWindow = new WebGLUpgradeWindow(),     // WebGL builds
                });
                _client.SessionChanged += session =>
                    _status = session == null ? "Signed out." : (session.IsGuest ? "Playing as guest." : "Signed in.");
            }
            catch (ArgumentException error)
            {
                _status = "Configure the sample in the Inspector: " + error.Message;
            }
        }

        private void OnDestroy()
        {
            _cancellation?.Cancel();
            _client?.Dispose();
        }

        private void OnGUI()
        {
            GUILayout.BeginArea(new Rect(20, 20, 420, 400));
            GUILayout.Label("auth4.dev device login");
            GUILayout.Label(_status);
            if (_client == null)
            {
                GUILayout.EndArea();
                return;
            }

            if (_pending != null)
            {
                GUILayout.Label("Code: " + _pending.UserCode);
                GUILayout.Label("Open " + _pending.VerificationUri + " on another device.");
                if (GUILayout.Button("Open verification page"))
                {
                    Application.OpenURL((_pending.VerificationUriComplete ?? _pending.VerificationUri).ToString());
                }

                if (GUILayout.Button("Cancel"))
                {
                    _cancellation?.Cancel();
                }
            }
            else if (_upgrading)
            {
                GUILayout.Label(Application.platform == RuntimePlatform.WebGLPlayer
                    ? "Finish linking in the popup window. If none opened, click once more."
                    : "Finish linking in your browser, then return here.");
                if (GUILayout.Button("Cancel"))
                {
                    _cancellation?.Cancel();
                }
            }
            else if (_client.CurrentSession == null)
            {
                if (GUILayout.Button("Sign in with another device"))
                {
                    SignInWithDevice();
                }

                if (GUILayout.Button("Play as guest"))
                {
                    PlayAsGuest();
                }
            }
            else
            {
                // In WebGL the popup must open inside a browser input event. IMGUI buttons fire on
                // release, a frame after the browser's event; most browsers still count that press,
                // and otherwise the window opens on the player's next click.
                if (_client.CurrentSession?.IsGuest == true &&
                    GUILayout.Button("Save progress with email or Discord"))
                {
                    SaveGuestProgress(null);
                }

                // The page offers Steam first; the player can still pick another method there.
                if (_client.CurrentSession?.IsGuest == true &&
                    GUILayout.Button("Save progress with Steam"))
                {
                    SaveGuestProgress(Auth4Provider.Steam);
                }

                if (GUILayout.Button("Sign out"))
                {
                    SignOut();
                }
            }

            GUILayout.EndArea();
        }

        private async void SignInWithDevice()
        {
            _cancellation = new CancellationTokenSource();
            try
            {
                _status = "Waiting for approval…";
                await _client.SignInWithDeviceAsync(authorization => _pending = authorization, null, _cancellation.Token);
            }
            catch (OperationCanceledException)
            {
                _status = "Sign-in cancelled.";
            }
            catch (Auth4DeviceAuthorizationException error)
            {
                _status = error.Reason == DeviceAuthorizationFailure.Denied ? "Sign-in was denied." : "The code expired.";
            }
            catch (Auth4Exception error)
            {
                _status = "Sign-in failed: " + error.Error;
            }
            finally
            {
                _pending = null;
                _cancellation.Dispose();
                _cancellation = null;
            }
        }

        #region Guest sign-in
        private async void PlayAsGuest()
        {
            try
            {
                await _client.SignInAsGuestAsync();
            }
            catch (Auth4Exception error)
            {
                _status = "Guest sign-in failed: " + error.Error;
            }
        }

        #endregion

        #region Guest upgrade
        private async void SaveGuestProgress(Auth4Provider? provider)
        {
            _cancellation = new CancellationTokenSource();
            _upgrading = true;
            try
            {
                Action<GuestUpgradeProgress> onProgress =
                    progress => _status = progress.Stage == GuestUpgradeStage.Completed ? "Progress saved." : "Waiting for the browser…";
                var result = provider.HasValue
                    ? await _client.UpgradeGuestAsync(provider.Value, onProgress, _cancellation.Token)
                    : await _client.UpgradeGuestAsync(onProgress, _cancellation.Token);
                _status = "Progress saved with " + result.Identity.Provider + ".";
            }
            catch (Auth4GuestUpgradeException error)
            {
                switch (error.Reason)
                {
                    case GuestUpgradeFailure.Conflict:
                        _status = "That account already belongs to another player. Still playing as guest.";
                        break;
                    case GuestUpgradeFailure.Denied:
                        _status = "Not saved. Still playing as guest.";
                        break;
                    case GuestUpgradeFailure.Expired:
                        _status = "The link expired. Try again.";
                        break;
                    case GuestUpgradeFailure.PopupBlocked:
                        _status = "The browser blocked the window. Allow pop-ups and try again.";
                        break;
                    case GuestUpgradeFailure.WindowClosed:
                        _status = "The window was closed. Still playing as guest.";
                        break;
                    case GuestUpgradeFailure.SessionEnded:
                        _status = "The guest session ended. Sign in again.";
                        break;
                    default:
                        _status = "Saving cancelled.";
                        break;
                }
            }
            catch (Auth4Exception error)
            {
                _status = "Saving failed: " + error.Error;
            }
            finally
            {
                _upgrading = false;
                _cancellation.Dispose();
                _cancellation = null;
            }
        }

        #endregion

        private async void SignOut()
        {
            await _client.SignOutAsync();
        }
    }
}
