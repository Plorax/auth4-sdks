using System;
using System.Threading;
using Auth4;
using Auth4.Unity;
using UnityEngine;

namespace Auth4.Samples.GameCenterSignIn
{
    /// <summary>
    /// Game Center sign-in on iOS and macOS (AUTH4D-311): sign in, or save a guest's progress to the
    /// Game Center player, and finish the verified email step in game when the application asks for
    /// one. Configure the tenant, client and auth origin in the Inspector, allow the app's bundle id
    /// for the game application in the console, and see AppleGameKitGameCenter.cs for the plug-in
    /// setup. Tokens stay in memory because no secure storage adapter is supplied.
    /// </summary>
    public sealed class GameCenterSignInSample : MonoBehaviour
    {
        [SerializeField] private string tenantId = "ten_replace_with_tenant";
        [SerializeField] private string clientId = "cli_replace_with_native_client";
        [SerializeField] private string authOrigin = "https://auth.auth4.dev";

        private Auth4Client _client;
        private CancellationTokenSource _cancellation;
        private GameCenterEmailContinuation _emailStep;
        private string _email = string.Empty;
        private string _code = string.Empty;
        private bool _busy;
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
#if AUTH4_APPLE_GAMEKIT && (UNITY_IOS || UNITY_STANDALONE_OSX)
                    GameCenter = new AppleGameKitGameCenter(),
#endif
                });
                _client.SessionChanged += session =>
                    _status = session == null ? "Signed out." : (session.IsGuest ? "Playing as guest." : "Signed in.");
                _cancellation = new CancellationTokenSource();
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
            GUILayout.BeginArea(new Rect(20, 20, 420, 420));
            GUILayout.Label("auth4.dev Game Center sign-in");
            GUILayout.Label(_status);
            if (_client == null || _busy)
            {
                GUILayout.EndArea();
                return;
            }

            if (_emailStep != null)
            {
                GUILayout.Label("Add an email address to continue.");
                _email = GUILayout.TextField(_email, 254);
                if (GUILayout.Button("Send code"))
                {
                    SendCode();
                }

                _code = GUILayout.TextField(_code, 6);
                if (GUILayout.Button("Confirm code"))
                {
                    ConfirmCode();
                }
            }
            else if (_client.CurrentSession == null)
            {
                if (GUILayout.Button("Play as guest"))
                {
                    Run(async () => await _client.SignInAsGuestAsync(_cancellation.Token));
                }

                if (GUILayout.Button("Sign in with Game Center"))
                {
                    SignIn();
                }
            }
            else
            {
                if (_client.CurrentSession.IsGuest && GUILayout.Button("Save progress with Game Center"))
                {
                    SignIn();
                }

                if (GUILayout.Button("Sign out"))
                {
                    Run(async () => await _client.SignOutAsync(_cancellation.Token));
                }
            }

            GUILayout.EndArea();
        }

        private void SignIn()
        {
            Run(async () =>
            {
                try
                {
                    await _client.SignInWithGameCenterAsync(_cancellation.Token);
                }
                catch (Auth4EmailVerificationRequiredException required)
                {
                    _emailStep = required.Continuation;
                    _status = "This game needs a verified email address.";
                }
            });
        }

        private void SendCode()
        {
            Run(async () =>
            {
                await _client.SendGameCenterEmailCodeAsync(_emailStep, _email, _cancellation.Token);
                _status = "We sent a code to " + _email.Trim() + ".";
            });
        }

        private void ConfirmCode()
        {
            Run(async () =>
            {
                await _client.ConfirmGameCenterEmailCodeAsync(_emailStep, _code, _cancellation.Token);
                _emailStep = null;
                _code = string.Empty;
            });
        }

        private async void Run(Func<System.Threading.Tasks.Task> action)
        {
            _busy = true;
            try
            {
                await action();
            }
            catch (PlatformNotSupportedException)
            {
                _status = "Game Center needs iOS or macOS and the GameKit plug-in.";
            }
            catch (Auth4Exception error)
            {
                // Show plain wording; server descriptions are not meant for players.
                _status = error.Error == "invalid_code"
                    ? "That code is not right. Try again."
                    : error.Error == "email_unavailable"
                        ? "Use a different email address."
                        : error.Error == "identity_in_use"
                            ? "This Game Center player already has an account. Sign out and sign in with Game Center."
                            : "Sign-in did not finish. Try again.";
                if (error.Error == "step_expired")
                {
                    _emailStep = null;
                }
            }
            catch (InvalidOperationException)
            {
                _status = "Sign out first.";
            }
            finally
            {
                _busy = false;
            }
        }
    }
}
