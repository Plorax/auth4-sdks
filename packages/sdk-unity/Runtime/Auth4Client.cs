using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Auth4.Internal;

namespace Auth4
{
    /// <summary>
    /// auth4.dev client for native games: device authorization, guest sessions, guest upgrades and
    /// rotating refresh tokens. Access tokens are opaque credentials for the game server to validate.
    /// The client never awaits with ConfigureAwait(false), so continuations stay on Unity's main thread.
    /// </summary>
    public sealed class Auth4Client : IDisposable
    {
        private const string DeviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code";
        private const string FlowCookiePrefix = "__Host-auth4_flow_";
        private const int MinimumPollIntervalSeconds = 5;
        private const int SlowDownIncrementSeconds = 5;
        private const int MaxTransientBackoffSeconds = 60;
        private const double MaxTokenLifetimeSeconds = 86_400;

        private static readonly Regex TenantIdPattern = new Regex("^ten_[A-Za-z0-9]{16,64}$");
        private static readonly Regex ClientIdPattern = new Regex("^cli_[A-Za-z0-9]{16,64}$");
        private static readonly Regex IntentHandlePattern = new Regex("^gui_[A-Za-z0-9_-]{32,64}$");
        private static readonly Regex PollSecretPattern = new Regex("^gps_[A-Za-z0-9_-]{43,86}$");
        private static readonly Regex AddEmailIntentPattern = new Regex("^aei_[A-Za-z0-9_-]{32,64}$");
        private static readonly Regex AddEmailSecretPattern = new Regex("^aep_[A-Za-z0-9_-]{43,86}$");

        private readonly object _sync = new object();
        private readonly SemaphoreSlim _gate = new SemaphoreSlim(1, 1);
        private readonly IAuth4HttpTransport _transport;
        private readonly bool _ownsTransport;
        private readonly IAuth4Clock _clock;
        private readonly IAuth4TokenStorage _storage;
        private readonly string _storageKey;
        private readonly TimeSpan _refreshMargin;
        private readonly int _maxPollAttempts;
        private readonly int _maxTransientFailures;
        private readonly IAuth4BrowserLauncher _browserLauncher;
        private readonly IAuth4UpgradeWindow _upgradeWindow;

        private TokenState _state;
        private Task<Auth4Session> _refreshInFlight;
        private int _upgradeInFlight;
        private WindowUpgrade _windowUpgrade;
        private int _signOutGeneration;

        public Auth4Client(Auth4ClientOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (options.TenantId == null || !TenantIdPattern.IsMatch(options.TenantId))
            {
                throw new ArgumentException("A valid tenant ID (ten_…) is required.", nameof(options));
            }

            if (options.ClientId == null || !ClientIdPattern.IsMatch(options.ClientId))
            {
                throw new ArgumentException("A valid client ID (cli_…) is required.", nameof(options));
            }

            if (options.MaxDevicePollAttempts < 1 || options.MaxConsecutiveTransientPollFailures < 0 ||
                options.AccessTokenRefreshMargin < TimeSpan.Zero)
            {
                throw new ArgumentException("Polling and refresh limits must be positive.", nameof(options));
            }

            TenantId = options.TenantId;
            ClientId = options.ClientId;
            AuthOrigin = NormalizeOrigin(options.AuthOrigin);
            DefaultScope = NormalizeScope(options.DefaultScope);
            _transport = options.Transport ?? new HttpClientTransport();
            _ownsTransport = options.Transport == null;
            _clock = options.Clock ?? SystemClock.Instance;
            _storage = options.SecureStorage == null
                ? (IAuth4TokenStorage)new InMemoryTokenStorage()
                : new SecureTokenStorage(options.SecureStorage);
            _storageKey = "auth4." + TenantId + "." + ClientId + ".session";
            _refreshMargin = options.AccessTokenRefreshMargin;
            _maxPollAttempts = options.MaxDevicePollAttempts;
            _maxTransientFailures = options.MaxConsecutiveTransientPollFailures;
            _browserLauncher = options.BrowserLauncher;
            _upgradeWindow = options.UpgradeWindow;
        }

        /// <summary>Raised after sign-in, refresh, upgrade or sign-out. The argument is null when signed out.</summary>
        public event Action<Auth4Session> SessionChanged;

        public string TenantId { get; }

        public string ClientId { get; }

        public string AuthOrigin { get; }

        public string DefaultScope { get; }

        /// <summary>True only when a secure storage adapter was supplied.</summary>
        public bool IsRefreshPersistent => _storage.IsPersistent;

        public Auth4Session CurrentSession
        {
            get
            {
                lock (_sync)
                {
                    return _state?.ToSession(_storage.IsPersistent);
                }
            }
        }

        // ----- Device authorization (RFC 8628) -----

        public async Task<DeviceAuthorization> StartDeviceAuthorizationAsync(
            string scope = null,
            CancellationToken cancellationToken = default)
        {
            EnsureSignedOut();
            var requestedScope = scope == null ? DefaultScope : NormalizeScope(scope);
            var response = await SendAsync(
                FormRequest(Endpoint("/device/authorization?tenant_id=" + Escape(TenantId)), new Dictionary<string, string>
                {
                    ["client_id"] = ClientId,
                    ["scope"] = requestedScope,
                }),
                cancellationToken);
            var json = Auth4Json.TryParseObject(response.Body);
            if (response.StatusCode != 200)
            {
                throw ErrorFrom(response, json);
            }

            var deviceCode = Auth4Json.GetString(json, "device_code");
            var userCode = Auth4Json.GetString(json, "user_code");
            var verificationUri = SameOriginUri(Auth4Json.GetString(json, "verification_uri"));
            var completeValue = Auth4Json.GetString(json, "verification_uri_complete");
            var verificationUriComplete = completeValue == null ? null : SameOriginUri(completeValue);
            var expiresIn = Auth4Json.GetNumber(json, "expires_in");
            var interval = Auth4Json.GetNumber(json, "interval") ?? MinimumPollIntervalSeconds;
            if (string.IsNullOrEmpty(deviceCode) || string.IsNullOrEmpty(userCode) || verificationUri == null ||
                (completeValue != null && verificationUriComplete == null) ||
                expiresIn == null || expiresIn <= 0 || expiresIn > MaxTokenLifetimeSeconds || interval > 3_600)
            {
                throw InvalidResponse(response.StatusCode, "The device authorization response is malformed.");
            }

            return new DeviceAuthorization(
                deviceCode,
                userCode,
                verificationUri,
                verificationUriComplete,
                _clock.UtcNow.AddSeconds(expiresIn.Value),
                Math.Max(MinimumPollIntervalSeconds, (int)Math.Ceiling(interval)),
                requestedScope);
        }

        /// <summary>
        /// Polls until the player approves or denies, the code expires, or the token is cancelled.
        /// Polling is bounded by the code's expiry and MaxDevicePollAttempts. A cancelled poll can be
        /// resumed with the same authorization until it expires.
        /// </summary>
        public async Task<Auth4Session> PollDeviceAuthorizationAsync(
            DeviceAuthorization authorization,
            CancellationToken cancellationToken = default)
        {
            if (authorization == null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (authorization.IsCompleted)
            {
                throw new InvalidOperationException("This device authorization has already finished.");
            }

            if (!authorization.TryBeginPolling())
            {
                throw new InvalidOperationException("This device authorization is already being polled.");
            }

            var completed = false;
            try
            {
                var interval = authorization.IntervalSeconds;
                var transientFailures = 0;
                for (var attempt = 1; ; attempt++)
                {
                    if (attempt > _maxPollAttempts || _clock.UtcNow >= authorization.ExpiresAt)
                    {
                        completed = true;
                        throw new Auth4DeviceAuthorizationException(DeviceAuthorizationFailure.Expired, "expired_token");
                    }

                    await _clock.Delay(TimeSpan.FromSeconds(interval), cancellationToken);
                    cancellationToken.ThrowIfCancellationRequested();
                    if (_clock.UtcNow >= authorization.ExpiresAt)
                    {
                        completed = true;
                        throw new Auth4DeviceAuthorizationException(DeviceAuthorizationFailure.Expired, "expired_token");
                    }

                    Auth4HttpResponse response;
                    try
                    {
                        response = await SendAsync(
                            FormRequest(TokenEndpoint(), new Dictionary<string, string>
                            {
                                ["grant_type"] = DeviceCodeGrant,
                                ["client_id"] = ClientId,
                                ["device_code"] = authorization.DeviceCode,
                            }),
                            cancellationToken);
                    }
                    catch (Auth4Exception error) when (error.IsTransient && transientFailures < _maxTransientFailures)
                    {
                        transientFailures++;
                        interval = Backoff(interval);
                        continue;
                    }

                    var json = Auth4Json.TryParseObject(response.Body);
                    if (response.StatusCode == 200)
                    {
                        var tokens = ReadTokens(response, json);
                        completed = true;
                        return await AdoptNewSessionAsync(tokens);
                    }

                    var failure = ErrorFrom(response, json);
                    switch (failure.Error)
                    {
                        case "authorization_pending":
                            transientFailures = 0;
                            continue;
                        case "slow_down":
                            transientFailures = 0;
                            interval += SlowDownIncrementSeconds;
                            continue;
                        case "access_denied":
                            completed = true;
                            throw new Auth4DeviceAuthorizationException(
                                DeviceAuthorizationFailure.Denied,
                                failure.Error,
                                response.StatusCode);
                        case "expired_token":
                            completed = true;
                            throw new Auth4DeviceAuthorizationException(
                                DeviceAuthorizationFailure.Expired,
                                failure.Error,
                                response.StatusCode);
                    }

                    if (failure.IsTransient && transientFailures < _maxTransientFailures)
                    {
                        transientFailures++;
                        interval = Backoff(interval);
                        continue;
                    }

                    completed = !failure.IsTransient;
                    throw failure;
                }
            }
            finally
            {
                authorization.EndPolling(completed);
            }
        }

        /// <summary>Starts device authorization, reports the code, then polls until it finishes.</summary>
        public async Task<Auth4Session> SignInWithDeviceAsync(
            Action<DeviceAuthorization> showUserCode,
            string scope = null,
            CancellationToken cancellationToken = default)
        {
            if (showUserCode == null)
            {
                throw new ArgumentNullException(nameof(showUserCode));
            }

            var authorization = await StartDeviceAuthorizationAsync(scope, cancellationToken);
            showUserCode(authorization);
            return await PollDeviceAuthorizationAsync(authorization, cancellationToken);
        }

        // ----- Guest sessions and upgrades -----

        /// <summary>Creates a new guest player. Fails if a session is already active so a guest is never abandoned silently.</summary>
        public async Task<Auth4Session> SignInAsGuestAsync(CancellationToken cancellationToken = default)
        {
            EnsureSignedOut();
            var response = await SendAsync(
                JsonRequest(GuestEndpoint(string.Empty), new Dictionary<string, string>
                {
                    ["client_id"] = ClientId,
                    ["browser_flow_id"] = NewBrowserFlowId(),
                }),
                cancellationToken);
            var json = Auth4Json.TryParseObject(response.Body);
            if (response.StatusCode < 200 || response.StatusCode > 299)
            {
                throw ErrorFrom(response, json);
            }

            var userId = Auth4Json.GetString(json, "user_id");
            if (string.IsNullOrEmpty(userId))
            {
                throw InvalidResponse(response.StatusCode, "The guest response has no user ID.");
            }

            var tokens = ReadTokens(response, json);
            tokens.UserId = userId;
            tokens.IsGuest = true;
            return await AdoptNewSessionAsync(tokens);
        }

        /// <summary>
        /// Creates a linking intent for the current guest. Complete it with an email proof from
        /// StartEmailVerificationAsync and ConfirmEmailVerificationAsync, then CompleteGuestUpgradeAsync.
        /// </summary>
        public async Task<GuestUpgradeFlow> BeginGuestUpgradeAsync(CancellationToken cancellationToken = default)
        {
            var accessToken = await GetAccessTokenAsync(cancellationToken);
            TokenState current;
            lock (_sync)
            {
                current = _state;
            }

            if (current == null || !current.IsGuest)
            {
                throw new InvalidOperationException("Only an active guest session can be upgraded.");
            }

            var flowId = NewBrowserFlowId();
            var request = JsonRequest(GuestEndpoint("/linking-intent"), new Dictionary<string, string>
            {
                ["client_id"] = ClientId,
                ["browser_flow_id"] = flowId,
            });
            request.Headers["Authorization"] = "Bearer " + accessToken;
            var response = await SendAsync(request, cancellationToken);
            var json = Auth4Json.TryParseObject(response.Body);
            if (response.StatusCode < 200 || response.StatusCode > 299)
            {
                throw ErrorFrom(response, json);
            }

            var proof = Auth4Json.GetObject(json, "upgrade_proof");
            var expiresIn = Auth4Json.GetNumber(proof, "expires_in");
            var cookie = FindCookie(response.SetCookieHeaders, FlowCookiePrefix + flowId);
            if (proof == null || expiresIn == null || expiresIn <= 0 || cookie == null)
            {
                throw InvalidResponse(response.StatusCode, "The linking intent response is malformed.");
            }

            return new GuestUpgradeFlow(
                flowId,
                cookie,
                current.UserId,
                current.SessionId,
                _clock.UtcNow.AddSeconds(expiresIn.Value));
        }

        /// <summary>Sends a verification code to the email address that will be linked to the guest.</summary>
        public async Task StartEmailVerificationAsync(
            GuestUpgradeFlow flow,
            string email,
            CancellationToken cancellationToken = default)
        {
            EnsureFlowUsable(flow);
            RequireText(email, nameof(email));
            var response = await SendAsync(
                FlowRequest(flow, "/email/verification/start", new Dictionary<string, string>
                {
                    ["client_id"] = ClientId,
                    ["browser_flow_id"] = flow.BrowserFlowId,
                    ["email"] = email.Trim(),
                }),
                cancellationToken);
            if (response.StatusCode < 200 || response.StatusCode > 299)
            {
                throw ErrorFrom(response, Auth4Json.TryParseObject(response.Body));
            }
        }

        /// <summary>Confirms the emailed code and returns the one-time proof ID for CompleteGuestUpgradeAsync.</summary>
        public async Task<string> ConfirmEmailVerificationAsync(
            GuestUpgradeFlow flow,
            string email,
            string code,
            CancellationToken cancellationToken = default)
        {
            EnsureFlowUsable(flow);
            RequireText(email, nameof(email));
            RequireText(code, nameof(code));
            var response = await SendAsync(
                FlowRequest(flow, "/email/verification/confirm", new Dictionary<string, string>
                {
                    ["client_id"] = ClientId,
                    ["browser_flow_id"] = flow.BrowserFlowId,
                    ["email"] = email.Trim(),
                    ["code"] = code.Trim(),
                }),
                cancellationToken);
            var json = Auth4Json.TryParseObject(response.Body);
            if (response.StatusCode < 200 || response.StatusCode > 299)
            {
                throw ErrorFrom(response, json);
            }

            var proofId = Auth4Json.GetString(Auth4Json.GetObject(json, "proof"), "proof_id");
            if (string.IsNullOrEmpty(proofId))
            {
                throw InvalidResponse(response.StatusCode, "The verification response has no proof.");
            }

            return proofId;
        }

        /// <summary>
        /// Links the proven credential to the current guest. The player keeps the same user ID and
        /// receives a replacement session. 409 identity_in_use leaves the guest session unchanged.
        /// </summary>
        public async Task<GuestUpgradeResult> CompleteGuestUpgradeAsync(
            GuestUpgradeFlow flow,
            string proofId,
            CancellationToken cancellationToken = default)
        {
            EnsureFlowUsable(flow);
            RequireText(proofId, nameof(proofId));
            await GetAccessTokenAsync(cancellationToken);
            await _gate.WaitAsync(cancellationToken);
            try
            {
                TokenState current;
                lock (_sync)
                {
                    current = _state;
                }

                if (current == null || !current.IsGuest || current.AccessToken == null ||
                    current.SessionId != flow.SessionId || current.UserId != flow.GuestUserId)
                {
                    throw new InvalidOperationException("The guest session that started this upgrade is no longer active.");
                }

                var request = FlowRequest(flow, "/guest/upgrade", new Dictionary<string, string>
                {
                    ["client_id"] = ClientId,
                    ["browser_flow_id"] = flow.BrowserFlowId,
                    ["proof_id"] = proofId,
                });
                request.Headers.Remove("Origin");
                request.Headers["Authorization"] = "Bearer " + current.AccessToken;

                // Not cancellable once sent: a successful upgrade revokes the guest session, so the
                // replacement credentials must not be dropped.
                var response = await SendAsync(request, CancellationToken.None);
                var json = Auth4Json.TryParseObject(response.Body);
                if (response.StatusCode < 200 || response.StatusCode > 299)
                {
                    throw ErrorFrom(response, json);
                }

                var tokens = ReadTokens(response, json);
                var identity = Auth4Json.GetObject(json, "identity");
                var userId = Auth4Json.GetString(json, "user_id");
                if (userId != flow.GuestUserId || identity == null)
                {
                    await RevokeQuietlyAsync(tokens.RefreshToken ?? tokens.AccessToken, tokens.RefreshToken != null);
                    await ClearLocalAsync();
                    throw InvalidResponse(response.StatusCode, "The upgrade did not preserve the guest user.");
                }

                tokens.UserId = userId;
                tokens.IsGuest = false;
                var session = await CommitAsync(tokens);
                return new GuestUpgradeResult(
                    session,
                    new LinkedIdentity(
                        Auth4Json.GetString(identity, "identity_id"),
                        Auth4Json.GetString(identity, "provider")));
            }
            finally
            {
                _gate.Release();
            }
        }

        /// <summary>
        /// Upgrades the current guest by email or a social provider on the hosted page. On success the guest's
        /// tokens are replaced in one step and the user ID is unchanged.
        ///
        /// With a supported UpgradeWindow (Unity WebGL), the page opens in a browser popup and the game
        /// answers its postMessage handshake (docs/api-spec/auth4d-23.md); the popup is opened before
        /// this method first awaits, so call it from a pointer-down handler. Otherwise it creates an
        /// upgrade intent, opens the page with the BrowserLauncher and polls at the server's interval
        /// until the player finishes.
        ///
        /// Failures that end the upgrade throw Auth4GuestUpgradeException (Conflict, Expired, Denied or
        /// Cancelled; in a popup also PopupBlocked, WindowClosed or SessionEnded). Without a supported
        /// window or launcher it throws PlatformNotSupportedException.
        /// </summary>
        public Task<GuestUpgradeResult> UpgradeGuestAsync(
            Action<GuestUpgradeProgress> onProgress = null,
            CancellationToken cancellationToken = default)
        {
            return UpgradeGuestWithHintAsync(null, onProgress, cancellationToken);
        }

        /// <summary>
        /// Like UpgradeGuestAsync, but the hosted page offers <paramref name="provider"/> first, for a
        /// "Save progress with Steam" button (AUTH4D-125, AUTH4D-213). The player still confirms on the page, and
        /// the other enabled methods stay available. If the application has the provider turned off,
        /// the page shows its usual choices.
        /// </summary>
        public Task<GuestUpgradeResult> UpgradeGuestAsync(
            Auth4Provider provider,
            Action<GuestUpgradeProgress> onProgress = null,
            CancellationToken cancellationToken = default)
        {
            return UpgradeGuestWithHintAsync(provider, onProgress, cancellationToken);
        }

        private async Task<GuestUpgradeResult> UpgradeGuestWithHintAsync(
            Auth4Provider? provider,
            Action<GuestUpgradeProgress> onProgress,
            CancellationToken cancellationToken)
        {
            var hint = provider.HasValue ? ProviderName(provider.Value) : null;
            var inWindow = _upgradeWindow != null && _upgradeWindow.IsSupported;
            if (!inWindow && (_browserLauncher == null || !_browserLauncher.IsSupported))
            {
                throw new PlatformNotSupportedException(
                    "UpgradeGuestAsync needs a BrowserLauncher on a native platform or an UpgradeWindow in WebGL builds.");
            }

            if (Interlocked.CompareExchange(ref _upgradeInFlight, 1, 0) != 0)
            {
                throw new InvalidOperationException("A guest upgrade is already in progress.");
            }

            try
            {
                return inWindow
                    ? await UpgradeGuestInWindowAsync(hint, onProgress, cancellationToken)
                    : await UpgradeGuestCoreAsync(hint, onProgress, cancellationToken);
            }
            catch (OperationCanceledException error) when (cancellationToken.IsCancellationRequested)
            {
                throw new Auth4GuestUpgradeException(GuestUpgradeFailure.Cancelled, "cancelled", 0, error);
            }
            finally
            {
                Interlocked.Exchange(ref _upgradeInFlight, 0);
            }
        }

        /// <summary>
        /// Lets a signed-in player who has no email address (for example one who signed in with Steam)
        /// add one (AUTH4D-149). It creates an add-email request with the current access token, opens
        /// the hosted page with the BrowserLauncher, and polls at the server's interval until the player
        /// has verified the address with an email code. The session is then replaced with a refreshed one
        /// for the same user, and SessionChanged is raised. Progress uses the guest-upgrade stages.
        ///
        /// Failures that end the request throw Auth4AddEmailException (GuestAccount, AlreadyAdded,
        /// EmailSignInDisabled, Expired, Denied or Cancelled). An address that already belongs to another
        /// account is refused on the page, which lets the player try a different one. Without a
        /// supported BrowserLauncher it throws PlatformNotSupportedException.
        /// </summary>
        public async Task<AddEmailResult> AddEmailAsync(
            Action<GuestUpgradeProgress> onProgress = null,
            CancellationToken cancellationToken = default)
        {
            var outcome = await EmailActionAsync(EmailAction.Add, onProgress, cancellationToken);
            return new AddEmailResult(outcome.Session, outcome.Email, outcome.Identity);
        }

        /// <summary>
        /// Lets a signed-in player replace the email address on their account (AUTH4D-276). It works like
        /// AddEmailAsync, but opens the hosted change-email page, where the player proves the new address
        /// with an email code. The old email identity is replaced by a new one for the same user, the
        /// session is replaced with a refreshed one, and SessionChanged is raised.
        ///
        /// Failures that end the request throw Auth4AddEmailException (GuestAccount, NotAdded,
        /// EmailSignInDisabled, Expired, Denied or Cancelled). An address that already belongs to another
        /// account is refused on the page. Without a supported BrowserLauncher it throws
        /// PlatformNotSupportedException.
        /// </summary>
        public async Task<ChangeEmailResult> ChangeEmailAsync(
            Action<GuestUpgradeProgress> onProgress = null,
            CancellationToken cancellationToken = default)
        {
            var outcome = await EmailActionAsync(EmailAction.Change, onProgress, cancellationToken);
            return new ChangeEmailResult(outcome.Session, outcome.Email, outcome.Identity);
        }

        /// <summary>
        /// Lets a signed-in player remove the email address from their account (AUTH4D-276). It opens the
        /// hosted remove-email page, where the player confirms, and polls like AddEmailAsync. The session
        /// is then replaced with a refreshed one for the same user, and SessionChanged is raised.
        ///
        /// Failures that end the request throw Auth4AddEmailException (GuestAccount, NotAdded,
        /// OnlySignInMethod, Expired, Denied or Cancelled). OnlySignInMethod means the address is the
        /// only way the player can sign in, so it cannot be removed. Without a supported BrowserLauncher
        /// it throws PlatformNotSupportedException.
        /// </summary>
        public async Task<RemoveEmailResult> RemoveEmailAsync(
            Action<GuestUpgradeProgress> onProgress = null,
            CancellationToken cancellationToken = default)
        {
            var outcome = await EmailActionAsync(EmailAction.Remove, onProgress, cancellationToken);
            return new RemoveEmailResult(outcome.Session);
        }

        private async Task<EmailActionOutcome> EmailActionAsync(
            EmailAction action,
            Action<GuestUpgradeProgress> onProgress,
            CancellationToken cancellationToken)
        {
            var settings = EmailActionSettings.For(action);
            if (_browserLauncher == null || !_browserLauncher.IsSupported)
            {
                throw new PlatformNotSupportedException(settings.Method + " needs a supported BrowserLauncher.");
            }

            if (Interlocked.CompareExchange(ref _upgradeInFlight, 1, 0) != 0)
            {
                throw new InvalidOperationException("A guest upgrade or account email request is already in progress.");
            }

            try
            {
                return await EmailActionCoreAsync(settings, onProgress, cancellationToken);
            }
            catch (OperationCanceledException error) when (cancellationToken.IsCancellationRequested)
            {
                throw new Auth4AddEmailException(AddEmailFailure.Cancelled, "cancelled", 0, error);
            }
            finally
            {
                Interlocked.Exchange(ref _upgradeInFlight, 0);
            }
        }

        // ----- Tokens -----

        /// <summary>Returns a valid access token, refreshing first when it is about to expire.</summary>
        public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            TokenState current;
            lock (_sync)
            {
                current = _state;
            }

            if (current == null)
            {
                throw new Auth4Exception("login_required", "No session is active.");
            }

            if (current.AccessToken != null && current.AccessTokenExpiresAt - _refreshMargin > _clock.UtcNow)
            {
                return current.AccessToken;
            }

            if (current.RefreshToken == null)
            {
                throw new Auth4Exception("login_required", "The access token expired and the session cannot be refreshed.");
            }

            await RefreshAsync(cancellationToken);
            lock (_sync)
            {
                if (_state?.AccessToken == null)
                {
                    throw new Auth4Exception("login_required", "No session is active.");
                }

                return _state.AccessToken;
            }
        }

        /// <summary>
        /// Rotates the refresh token. Concurrent callers share one request, so ordinary parallel game
        /// requests never present the same refresh token twice. Cancelling stops waiting but not the
        /// shared request, which must finish to keep the rotated credential.
        /// </summary>
        public Task<Auth4Session> RefreshAsync(CancellationToken cancellationToken = default)
        {
            TaskCompletionSource<Auth4Session> owner = null;
            Task<Auth4Session> shared;
            lock (_sync)
            {
                if (_refreshInFlight == null)
                {
                    owner = new TaskCompletionSource<Auth4Session>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _refreshInFlight = owner.Task;
                }

                shared = _refreshInFlight;
            }

            if (owner != null)
            {
                _ = RunRefreshAsync(owner);
            }

            return WaitAsync(shared, cancellationToken);
        }

        /// <summary>Restores a session from secure storage. Returns false when nothing usable is stored.</summary>
        public async Task<bool> TryRestoreSessionAsync(CancellationToken cancellationToken = default)
        {
            await _gate.WaitAsync(cancellationToken);
            try
            {
                lock (_sync)
                {
                    if (_state != null)
                    {
                        return true;
                    }
                }

                var stored = Auth4Json.TryParseObject(await _storage.LoadAsync(_storageKey, cancellationToken));
                var refreshToken = Auth4Json.GetString(stored, "refresh_token");
                if (string.IsNullOrEmpty(refreshToken))
                {
                    if (stored != null)
                    {
                        await DeleteStoredQuietlyAsync();
                    }

                    return false;
                }

                lock (_sync)
                {
                    _state = new TokenState
                    {
                        RefreshToken = refreshToken,
                        UserId = Auth4Json.GetString(stored, "user_id"),
                        IsGuest = Auth4Json.GetString(stored, "guest") == "true",
                    };
                }
            }
            finally
            {
                _gate.Release();
            }

            try
            {
                await RefreshAsync(cancellationToken);
                return true;
            }
            catch (Auth4SessionExpiredException)
            {
                return false;
            }
        }

        /// <summary>
        /// Revokes the refresh credential and clears local state. Returns false when the server could not
        /// confirm revocation; the local session is cleared either way.
        /// </summary>
        public async Task<bool> SignOutAsync(CancellationToken cancellationToken = default)
        {
            await _gate.WaitAsync(cancellationToken);
            try
            {
                TokenState current;
                lock (_sync)
                {
                    current = _state;
                }

                var revoked = true;
                if (current != null)
                {
                    revoked = await RevokeQuietlyAsync(
                        current.RefreshToken ?? current.AccessToken,
                        current.RefreshToken != null);
                }

                await ClearLocalAsync();
                Interlocked.Increment(ref _signOutGeneration);
                return revoked;
            }
            finally
            {
                _gate.Release();
            }
        }

        public void Dispose()
        {
            if (_ownsTransport && _transport is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }

        // ----- Internals -----

        private async Task<GuestUpgradeResult> UpgradeGuestCoreAsync(
            string providerHint,
            Action<GuestUpgradeProgress> onProgress,
            CancellationToken cancellationToken)
        {
            var accessToken = await GetAccessTokenAsync(cancellationToken);
            TokenState guest;
            int generation;
            lock (_sync)
            {
                guest = _state;
                generation = Volatile.Read(ref _signOutGeneration);
            }

            if (guest == null || !guest.IsGuest || string.IsNullOrEmpty(guest.UserId))
            {
                throw new InvalidOperationException("Only an active guest session can be upgraded.");
            }

            var request = JsonRequest(GuestEndpoint("/upgrade-intent"), new Dictionary<string, string>
            {
                ["client_id"] = ClientId,
            });
            request.Headers["Authorization"] = "Bearer " + accessToken;
            var response = await SendAsync(request, cancellationToken);
            var json = Auth4Json.TryParseObject(response.Body);
            if (response.StatusCode < 200 || response.StatusCode > 299)
            {
                throw ErrorFrom(response, json);
            }

            var intent = Auth4Json.GetString(json, "intent");
            var pollSecret = Auth4Json.GetString(json, "poll_secret");
            var upgradeUri = SameOriginUri(Auth4Json.GetString(json, "upgrade_uri"));
            var expiresIn = Auth4Json.GetNumber(json, "expires_in");
            var interval = Auth4Json.GetNumber(json, "interval") ?? MinimumPollIntervalSeconds;
            if (intent == null || !IntentHandlePattern.IsMatch(intent) ||
                pollSecret == null || !PollSecretPattern.IsMatch(pollSecret) ||
                upgradeUri == null || upgradeUri.AbsolutePath != "/login/upgrade" ||
                expiresIn == null || expiresIn <= 0 || expiresIn > MaxTokenLifetimeSeconds || interval > 3_600)
            {
                throw InvalidResponse(response.StatusCode, "The upgrade intent response is malformed.");
            }

            if (providerHint != null)
            {
                upgradeUri = new Uri(
                    upgradeUri.AbsoluteUri + (string.IsNullOrEmpty(upgradeUri.Query) ? "?" : "&") +
                    "provider=" + providerHint,
                    UriKind.Absolute);
            }

            var expiresAt = _clock.UtcNow.AddSeconds(expiresIn.Value);
            var pollInterval = PollInterval(interval);
            ReportProgress(onProgress, new GuestUpgradeProgress(
                GuestUpgradeStage.OpeningBrowser, upgradeUri, expiresAt, pollInterval, 0));
            _browserLauncher.Open(upgradeUri);

            var transientFailures = 0;
            for (var attempt = 1; ; attempt++)
            {
                ReportProgress(onProgress, new GuestUpgradeProgress(
                    GuestUpgradeStage.WaitingForPlayer, upgradeUri, expiresAt, pollInterval, attempt - 1));
                if (attempt > _maxPollAttempts || _clock.UtcNow >= expiresAt)
                {
                    throw new Auth4GuestUpgradeException(GuestUpgradeFailure.Expired, "expired_token");
                }

                await _clock.Delay(TimeSpan.FromSeconds(pollInterval), cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                if (_clock.UtcNow >= expiresAt)
                {
                    throw new Auth4GuestUpgradeException(GuestUpgradeFailure.Expired, "expired_token");
                }

                Auth4HttpResponse poll;
                try
                {
                    // Not cancellable once sent: the token set is released exactly once, and the guest
                    // session has already been revoked when it is.
                    poll = await SendAsync(
                        JsonRequest(GuestEndpoint("/upgrade-intent/token"), new Dictionary<string, string>
                        {
                            ["client_id"] = ClientId,
                            ["intent"] = intent,
                            ["poll_secret"] = pollSecret,
                        }),
                        CancellationToken.None);
                }
                catch (Auth4Exception error) when (error.IsTransient && transientFailures < _maxTransientFailures)
                {
                    transientFailures++;
                    pollInterval = Backoff(pollInterval);
                    continue;
                }

                var body = Auth4Json.TryParseObject(poll.Body);
                if (poll.StatusCode == 200)
                {
                    var result = await CommitUpgradeAsync(poll, body, guest.UserId, generation);
                    ReportProgress(onProgress, new GuestUpgradeProgress(
                        GuestUpgradeStage.Completed, upgradeUri, expiresAt, pollInterval, attempt));
                    return result;
                }

                var failure = ErrorFrom(poll, body);
                var serverInterval = Auth4Json.GetNumber(body, "interval");
                switch (failure.Error)
                {
                    case "authorization_pending":
                        transientFailures = 0;
                        if (serverInterval != null)
                        {
                            pollInterval = Math.Max(pollInterval, PollInterval(serverInterval.Value));
                        }

                        continue;
                    case "slow_down":
                        transientFailures = 0;
                        pollInterval = Math.Max(
                            pollInterval + SlowDownIncrementSeconds,
                            serverInterval == null ? 0 : PollInterval(serverInterval.Value));
                        continue;
                    case "identity_in_use":
                        throw new Auth4GuestUpgradeException(GuestUpgradeFailure.Conflict, failure.Error, poll.StatusCode);
                    case "access_denied":
                        throw new Auth4GuestUpgradeException(GuestUpgradeFailure.Denied, failure.Error, poll.StatusCode);
                    case "expired_token":
                        throw new Auth4GuestUpgradeException(GuestUpgradeFailure.Expired, failure.Error, poll.StatusCode);
                }

                if (failure.IsTransient && transientFailures < _maxTransientFailures)
                {
                    transientFailures++;
                    pollInterval = Backoff(pollInterval);
                    continue;
                }

                throw failure;
            }
        }

        private async Task<EmailActionOutcome> EmailActionCoreAsync(
            EmailActionSettings settings,
            Action<GuestUpgradeProgress> onProgress,
            CancellationToken cancellationToken)
        {
            var accessToken = await GetAccessTokenAsync(cancellationToken);
            TokenState current;
            int generation;
            lock (_sync)
            {
                current = _state;
                generation = Volatile.Read(ref _signOutGeneration);
            }

            if (current == null)
            {
                throw new Auth4Exception("login_required", "No session is active.");
            }

            // Adding is the server's default action, so its request stays as it was before AUTH4D-276.
            var fields = new Dictionary<string, string> { ["client_id"] = ClientId };
            if (settings.Action != null)
            {
                fields["action"] = settings.Action;
            }

            var request = JsonRequest(Endpoint("/t/" + Escape(TenantId) + "/account/email/intent"), fields);
            request.Headers["Authorization"] = "Bearer " + accessToken;
            var response = await SendAsync(request, cancellationToken);
            var json = Auth4Json.TryParseObject(response.Body);
            if (response.StatusCode < 200 || response.StatusCode > 299)
            {
                var refused = ErrorFrom(response, json);
                switch (refused.Error)
                {
                    case "guest_account":
                        throw new Auth4AddEmailException(AddEmailFailure.GuestAccount, refused.Error, response.StatusCode);
                    case "email_already_added":
                        throw new Auth4AddEmailException(AddEmailFailure.AlreadyAdded, refused.Error, response.StatusCode);
                    case "email_sign_in_disabled":
                        throw new Auth4AddEmailException(AddEmailFailure.EmailSignInDisabled, refused.Error, response.StatusCode);
                    case "email_not_added":
                        throw new Auth4AddEmailException(AddEmailFailure.NotAdded, refused.Error, response.StatusCode);
                    case "only_sign_in_method":
                        throw new Auth4AddEmailException(AddEmailFailure.OnlySignInMethod, refused.Error, response.StatusCode);
                }

                throw refused;
            }

            var intent = Auth4Json.GetString(json, "intent");
            var pollSecret = Auth4Json.GetString(json, "poll_secret");
            var pageUri = SameOriginUri(Auth4Json.GetString(json, "add_email_uri"));
            var expiresIn = Auth4Json.GetNumber(json, "expires_in");
            var interval = Auth4Json.GetNumber(json, "interval") ?? MinimumPollIntervalSeconds;
            if (intent == null || !AddEmailIntentPattern.IsMatch(intent) ||
                pollSecret == null || !AddEmailSecretPattern.IsMatch(pollSecret) ||
                pageUri == null || pageUri.AbsolutePath != settings.PagePath ||
                expiresIn == null || expiresIn <= 0 || expiresIn > MaxTokenLifetimeSeconds || interval > 3_600)
            {
                throw InvalidResponse(response.StatusCode, "The " + settings.Label + " response is malformed.");
            }

            var expiresAt = _clock.UtcNow.AddSeconds(expiresIn.Value);
            var pollInterval = PollInterval(interval);
            ReportProgress(onProgress, new GuestUpgradeProgress(
                GuestUpgradeStage.OpeningBrowser, pageUri, expiresAt, pollInterval, 0));
            _browserLauncher.Open(pageUri);

            var transientFailures = 0;
            for (var attempt = 1; ; attempt++)
            {
                ReportProgress(onProgress, new GuestUpgradeProgress(
                    GuestUpgradeStage.WaitingForPlayer, pageUri, expiresAt, pollInterval, attempt - 1));
                if (attempt > _maxPollAttempts || _clock.UtcNow >= expiresAt)
                {
                    throw new Auth4AddEmailException(AddEmailFailure.Expired, "expired_token");
                }

                await _clock.Delay(TimeSpan.FromSeconds(pollInterval), cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                if (_clock.UtcNow >= expiresAt)
                {
                    throw new Auth4AddEmailException(AddEmailFailure.Expired, "expired_token");
                }

                Auth4HttpResponse poll;
                try
                {
                    // Not cancellable once sent: the refreshed session is released exactly once, and the
                    // previous session has already been revoked when it is.
                    poll = await SendAsync(
                        JsonRequest(
                            Endpoint("/t/" + Escape(TenantId) + "/account/email/intent/token"),
                            new Dictionary<string, string>
                            {
                                ["client_id"] = ClientId,
                                ["intent"] = intent,
                                ["poll_secret"] = pollSecret,
                            }),
                        CancellationToken.None);
                }
                catch (Auth4Exception error) when (error.IsTransient && transientFailures < _maxTransientFailures)
                {
                    transientFailures++;
                    pollInterval = Backoff(pollInterval);
                    continue;
                }

                var body = Auth4Json.TryParseObject(poll.Body);
                if (poll.StatusCode == 200)
                {
                    var result = await CommitEmailActionAsync(settings, poll, body, current.UserId, generation);
                    ReportProgress(onProgress, new GuestUpgradeProgress(
                        GuestUpgradeStage.Completed, pageUri, expiresAt, pollInterval, attempt));
                    return result;
                }

                var failure = ErrorFrom(poll, body);
                var serverInterval = Auth4Json.GetNumber(body, "interval");
                switch (failure.Error)
                {
                    case "authorization_pending":
                        transientFailures = 0;
                        if (serverInterval != null)
                        {
                            pollInterval = Math.Max(pollInterval, PollInterval(serverInterval.Value));
                        }

                        continue;
                    case "slow_down":
                        transientFailures = 0;
                        pollInterval = Math.Max(
                            pollInterval + SlowDownIncrementSeconds,
                            serverInterval == null ? 0 : PollInterval(serverInterval.Value));
                        continue;
                    case "access_denied":
                        throw new Auth4AddEmailException(AddEmailFailure.Denied, failure.Error, poll.StatusCode);
                    case "expired_token":
                        throw new Auth4AddEmailException(AddEmailFailure.Expired, failure.Error, poll.StatusCode);
                }

                if (failure.IsTransient && transientFailures < _maxTransientFailures)
                {
                    transientFailures++;
                    pollInterval = Backoff(pollInterval);
                    continue;
                }

                throw failure;
            }
        }

        /// <summary>
        /// Replaces the session with the refreshed one under the gate, so storage and memory switch
        /// together. The user must be unchanged; an explicit sign-out wins. An add or change result
        /// carries the new email identity and its address; a removal result carries neither.
        /// </summary>
        private async Task<EmailActionOutcome> CommitEmailActionAsync(
            EmailActionSettings settings,
            Auth4HttpResponse response,
            Dictionary<string, object> json,
            string knownUserId,
            int generation)
        {
            var tokens = ReadTokens(response, json);
            var identity = Auth4Json.GetObject(json, "identity");
            var userId = Auth4Json.GetString(json, "user_id");
            var email = Auth4Json.GetString(json, "email");
            await _gate.WaitAsync();
            try
            {
                TokenState current;
                lock (_sync)
                {
                    current = _state;
                }

                if (Volatile.Read(ref _signOutGeneration) != generation ||
                    (current != null && knownUserId != null && current.UserId != knownUserId))
                {
                    await RevokeQuietlyAsync(tokens.RefreshToken ?? tokens.AccessToken, tokens.RefreshToken != null);
                    throw new InvalidOperationException(
                        "The player signed out before the email address was " + settings.Done + "; sign in again.");
                }

                var shapeIsValid = settings.Removes
                    ? identity == null
                    : identity != null && Auth4Json.GetString(identity, "provider") == "email" &&
                      !string.IsNullOrEmpty(email);
                if (string.IsNullOrEmpty(userId) || (knownUserId != null && userId != knownUserId) || !shapeIsValid)
                {
                    await RevokeQuietlyAsync(tokens.RefreshToken ?? tokens.AccessToken, tokens.RefreshToken != null);
                    await ClearLocalAsync();
                    throw InvalidResponse(response.StatusCode, "The " + settings.Label + " result did not preserve the user.");
                }

                tokens.UserId = userId;
                tokens.IsGuest = false;
                var session = await CommitAsync(tokens);
                return settings.Removes
                    ? new EmailActionOutcome(session, null, null)
                    : new EmailActionOutcome(
                        session,
                        email,
                        new LinkedIdentity(Auth4Json.GetString(identity, "identity_id"), "email"));
            }
            finally
            {
                _gate.Release();
            }
        }

        /// <summary>
        /// Opener side of the hosted window protocol for games that run in a browser. Everything up to
        /// IAuth4UpgradeWindow.Open runs synchronously, so a browser user gesture still applies.
        /// </summary>
        private async Task<GuestUpgradeResult> UpgradeGuestInWindowAsync(
            string providerHint,
            Action<GuestUpgradeProgress> onProgress,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TokenState guest;
            int generation;
            lock (_sync)
            {
                guest = _state;
                generation = Volatile.Read(ref _signOutGeneration);
            }

            if (guest == null)
            {
                throw new Auth4Exception("login_required", "No session is active.");
            }

            if (!guest.IsGuest || string.IsNullOrEmpty(guest.UserId))
            {
                throw new InvalidOperationException("Only an active guest session can be upgraded.");
            }

            // A window still answered after a Conflict stops here; the new popup reuses its window name.
            Interlocked.Exchange(ref _windowUpgrade, null)?.Stop();
            var upgradeUri = Endpoint(
                "/login/upgrade?tenant_id=" + Escape(TenantId) + "&client_id=" + Escape(ClientId) +
                (providerHint == null ? string.Empty : "&provider=" + providerHint));
            var upgrade = new WindowUpgrade(this, guest.UserId, generation, upgradeUri, onProgress);
            Volatile.Write(ref _windowUpgrade, upgrade);
            ReportProgress(onProgress, upgrade.Progress(GuestUpgradeStage.OpeningBrowser));
            upgrade.Open(_upgradeWindow);
            using (cancellationToken.Register(upgrade.Cancel))
            {
                return await upgrade.Result;
            }
        }

        private bool IsCurrentGuest(string guestUserId, int generation)
        {
            lock (_sync)
            {
                return Volatile.Read(ref _signOutGeneration) == generation &&
                       _state != null && _state.IsGuest && _state.UserId == guestUserId;
            }
        }

        /// <summary>
        /// One popup upgrade. It answers each ready message with a fresh guest access token while the
        /// guest session that started it is live, and commits the result of a complete message. After
        /// a Conflict it keeps answering the window, as the browser SDK does, so a different credential
        /// linked in the same window still replaces the token set and raises SessionChanged.
        /// </summary>
        private sealed class WindowUpgrade
        {
            private readonly object _lock = new object();
            private readonly Auth4Client _client;
            private readonly string _guestUserId;
            private readonly int _generation;
            private readonly Uri _upgradeUri;
            private readonly Action<GuestUpgradeProgress> _onProgress;
            private readonly TaskCompletionSource<GuestUpgradeResult> _result =
                new TaskCompletionSource<GuestUpgradeResult>(TaskCreationOptions.RunContinuationsAsynchronously);

            private IAuth4UpgradeWindowHandle _handle;
            private bool _stopped;
            private bool _completing;

            public WindowUpgrade(
                Auth4Client client,
                string guestUserId,
                int generation,
                Uri upgradeUri,
                Action<GuestUpgradeProgress> onProgress)
            {
                _client = client;
                _guestUserId = guestUserId;
                _generation = generation;
                _upgradeUri = upgradeUri;
                _onProgress = onProgress;
            }

            public Task<GuestUpgradeResult> Result => _result.Task;

            /// <summary>A popup has no intent deadline and no polling.</summary>
            public GuestUpgradeProgress Progress(GuestUpgradeStage stage)
            {
                return new GuestUpgradeProgress(stage, _upgradeUri, DateTimeOffset.MaxValue, 0, 0);
            }

            public void Open(IAuth4UpgradeWindow window)
            {
                IAuth4UpgradeWindowHandle handle;
                try
                {
                    handle = window.Open(_upgradeUri, _client.AuthOrigin, OnMessage);
                }
                catch (Exception)
                {
                    Stop();
                    throw;
                }

                bool stopped;
                lock (_lock)
                {
                    // The window may report Blocked before Open returns.
                    stopped = _stopped;
                    if (!stopped)
                    {
                        _handle = handle;
                    }
                }

                if (stopped)
                {
                    handle?.Dispose();
                }
            }

            /// <summary>The cancellation token fired: close the window and stop waiting.</summary>
            public void Cancel()
            {
                var handle = Detach();
                try
                {
                    handle?.Close();
                }
                catch (Exception)
                {
                    // Already closed.
                }

                _result.TrySetCanceled();
            }

            /// <summary>Stops listening and leaves the window open, so the page can show its outcome.</summary>
            public void Stop()
            {
                var handle = Detach();
                try
                {
                    handle?.Dispose();
                }
                catch (Exception)
                {
                    // The bridge has already let go of the window.
                }
            }

            private IAuth4UpgradeWindowHandle Detach()
            {
                IAuth4UpgradeWindowHandle handle;
                lock (_lock)
                {
                    _stopped = true;
                    handle = _handle;
                    _handle = null;
                }

                Interlocked.CompareExchange(ref _client._windowUpgrade, null, this);
                return handle;
            }

            private void Finish(Exception error)
            {
                Stop();
                _result.TrySetException(error);
            }

            private void Finish(GuestUpgradeFailure reason, string error)
            {
                Finish(new Auth4GuestUpgradeException(reason, error));
            }

            private void OnMessage(Auth4UpgradeWindowMessage message)
            {
                lock (_lock)
                {
                    if (_stopped || message == null)
                    {
                        return;
                    }
                }

                switch (message.Kind)
                {
                    case Auth4UpgradeWindowEvent.Opened:
                        ReportProgress(_onProgress, Progress(GuestUpgradeStage.WaitingForPlayer));
                        return;
                    case Auth4UpgradeWindowEvent.Blocked:
                        Finish(GuestUpgradeFailure.PopupBlocked, "popup_blocked");
                        return;
                    case Auth4UpgradeWindowEvent.Closed:
                        Finish(GuestUpgradeFailure.WindowClosed, "window_closed");
                        return;
                    case Auth4UpgradeWindowEvent.Cancelled:
                        Finish(GuestUpgradeFailure.Denied, "access_denied");
                        return;
                    case Auth4UpgradeWindowEvent.Failed:
                        if (message.Data == "identity_in_use")
                        {
                            // The page offers to link a different credential, so keep answering it.
                            _result.TrySetException(
                                new Auth4GuestUpgradeException(GuestUpgradeFailure.Conflict, "identity_in_use"));
                        }
                        else if (message.Data == "invalid_session")
                        {
                            Finish(GuestUpgradeFailure.SessionEnded, "invalid_session");
                        }

                        return;
                    case Auth4UpgradeWindowEvent.Ready:
                        var ready = Auth4Json.TryParseObject(message.Data);
                        if (Auth4Json.GetString(ready, "tenant_id") == _client.TenantId &&
                            Auth4Json.GetString(ready, "client_id") == _client.ClientId)
                        {
                            _ = AnswerReadyAsync();
                        }

                        return;
                    case Auth4UpgradeWindowEvent.Complete:
                        lock (_lock)
                        {
                            if (_completing)
                            {
                                return;
                            }

                            _completing = true;
                        }

                        _ = CompleteAsync(message.Data);
                        return;
                }
            }

            /// <summary>Sends a fresh token only while the guest session that started the upgrade is live.</summary>
            private async Task AnswerReadyAsync()
            {
                string accessToken = null;
                try
                {
                    if (_client.IsCurrentGuest(_guestUserId, _generation))
                    {
                        accessToken = await _client.GetAccessTokenAsync(CancellationToken.None);
                    }
                }
                catch (Exception)
                {
                    accessToken = null;
                }

                if (accessToken == null || !_client.IsCurrentGuest(_guestUserId, _generation))
                {
                    Finish(GuestUpgradeFailure.SessionEnded, "invalid_session");
                    return;
                }

                IAuth4UpgradeWindowHandle handle;
                lock (_lock)
                {
                    handle = _stopped ? null : _handle;
                }

                handle?.SendAccessToken(accessToken);
            }

            private async Task CompleteAsync(string data)
            {
                try
                {
                    var json = Auth4Json.TryParseObject(data);
                    if (json == null)
                    {
                        throw InvalidResponse(0, "The upgrade result is malformed.");
                    }

                    // The result came from the hosted page, not an HTTP response of this client.
                    var result = await _client.CommitUpgradeAsync(
                        new Auth4HttpResponse(0, null), json, _guestUserId, _generation);
                    ReportProgress(_onProgress, Progress(GuestUpgradeStage.Completed));
                    Stop();
                    _result.TrySetResult(result);
                }
                catch (Exception error)
                {
                    Finish(error);
                }
            }
        }

        /// <summary>
        /// Replaces the guest token set with the upgraded one under the gate, so storage and memory
        /// switch together. The local guest session may already be gone if a refresh hit the revoked
        /// guest token meanwhile; it is replaced all the same. An explicit sign-out wins.
        /// </summary>
        private async Task<GuestUpgradeResult> CommitUpgradeAsync(
            Auth4HttpResponse response,
            Dictionary<string, object> json,
            string guestUserId,
            int generation)
        {
            var tokens = ReadTokens(response, json);
            var identity = Auth4Json.GetObject(json, "identity");
            var userId = Auth4Json.GetString(json, "user_id");
            await _gate.WaitAsync();
            try
            {
                TokenState current;
                lock (_sync)
                {
                    current = _state;
                }

                if (Volatile.Read(ref _signOutGeneration) != generation ||
                    (current != null && current.UserId != guestUserId))
                {
                    await RevokeQuietlyAsync(tokens.RefreshToken ?? tokens.AccessToken, tokens.RefreshToken != null);
                    throw new InvalidOperationException(
                        "The guest signed out before the upgrade finished; sign in with the linked account.");
                }

                if (userId != guestUserId || identity == null)
                {
                    await RevokeQuietlyAsync(tokens.RefreshToken ?? tokens.AccessToken, tokens.RefreshToken != null);
                    await ClearLocalAsync();
                    throw InvalidResponse(response.StatusCode, "The upgrade did not preserve the guest user.");
                }

                tokens.UserId = userId;
                tokens.IsGuest = false;
                var session = await CommitAsync(tokens);
                return new GuestUpgradeResult(
                    session,
                    new LinkedIdentity(
                        Auth4Json.GetString(identity, "identity_id"),
                        Auth4Json.GetString(identity, "provider")));
            }
            finally
            {
                _gate.Release();
            }
        }

        private static int PollInterval(double seconds)
        {
            return Math.Min(3_600, Math.Max(MinimumPollIntervalSeconds, (int)Math.Ceiling(seconds)));
        }

        private static void ReportProgress(Action<GuestUpgradeProgress> onProgress, GuestUpgradeProgress progress)
        {
            try
            {
                onProgress?.Invoke(progress);
            }
            catch (Exception)
            {
                // A game callback must not abandon an upgrade whose token set is released only once.
            }
        }

        private async Task RunRefreshAsync(TaskCompletionSource<Auth4Session> owner)
        {
            try
            {
                var session = await RefreshCoreAsync();
                lock (_sync)
                {
                    _refreshInFlight = null;
                }

                owner.SetResult(session);
            }
            catch (Exception error)
            {
                lock (_sync)
                {
                    _refreshInFlight = null;
                }

                owner.SetException(error);
            }
        }

        private async Task<Auth4Session> RefreshCoreAsync()
        {
            await _gate.WaitAsync();
            try
            {
                TokenState current;
                lock (_sync)
                {
                    current = _state;
                }

                if (current?.RefreshToken == null)
                {
                    throw new Auth4Exception("login_required", "No refresh credential is available.");
                }

                var response = await SendAsync(
                    FormRequest(TokenEndpoint(), new Dictionary<string, string>
                    {
                        ["grant_type"] = "refresh_token",
                        ["client_id"] = ClientId,
                        ["refresh_token"] = current.RefreshToken,
                    }),
                    CancellationToken.None);
                var json = Auth4Json.TryParseObject(response.Body);
                if (response.StatusCode == 200)
                {
                    var next = ReadTokens(response, json);
                    next.UserId = current.UserId;
                    next.IsGuest = current.IsGuest;
                    next.SessionId = next.SessionId ?? current.SessionId;
                    return await CommitAsync(next);
                }

                var failure = ErrorFrom(response, json);
                if (failure.Error == "invalid_grant")
                {
                    await ClearLocalAsync();
                    throw new Auth4SessionExpiredException(failure.Error, failure.Description, failure.StatusCode);
                }

                throw failure;
            }
            finally
            {
                _gate.Release();
            }
        }

        private async Task<Auth4Session> AdoptNewSessionAsync(TokenState tokens)
        {
            await _gate.WaitAsync();
            try
            {
                bool occupied;
                lock (_sync)
                {
                    occupied = _state != null;
                }

                if (occupied)
                {
                    await RevokeQuietlyAsync(tokens.RefreshToken ?? tokens.AccessToken, tokens.RefreshToken != null);
                    throw new InvalidOperationException("Another session became active; sign out before signing in again.");
                }

                return await CommitAsync(tokens);
            }
            finally
            {
                _gate.Release();
            }
        }

        /// <summary>Caller holds the gate. Storage writes are not cancellable so the stored and live tokens agree.</summary>
        private async Task<Auth4Session> CommitAsync(TokenState next)
        {
            try
            {
                if (next.RefreshToken == null)
                {
                    await _storage.DeleteAsync(_storageKey, CancellationToken.None);
                }
                else
                {
                    await _storage.SaveAsync(
                        _storageKey,
                        Auth4Json.SerializeStrings(new Dictionary<string, string>
                        {
                            ["v"] = "1",
                            ["refresh_token"] = next.RefreshToken,
                            ["user_id"] = next.UserId,
                            ["guest"] = next.IsGuest ? "true" : "false",
                        }),
                        CancellationToken.None);
                }
            }
            catch (Exception)
            {
                // A stale stored token would be replayed after restart and revoke the family; drop it.
                await DeleteStoredQuietlyAsync();
            }

            Auth4Session session;
            lock (_sync)
            {
                _state = next;
                session = next.ToSession(_storage.IsPersistent);
            }

            RaiseSessionChanged(session);
            return session;
        }

        private async Task ClearLocalAsync()
        {
            bool hadSession;
            lock (_sync)
            {
                hadSession = _state != null;
                _state = null;
            }

            await DeleteStoredQuietlyAsync();
            if (hadSession)
            {
                RaiseSessionChanged(null);
            }
        }

        private async Task DeleteStoredQuietlyAsync()
        {
            try
            {
                await _storage.DeleteAsync(_storageKey, CancellationToken.None);
            }
            catch (Exception)
            {
                // Storage adapters may be unavailable; the in-memory session is still cleared.
            }
        }

        private async Task<bool> RevokeQuietlyAsync(string token, bool isRefreshToken)
        {
            if (token == null)
            {
                return true;
            }

            try
            {
                var response = await SendAsync(
                    FormRequest(Endpoint("/oauth/revoke?tenant_id=" + Escape(TenantId)), new Dictionary<string, string>
                    {
                        ["client_id"] = ClientId,
                        ["token"] = token,
                        ["token_type_hint"] = isRefreshToken ? "refresh_token" : "access_token",
                    }),
                    CancellationToken.None);
                return response.StatusCode >= 200 && response.StatusCode <= 299;
            }
            catch (Auth4Exception)
            {
                return false;
            }
        }

        private void RaiseSessionChanged(Auth4Session session)
        {
            try
            {
                SessionChanged?.Invoke(session);
            }
            catch (Exception)
            {
                // A game callback must not corrupt token state that has already been committed.
            }
        }

        private void EnsureSignedOut()
        {
            lock (_sync)
            {
                if (_state != null)
                {
                    throw new InvalidOperationException(
                        "A session is already active. Upgrade the guest or sign out before signing in again.");
                }
            }
        }

        private void EnsureFlowUsable(GuestUpgradeFlow flow)
        {
            if (flow == null)
            {
                throw new ArgumentNullException(nameof(flow));
            }

            if (_clock.UtcNow >= flow.ExpiresAt)
            {
                throw new Auth4Exception("expired_token", "The guest upgrade expired; begin a new upgrade.");
            }
        }

        private TokenState ReadTokens(Auth4HttpResponse response, Dictionary<string, object> json)
        {
            var accessToken = Auth4Json.GetString(json, "access_token");
            var tokenType = Auth4Json.GetString(json, "token_type");
            var expiresIn = Auth4Json.GetNumber(json, "expires_in");
            if (string.IsNullOrEmpty(accessToken) ||
                !string.Equals(tokenType, "Bearer", StringComparison.OrdinalIgnoreCase) ||
                expiresIn == null || expiresIn <= 0 || expiresIn > MaxTokenLifetimeSeconds)
            {
                throw InvalidResponse(response.StatusCode, "The token response is malformed.");
            }

            var refreshToken = Auth4Json.GetString(json, "refresh_token");
            return new TokenState
            {
                AccessToken = accessToken,
                AccessTokenExpiresAt = _clock.UtcNow.AddSeconds(expiresIn.Value),
                RefreshToken = string.IsNullOrEmpty(refreshToken) ? null : refreshToken,
                IdToken = Auth4Json.GetString(json, "id_token"),
                Scope = Auth4Json.GetString(json, "scope"),
                SessionId = Auth4Json.GetString(json, "session_id"),
            };
        }

        private async Task<Auth4HttpResponse> SendAsync(Auth4HttpRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Auth4HttpResponse response;
            try
            {
                response = await _transport.SendAsync(request, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error)
            {
                throw new Auth4Exception("network_error", "The auth4.dev API could not be reached.", 0, error);
            }

            if (response == null)
            {
                throw new Auth4Exception("network_error", "The transport returned no response.");
            }

            return response;
        }

        private static Auth4Exception ErrorFrom(Auth4HttpResponse response, Dictionary<string, object> json)
        {
            var error = Auth4Json.GetString(json, "error");
            if (string.IsNullOrEmpty(error))
            {
                error = response.StatusCode >= 500 ? "server_error" : "invalid_response";
            }

            return new Auth4Exception(error, Auth4Json.GetString(json, "error_description"), response.StatusCode);
        }

        private static Auth4Exception InvalidResponse(int statusCode, string description)
        {
            return new Auth4Exception("invalid_response", description, statusCode);
        }

        private static int Backoff(int interval)
        {
            return Math.Max(interval, Math.Min(interval * 2, MaxTransientBackoffSeconds));
        }

        private Auth4HttpRequest FlowRequest(GuestUpgradeFlow flow, string path, Dictionary<string, string> body)
        {
            var request = JsonRequest(Endpoint("/t/" + Escape(TenantId) + path), body);
            request.Headers["Cookie"] = FlowCookiePrefix + flow.BrowserFlowId + "=" + flow.FlowCookie;
            // Hosted-login endpoints require the auth origin as a CSRF check. Native HTTP has no
            // ambient browser credentials; the flow cookie is held only by this client.
            request.Headers["Origin"] = AuthOrigin;
            return request;
        }

        private static Auth4HttpRequest FormRequest(Uri uri, Dictionary<string, string> fields)
        {
            var parts = new List<string>(fields.Count);
            foreach (var field in fields)
            {
                parts.Add(Escape(field.Key) + "=" + Escape(field.Value));
            }

            var request = new Auth4HttpRequest("POST", uri)
            {
                ContentType = "application/x-www-form-urlencoded",
                Body = Encoding.UTF8.GetBytes(string.Join("&", parts)),
            };
            request.Headers["Accept"] = "application/json";
            return request;
        }

        private static Auth4HttpRequest JsonRequest(Uri uri, Dictionary<string, string> fields)
        {
            var request = new Auth4HttpRequest("POST", uri)
            {
                ContentType = "application/json",
                Body = Encoding.UTF8.GetBytes(Auth4Json.SerializeStrings(fields)),
            };
            request.Headers["Accept"] = "application/json";
            return request;
        }

        private Uri TokenEndpoint()
        {
            return Endpoint("/oauth/token?tenant_id=" + Escape(TenantId));
        }

        private Uri GuestEndpoint(string suffix)
        {
            return Endpoint("/t/" + Escape(TenantId) + "/guest" + suffix);
        }

        private Uri Endpoint(string pathAndQuery)
        {
            return new Uri(AuthOrigin + pathAndQuery, UriKind.Absolute);
        }

        private Uri SameOriginUri(string value)
        {
            if (value == null || !Uri.TryCreate(value, UriKind.Absolute, out var uri))
            {
                return null;
            }

            return string.Equals(uri.GetLeftPart(UriPartial.Authority), AuthOrigin, StringComparison.OrdinalIgnoreCase)
                ? uri
                : null;
        }

        private static string FindCookie(IReadOnlyList<string> setCookieHeaders, string name)
        {
            foreach (var header in setCookieHeaders)
            {
                // Some stacks fold several Set-Cookie headers into one comma-separated value.
                foreach (var cookie in header.Split(','))
                {
                    var pair = cookie.Split(';')[0].Trim();
                    var separator = pair.IndexOf('=');
                    if (separator > 0 && pair.Substring(0, separator) == name && separator < pair.Length - 1)
                    {
                        return pair.Substring(separator + 1);
                    }
                }
            }

            return null;
        }

        private static string NewBrowserFlowId()
        {
            var bytes = new byte[24];
            using (var random = RandomNumberGenerator.Create())
            {
                random.GetBytes(bytes);
            }

            return "flw_" + Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static string NormalizeOrigin(string value)
        {
            if (value == null || !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                !string.IsNullOrEmpty(uri.UserInfo) || uri.AbsolutePath != "/" ||
                !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) ||
                !(uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
            {
                throw new ArgumentException(
                    "AuthOrigin must be an https origin without a path (http is allowed only for loopback hosts).",
                    nameof(value));
            }

            return uri.GetLeftPart(UriPartial.Authority);
        }

        private static string NormalizeScope(string scope)
        {
            var values = new List<string>();
            foreach (var part in (scope ?? string.Empty).Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (!values.Contains(part))
                {
                    values.Add(part);
                }
            }

            if (!values.Contains("openid"))
            {
                throw new ArgumentException("The scope must include openid.", nameof(scope));
            }

            return string.Join(" ", values);
        }

        private static void RequireText(string value, string name)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException(name + " is required.", name);
            }
        }

        /// <summary>The hosted pages' name for a provider; an undefined enum value is a caller bug.</summary>
        private static string ProviderName(Auth4Provider provider)
        {
            switch (provider)
            {
                case Auth4Provider.Discord:
                    return "discord";
                case Auth4Provider.Steam:
                    return "steam";
                case Auth4Provider.Epic:
                    return "epic";
                case Auth4Provider.Google:
                    return "google";
                case Auth4Provider.Apple:
                    return "apple";
                case Auth4Provider.Microsoft:
                    return "microsoft";
                default:
                    throw new ArgumentOutOfRangeException(nameof(provider), provider, "Use a supported auth4.dev provider.");
            }
        }

        private static string Escape(string value)
        {
            return Uri.EscapeDataString(value ?? string.Empty);
        }

        private static async Task<T> WaitAsync<T>(Task<T> task, CancellationToken cancellationToken)
        {
            if (!cancellationToken.CanBeCanceled || task.IsCompleted)
            {
                return await task;
            }

            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (cancellationToken.Register(() => cancelled.TrySetResult(true)))
            {
                if (await Task.WhenAny(task, cancelled.Task) != task)
                {
                    throw new OperationCanceledException(cancellationToken);
                }
            }

            return await task;
        }

        private sealed class TokenState
        {
            public string AccessToken;
            public DateTimeOffset AccessTokenExpiresAt;
            public string RefreshToken;
            public string IdToken;
            public string Scope;
            public string SessionId;
            public string UserId;
            public bool IsGuest;

            public Auth4Session ToSession(bool persistent)
            {
                return new Auth4Session(
                    UserId,
                    SessionId,
                    Scope,
                    IsGuest,
                    AccessTokenExpiresAt,
                    RefreshToken != null,
                    persistent && RefreshToken != null);
            }
        }

        private enum EmailAction
        {
            Add,
            Change,
            Remove,
        }

        /// <summary>
        /// Per-action request and checks for the account email intent, matching the browser SDK's
        /// EMAIL_ACTIONS: only the hosted page for the action may be opened.
        /// </summary>
        private sealed class EmailActionSettings
        {
            private static readonly EmailActionSettings AddSettings =
                new EmailActionSettings(null, "/login/add-email", "add-email", "added", "AddEmailAsync", false);

            private static readonly EmailActionSettings ChangeSettings =
                new EmailActionSettings("change", "/login/change-email", "change-email", "changed", "ChangeEmailAsync", false);

            private static readonly EmailActionSettings RemoveSettings =
                new EmailActionSettings("remove", "/login/remove-email", "remove-email", "removed", "RemoveEmailAsync", true);

            private EmailActionSettings(string action, string pagePath, string label, string done, string method, bool removes)
            {
                Action = action;
                PagePath = pagePath;
                Label = label;
                Done = done;
                Method = method;
                Removes = removes;
            }

            /// <summary>The action sent in the intent request; null for add, the server default.</summary>
            public string Action { get; }

            public string PagePath { get; }

            public string Label { get; }

            public string Done { get; }

            public string Method { get; }

            public bool Removes { get; }

            public static EmailActionSettings For(EmailAction action)
            {
                switch (action)
                {
                    case EmailAction.Change:
                        return ChangeSettings;
                    case EmailAction.Remove:
                        return RemoveSettings;
                    default:
                        return AddSettings;
                }
            }
        }

        private sealed class EmailActionOutcome
        {
            public EmailActionOutcome(Auth4Session session, string email, LinkedIdentity identity)
            {
                Session = session;
                Email = email;
                Identity = identity;
            }

            public Auth4Session Session { get; }

            public string Email { get; }

            public LinkedIdentity Identity { get; }
        }
    }
}
