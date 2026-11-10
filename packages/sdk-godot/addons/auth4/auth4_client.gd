class_name Auth4Client
extends Node
## auth4.dev client for Godot 4 games: device authorization, guest sessions, guest upgrades and
## rotating refresh tokens. Access tokens are opaque credentials for the game server to validate.
##
## Add the client to the scene tree (as a child or an autoload) before calling it. Every call is a
## coroutine that returns an Auth4Result; await it and check ok. Mirrors the Unity Auth4Client.
##
## In web exports, sign_in_with_browser() and upgrade_guest() use popup windows through
## Auth4WebBridge, as the browser SDK and Unity WebGL do. Tokens stay in memory there.

## Emitted after sign-in, refresh, upgrade or sign-out. The session is null when signed out.
signal session_changed(session: Auth4Session)

signal _gate_opened
signal _refresh_finished(result: Auth4Result)
signal _restore_finished(result: Auth4Result)

const _DEVICE_CODE_GRANT := "urn:ietf:params:oauth:grant-type:device_code"
const _FLOW_COOKIE_PREFIX := "__Host-auth4_flow_"
const _MINIMUM_POLL_INTERVAL := 5
const _SLOW_DOWN_INCREMENT := 5
const _MAX_TRANSIENT_BACKOFF := 60
const _MAX_TOKEN_LIFETIME := 86400.0
const _MAX_POLL_INTERVAL := 3600


## One popup window opened through the web bridge. finish() delivers the caller's result once;
## an upgrade window may keep listening after that (see upgrade_guest()).
class _WebWindow:
	extends RefCounted
	signal finished
	var handle := 0
	var stopped := false
	var result: Auth4Result = null

	func finish(outcome: Auth4Result) -> void:
		if result != null:
			return
		result = outcome
		finished.emit()

	func wait() -> Auth4Result:
		if result == null:
			await finished
		return result


class _TokenState:
	extends RefCounted
	var access_token := ""
	var access_token_expires_at := 0.0
	var refresh_token := ""
	var scope := ""
	var session_id := ""
	var user_id := ""
	var is_guest := false

	func to_session(persistent: bool) -> Auth4Session:
		var session := Auth4Session.new()
		session.user_id = user_id
		session.session_id = session_id
		session.scope = scope
		session.is_guest = is_guest
		session.access_token_expires_at = access_token_expires_at
		session.can_refresh = not refresh_token.is_empty()
		session.is_refresh_persistent = persistent and session.can_refresh
		return session


## Read-only. Set from Auth4ClientOptions.
var tenant_id := ""
var client_id := ""
var auth_origin := ""
var default_scope := ""
## Empty when the options were valid. Every call fails with invalid_configuration otherwise.
var configuration_error := ""

var _transport: Auth4HttpTransport
var _clock: Auth4Clock
var _secure_storage: Auth4SecureStorage
var _memory := {}
var _storage_key := ""
var _refresh_margin := 30.0
var _max_poll_attempts := 240
var _max_transient_failures := 5
var _browser_launcher := Callable()
var _redirect_uri := ""
var _web_bridge: Auth4WebBridge
var _web_window: _WebWindow = null

var _state: _TokenState = null
var _gate_busy := false
var _refreshing := false
var _restoring := false
var _upgrading := false
var _sign_out_generation := 0


func _init(options: Auth4ClientOptions = null) -> void:
	name = "Auth4Client"
	if options == null:
		configuration_error = "Auth4ClientOptions are required."
		return
	if not _matches("^ten_[A-Za-z0-9]{16,64}$", options.tenant_id):
		configuration_error = "A valid tenant ID (ten_...) is required."
		return
	if not _matches("^cli_[A-Za-z0-9]{16,64}$", options.client_id):
		configuration_error = "A valid client ID (cli_...) is required."
		return
	if (
		options.max_device_poll_attempts < 1
		or options.max_consecutive_transient_poll_failures < 0
		or options.access_token_refresh_margin < 0.0
	):
		configuration_error = "Polling and refresh limits must be positive."
		return
	var origin := _normalize_origin(options.auth_origin)
	if origin.is_empty():
		configuration_error = "auth_origin must be an https origin without a path (http is allowed only for loopback hosts)."
		return
	var scope := _normalize_scope(options.default_scope)
	if scope.is_empty():
		configuration_error = "The default scope must include openid."
		return
	if not options.redirect_uri.is_empty() and not _is_redirect_uri(options.redirect_uri):
		configuration_error = "redirect_uri must be an absolute https URL without a fragment (http only for loopback hosts)."
		return

	tenant_id = options.tenant_id
	client_id = options.client_id
	auth_origin = origin
	default_scope = scope
	_transport = options.transport if options.transport != null else Auth4HttpRequestTransport.new(self)
	_clock = options.clock if options.clock != null else Auth4Clock.new()
	_secure_storage = options.secure_storage
	_storage_key = "auth4.%s.%s.session" % [tenant_id, client_id]
	_refresh_margin = options.access_token_refresh_margin
	_max_poll_attempts = options.max_device_poll_attempts
	_max_transient_failures = options.max_consecutive_transient_poll_failures
	_browser_launcher = options.browser_launcher
	_redirect_uri = options.redirect_uri
	_web_bridge = options.web_bridge if options.web_bridge != null else Auth4WebBridge.new()
	if not _browser_launcher.is_valid() and not OS.has_feature("web"):
		_browser_launcher = func(url: String) -> void: OS.shell_open(url)


## True only when a secure storage adapter was supplied.
func is_refresh_persistent() -> bool:
	return _secure_storage != null


## The current session, or null when signed out.
func get_current_session() -> Auth4Session:
	# A refresh-only state is an incomplete restoration, not a usable session.
	if _state == null or _state.access_token.is_empty():
		return null
	return _state.to_session(is_refresh_persistent())


# ----- Device authorization (RFC 8628) -----


## Starts device authorization. value is an Auth4DeviceAuthorization.
func start_device_authorization(scope := "", cancel: Auth4CancelToken = null) -> Auth4Result:
	var refused := _refuse_if_signed_in()
	if refused != null:
		return refused
	var requested_scope := default_scope if scope.is_empty() else _normalize_scope(scope)
	if requested_scope.is_empty():
		return Auth4Result.failure("invalid_argument", "The scope must include openid.")
	if _is_cancelled(cancel):
		return _cancelled()

	var response := await _send(
		_form_request(
			_endpoint("/device/authorization?tenant_id=" + tenant_id.uri_encode()),
			{"client_id": client_id, "scope": requested_scope}
		)
	)
	var json := _parse(response.body)
	if response.status_code != 200:
		return _error_from(response, json)

	var device_code := _string(json, "device_code")
	var user_code := _string(json, "user_code")
	var verification_uri := _same_origin_uri(_string(json, "verification_uri"))
	var complete_value := _string(json, "verification_uri_complete")
	var verification_uri_complete := _same_origin_uri(complete_value)
	var expires_in := _number(json, "expires_in")
	var interval := _number(json, "interval", _MINIMUM_POLL_INTERVAL)
	if (
		device_code.is_empty()
		or user_code.is_empty()
		or verification_uri.is_empty()
		or (not complete_value.is_empty() and verification_uri_complete.is_empty())
		or expires_in <= 0.0
		or expires_in > _MAX_TOKEN_LIFETIME
		or interval > _MAX_POLL_INTERVAL
	):
		return _invalid_response(response.status_code, "The device authorization response is malformed.")

	var authorization := Auth4DeviceAuthorization.new()
	authorization._device_code = device_code
	authorization.user_code = user_code
	authorization.verification_uri = verification_uri
	authorization.verification_uri_complete = verification_uri_complete
	authorization.expires_at = _clock.now() + expires_in
	authorization.interval_seconds = maxi(_MINIMUM_POLL_INTERVAL, ceili(interval))
	authorization.scope = requested_scope
	return Auth4Result.success(authorization)


## Polls until the player approves or denies, the code expires, or `cancel` fires. value is an
## Auth4Session. Polling is bounded by the code's expiry and max_device_poll_attempts. A cancelled
## poll (reason CANCELLED) can be resumed with the same authorization until it expires.
func poll_device_authorization(
	authorization: Auth4DeviceAuthorization, cancel: Auth4CancelToken = null
) -> Auth4Result:
	if authorization == null:
		return Auth4Result.failure("invalid_argument", "authorization is required.")
	if authorization.is_completed():
		return Auth4Result.failure("invalid_state", "This device authorization has already finished.")
	if authorization._state == Auth4DeviceAuthorization._State.POLLING:
		return Auth4Result.failure("invalid_state", "This device authorization is already being polled.")

	authorization._state = Auth4DeviceAuthorization._State.POLLING
	var result := await _poll_device(authorization, cancel)
	var resumable := result.reason == Auth4Result.CANCELLED or (not result.ok and result.is_transient())
	authorization._state = (
		Auth4DeviceAuthorization._State.IDLE if resumable else Auth4DeviceAuthorization._State.COMPLETED
	)
	return result


## Starts device authorization, passes it to `show_user_code`, then polls until it finishes.
## value is an Auth4Session.
func sign_in_with_device(
	show_user_code: Callable, scope := "", cancel: Auth4CancelToken = null
) -> Auth4Result:
	if not show_user_code.is_valid():
		return Auth4Result.failure("invalid_argument", "show_user_code is required.")
	var started := await start_device_authorization(scope, cancel)
	if not started.ok:
		return started
	show_user_code.call(started.value)
	return await poll_device_authorization(started.value, cancel)


# ----- Browser sign-in (web exports) -----


## Web exports only. Signs the player in on the hosted login page in a popup, with the
## authorization code flow and S256 PKCE. value is an Auth4Session. Call it from a button's input
## handler: the popup opens before the first await, and if the browser no longer counts the input
## as a user gesture, it opens on the player's next click or tap. `provider` (for example
## "discord" or "steam") offers that sign-in method first.
##
## Fails with popup_blocked or window_closed when the window could not open or the player closed
## it, with reason DENIED when the player declined, and with unsupported_platform outside the web.
func sign_in_with_browser(provider := "", scope := "", cancel: Auth4CancelToken = null) -> Auth4Result:
	var refused := _refuse_if_signed_in()
	if refused != null:
		return refused
	if not _is_web():
		return Auth4Result.failure(
			"unsupported_platform", "sign_in_with_browser() is available only in web exports."
		)
	if _redirect_uri.is_empty():
		return Auth4Result.failure(
			"invalid_configuration", "Set Auth4ClientOptions.redirect_uri for browser sign-in."
		)
	var requested_scope := default_scope if scope.is_empty() else _normalize_scope(scope)
	if requested_scope.is_empty():
		return Auth4Result.failure("invalid_argument", "The scope must include openid.")
	if not provider.is_empty() and not _matches("^[a-z][a-z0-9_-]{0,63}$", provider):
		return Auth4Result.failure("invalid_argument", "provider must be a provider name such as \"discord\".")
	if _is_cancelled(cancel):
		return _cancelled()
	if _web_window != null and _web_window.result == null:
		return Auth4Result.failure("invalid_state", "Another auth4.dev window is already open.")

	var state := _random_value()
	var verifier := _random_value()
	var query := {
		"tenant_id": tenant_id,
		"response_type": "code",
		"client_id": client_id,
		"redirect_uri": _redirect_uri,
		"scope": requested_scope,
		"state": state,
		"code_challenge": _code_challenge(verifier),
		"code_challenge_method": "S256",
	}
	if not provider.is_empty():
		query["provider_hint"] = provider
	# Opened before the first await, so the caller's user gesture still applies.
	var window := _open_web_window(cancel)
	window.handle = _web_bridge.open_sign_in_window(
		_endpoint("/oauth/authorize?" + _query_string(query)),
		auth_origin,
		_redirect_uri,
		_on_sign_in_event.bind(window)
	)
	if window.handle == 0:
		_end_web_window(window, false)
		return Auth4Result.failure(
			"invalid_configuration", "redirect_uri must be a page on the game's own origin."
		)

	var opened := await window.wait()
	if not opened.ok:
		return opened
	var callback := _parse_query(opened.value)
	var states: Array = callback.get("state", [])
	if states.size() != 1 or states[0] != state:
		return _invalid_response(0, "The sign-in callback state does not match.")
	var issuers: Array = callback.get("iss", [])
	if issuers.size() > 1 or (issuers.size() == 1 and issuers[0] != _issuer()):
		return _invalid_response(0, "The sign-in callback came from another issuer.")
	var errors: Array = callback.get("error", [])
	var codes: Array = callback.get("code", [])
	if errors.size() == 1 and codes.is_empty():
		var failure := Auth4Result.failure(errors[0])
		if failure.error == "access_denied":
			failure.reason = Auth4Result.DENIED
		return failure
	if codes.size() != 1 or String(codes[0]).is_empty() or not errors.is_empty():
		return _invalid_response(0, "The sign-in callback has no authorization code.")
	if _is_cancelled(cancel):
		return _cancelled()

	# Not cancellable once sent: the code is single-use.
	var response := await _send(
		_form_request(
			_token_endpoint(),
			{
				"grant_type": "authorization_code",
				"code": codes[0],
				"redirect_uri": _redirect_uri,
				"client_id": client_id,
				"code_verifier": verifier,
			}
		)
	)
	var json := _parse(response.body)
	if response.status_code != 200:
		return _error_from(response, json)
	var tokens := _read_tokens(json)
	if tokens == null:
		return _invalid_response(response.status_code, "The token response is malformed.")
	return await _adopt_new_session(tokens)


# ----- Guest sessions and upgrades -----


## Creates a new guest player. value is an Auth4Session. Fails with invalid_state if a session is
## already active, so a guest is never abandoned silently.
func sign_in_as_guest(cancel: Auth4CancelToken = null) -> Auth4Result:
	var refused := _refuse_if_signed_in()
	if refused != null:
		return refused
	if _is_cancelled(cancel):
		return _cancelled()

	var response := await _send(
		_json_request(_guest_endpoint(""), {"client_id": client_id, "browser_flow_id": _new_browser_flow_id()})
	)
	var json := _parse(response.body)
	if not _is_success(response):
		return _error_from(response, json)
	var user_id := _string(json, "user_id")
	if user_id.is_empty():
		return _invalid_response(response.status_code, "The guest response has no user ID.")
	var tokens := _read_tokens(json)
	if tokens == null:
		return _invalid_response(response.status_code, "The token response is malformed.")
	tokens.user_id = user_id
	tokens.is_guest = true
	return await _adopt_new_session(tokens)


## Creates a linking intent for the current guest, for linking an email address without leaving the
## game. value is an Auth4GuestUpgradeFlow. Complete it with start_email_verification(),
## confirm_email_verification() and complete_guest_upgrade(). Not available in web exports, where
## the browser owns the cookie and Origin headers these steps need; use upgrade_guest() there.
func begin_guest_upgrade(cancel: Auth4CancelToken = null) -> Auth4Result:
	if configuration_error.is_empty() and _is_web():
		return Auth4Result.failure(
			"unsupported_platform", "In web exports, upgrade guests with upgrade_guest()."
		)
	var token := await get_access_token()
	if not token.ok:
		return token
	var current := _state
	if current == null or not current.is_guest:
		return Auth4Result.failure("invalid_state", "Only an active guest session can be upgraded.")
	if _is_cancelled(cancel):
		return _cancelled()

	var flow_id := _new_browser_flow_id()
	var request := _json_request(
		_guest_endpoint("/linking-intent"), {"client_id": client_id, "browser_flow_id": flow_id}
	)
	request.headers.append("Authorization: Bearer " + token.value)
	var response := await _send(request)
	var json := _parse(response.body)
	if not _is_success(response):
		return _error_from(response, json)

	var proof := _object(json, "upgrade_proof")
	var expires_in := _number(proof, "expires_in")
	var cookie := _find_cookie(response.set_cookie_headers(), _FLOW_COOKIE_PREFIX + flow_id)
	if proof.is_empty() or expires_in <= 0.0 or cookie.is_empty():
		return _invalid_response(response.status_code, "The linking intent response is malformed.")

	var flow := Auth4GuestUpgradeFlow.new()
	flow.browser_flow_id = flow_id
	flow._flow_cookie = cookie
	flow.guest_user_id = current.user_id
	flow._session_id = current.session_id
	flow.expires_at = _clock.now() + expires_in
	return Auth4Result.success(flow)


## Sends a verification code to the email address that will be linked to the guest.
func start_email_verification(
	flow: Auth4GuestUpgradeFlow, email: String, cancel: Auth4CancelToken = null
) -> Auth4Result:
	var unusable := _refuse_flow(flow)
	if unusable != null:
		return unusable
	if email.strip_edges().is_empty():
		return Auth4Result.failure("invalid_argument", "email is required.")
	if _is_cancelled(cancel):
		return _cancelled()

	var response := await _send(
		_flow_request(
			flow,
			"/email/verification/start",
			{
				"client_id": client_id,
				"browser_flow_id": flow.browser_flow_id,
				"email": email.strip_edges(),
			},
			true
		)
	)
	if not _is_success(response):
		return _error_from(response, _parse(response.body))
	return Auth4Result.success()


## Confirms the emailed code. value is the one-time proof ID for complete_guest_upgrade().
func confirm_email_verification(
	flow: Auth4GuestUpgradeFlow, email: String, code: String, cancel: Auth4CancelToken = null
) -> Auth4Result:
	var unusable := _refuse_flow(flow)
	if unusable != null:
		return unusable
	if email.strip_edges().is_empty() or code.strip_edges().is_empty():
		return Auth4Result.failure("invalid_argument", "email and code are required.")
	if _is_cancelled(cancel):
		return _cancelled()

	var response := await _send(
		_flow_request(
			flow,
			"/email/verification/confirm",
			{
				"client_id": client_id,
				"browser_flow_id": flow.browser_flow_id,
				"email": email.strip_edges(),
				"code": code.strip_edges(),
			},
			true
		)
	)
	var json := _parse(response.body)
	if not _is_success(response):
		return _error_from(response, json)
	var proof_id := _string(_object(json, "proof"), "proof_id")
	if proof_id.is_empty():
		return _invalid_response(response.status_code, "The verification response has no proof.")
	return Auth4Result.success(proof_id)


## Links the proven email address to the current guest. value is an Auth4GuestUpgradeResult: the
## player keeps the same user ID and receives a replacement session. An error of identity_in_use
## (reason CONFLICT) leaves the guest session unchanged.
func complete_guest_upgrade(
	flow: Auth4GuestUpgradeFlow, proof_id: String, cancel: Auth4CancelToken = null
) -> Auth4Result:
	var unusable := _refuse_flow(flow)
	if unusable != null:
		return unusable
	if proof_id.strip_edges().is_empty():
		return Auth4Result.failure("invalid_argument", "proof_id is required.")
	var token := await get_access_token()
	if not token.ok:
		return token
	if _is_cancelled(cancel):
		return _cancelled()

	await _gate_enter()
	var current := _state
	if (
		current == null
		or not current.is_guest
		or current.access_token.is_empty()
		or current.session_id != flow._session_id
		or current.user_id != flow.guest_user_id
	):
		_gate_exit()
		return Auth4Result.failure(
			"invalid_state", "The guest session that started this upgrade is no longer active."
		)

	# The guest upgrade endpoint takes the bearer token instead of the hosted-login Origin check.
	var request := _flow_request(
		flow,
		"/guest/upgrade",
		{"client_id": client_id, "browser_flow_id": flow.browser_flow_id, "proof_id": proof_id},
		false
	)
	request.headers.append("Authorization: Bearer " + current.access_token)
	# Not cancellable once sent: a successful upgrade revokes the guest session, so the replacement
	# credentials must not be dropped.
	var response := await _send(request)
	var json := _parse(response.body)
	var result: Auth4Result
	if not _is_success(response):
		result = _error_from(response, json)
		if result.error == "identity_in_use":
			result.reason = Auth4Result.CONFLICT
	else:
		result = await _commit_upgrade(response, json, flow.guest_user_id)
	_gate_exit()
	return result


## Upgrades the current guest by email or an enabled social provider in the system browser.
## value is an Auth4GuestUpgradeResult; the guest's tokens are replaced in one step and the user ID
## is unchanged. `provider` may be a social provider name to offer that method first, for a
## "Save progress with Steam" button; the player still confirms on the page.
##
## It creates an upgrade intent, opens the page with the browser launcher, reports progress to
## `on_progress` (an Auth4GuestUpgradeProgress) and polls at the server's interval until the player
## finishes. Failures that end the upgrade have reason CONFLICT, EXPIRED, DENIED or CANCELLED.
##
## In web exports it opens the hosted page in a popup instead and runs the window protocol: call it
## from a button's input handler, as for sign_in_with_browser(). The guest access token is posted
## only to the auth origin, in answer to the page's ready message. Extra failures there are
## popup_blocked, window_closed and invalid_session (the guest session ended). After a CONFLICT the
## window lets the player link another account; a later success still replaces the session and
## emits session_changed.
func upgrade_guest(
	provider := "", on_progress := Callable(), cancel: Auth4CancelToken = null
) -> Auth4Result:
	if not configuration_error.is_empty():
		return _misconfigured()
	if provider != "" and provider not in ["discord", "steam", "epic", "google", "apple", "microsoft"]:
		return Auth4Result.failure(
			"invalid_argument",
			"provider must be empty, discord, steam, epic, google, apple or microsoft."
		)
	if _is_web():
		return await _upgrade_guest_in_window(provider, on_progress, cancel)
	if not _browser_launcher.is_valid():
		return Auth4Result.failure(
			"unsupported_platform", "upgrade_guest() needs a browser launcher on this platform."
		)
	if _upgrading:
		return Auth4Result.failure("invalid_state", "A guest upgrade is already in progress.")

	_upgrading = true
	var result := await _upgrade_guest_core(provider, on_progress, cancel)
	_upgrading = false
	return result


# ----- Tokens -----


## Returns a valid access token as value, refreshing first when it is about to expire.
func get_access_token() -> Auth4Result:
	if not configuration_error.is_empty():
		return _misconfigured()
	var current := _state
	if current == null:
		return Auth4Result.failure("login_required", "No session is active.")
	if (
		not current.access_token.is_empty()
		and current.access_token_expires_at - _refresh_margin > _clock.now()
	):
		return Auth4Result.success(current.access_token)
	if current.refresh_token.is_empty():
		return Auth4Result.failure(
			"login_required", "The access token expired and the session cannot be refreshed."
		)

	var refreshed := await refresh()
	if not refreshed.ok:
		return refreshed
	if _state == null or _state.access_token.is_empty():
		return Auth4Result.failure("login_required", "No session is active.")
	return Auth4Result.success(_state.access_token)


## Rotates the refresh token. value is an Auth4Session. Concurrent callers share one request, so
## parallel game requests never present the same refresh token twice. The request always runs to
## completion, so the rotated credential is never lost.
func refresh() -> Auth4Result:
	if not configuration_error.is_empty():
		return _misconfigured()
	if _refreshing:
		return await _refresh_finished
	_refreshing = true
	var result := await _refresh_core()
	_refreshing = false
	_refresh_finished.emit(result)
	return result


## Restores a session from secure storage. value is true only once a usable access token exists,
## and false when nothing usable is stored or the stored credential was rejected (it is then
## cleared). Transient failures are returned as errors and keep the stored credential, so calling
## again retries the refresh. Concurrent callers share one outcome.
func try_restore_session() -> Auth4Result:
	if not configuration_error.is_empty():
		return _misconfigured()
	if _state != null and not _state.access_token.is_empty():
		return Auth4Result.success(true)
	if _restoring:
		return await _restore_finished
	_restoring = true
	var result := await _restore_core()
	_restoring = false
	_restore_finished.emit(result)
	return result


func _restore_core() -> Auth4Result:
	var generation := _sign_out_generation
	await _gate_enter()
	if _state != null and not _state.access_token.is_empty():
		_gate_exit()
		return Auth4Result.success(true)
	# A refresh-only state left by a transient failure is retried without reloading.
	if _state == null or _state.refresh_token.is_empty():
		var raw: Variant = await _storage_load()
		var stored := _parse(raw if raw is String else "")
		var refresh_token := _string(stored, "refresh_token")
		if refresh_token.is_empty():
			if raw != null:
				await _delete_stored_quietly()
			_gate_exit()
			return Auth4Result.success(false)
		var restored := _TokenState.new()
		restored.refresh_token = refresh_token
		restored.user_id = _string(stored, "user_id")
		restored.is_guest = _string(stored, "guest") == "true"
		_state = restored
	_gate_exit()

	var refreshed := await refresh()
	if _sign_out_generation != generation:
		# Signed out while restoring: nothing to restore.
		return Auth4Result.success(false)
	if refreshed.ok:
		return Auth4Result.success(true)
	if refreshed.reason == Auth4Result.SESSION_EXPIRED:
		return Auth4Result.success(false)
	return refreshed


## Revokes the refresh credential and clears local state. Returns false when the server could not
## confirm revocation; the local session is cleared either way.
func sign_out() -> bool:
	if not configuration_error.is_empty():
		return false
	await _gate_enter()
	var current := _state
	var revoked := true
	if current != null:
		var has_refresh := not current.refresh_token.is_empty()
		revoked = await _revoke_quietly(
			current.refresh_token if has_refresh else current.access_token, has_refresh
		)
	await _clear_local()
	_sign_out_generation += 1
	_gate_exit()
	return revoked


# ----- Internals -----


func _poll_device(authorization: Auth4DeviceAuthorization, cancel: Auth4CancelToken) -> Auth4Result:
	var interval := authorization.interval_seconds
	var transient_failures := 0
	var attempt := 0
	while true:
		attempt += 1
		if attempt > _max_poll_attempts or _clock.now() >= authorization.expires_at:
			return Auth4Result.failure("expired_token", "", 0, Auth4Result.EXPIRED)
		await _clock.delay(interval, cancel)
		if _is_cancelled(cancel):
			return _cancelled()
		if _clock.now() >= authorization.expires_at:
			return Auth4Result.failure("expired_token", "", 0, Auth4Result.EXPIRED)

		var response := await _send(
			_form_request(
				_token_endpoint(),
				{
					"grant_type": _DEVICE_CODE_GRANT,
					"client_id": client_id,
					"device_code": authorization._device_code,
				}
			)
		)
		var json := _parse(response.body)
		if response.status_code == 200:
			var tokens := _read_tokens(json)
			if tokens == null:
				return _invalid_response(response.status_code, "The token response is malformed.")
			return await _adopt_new_session(tokens)

		var failure := _error_from(response, json)
		match failure.error:
			"authorization_pending":
				transient_failures = 0
				continue
			"slow_down":
				transient_failures = 0
				interval += _SLOW_DOWN_INCREMENT
				continue
			"access_denied":
				failure.reason = Auth4Result.DENIED
				return failure
			"expired_token":
				failure.reason = Auth4Result.EXPIRED
				return failure
			"account_suspended":
				failure.reason = Auth4Result.SUSPENDED
				return failure
		if failure.is_transient() and transient_failures < _max_transient_failures:
			transient_failures += 1
			interval = _backoff(interval)
			continue
		return failure
	return null


func _upgrade_guest_core(
	provider_hint: String, on_progress: Callable, cancel: Auth4CancelToken
) -> Auth4Result:
	var token := await get_access_token()
	if not token.ok:
		return token
	var guest := _state
	var generation := _sign_out_generation
	if guest == null or not guest.is_guest or guest.user_id.is_empty():
		return Auth4Result.failure("invalid_state", "Only an active guest session can be upgraded.")
	if _is_cancelled(cancel):
		return _cancelled()

	var request := _json_request(_guest_endpoint("/upgrade-intent"), {"client_id": client_id})
	request.headers.append("Authorization: Bearer " + token.value)
	var response := await _send(request)
	var json := _parse(response.body)
	if not _is_success(response):
		return _error_from(response, json)

	var intent := _string(json, "intent")
	var poll_secret := _string(json, "poll_secret")
	var upgrade_uri := _same_origin_uri(_string(json, "upgrade_uri"))
	var expires_in := _number(json, "expires_in")
	var interval := _number(json, "interval", _MINIMUM_POLL_INTERVAL)
	if (
		not _matches("^gui_[A-Za-z0-9_-]{32,64}$", intent)
		or not _matches("^gps_[A-Za-z0-9_-]{43,86}$", poll_secret)
		or _uri_path(upgrade_uri) != "/login/upgrade"
		or expires_in <= 0.0
		or expires_in > _MAX_TOKEN_LIFETIME
		or interval > _MAX_POLL_INTERVAL
	):
		return _invalid_response(response.status_code, "The upgrade intent response is malformed.")
	if not provider_hint.is_empty():
		# AUTH4D-343: the hint joins the query; the verifier stays in the fragment after it.
		var fragment_at := upgrade_uri.find("#")
		var fragment := "" if fragment_at < 0 else upgrade_uri.substr(fragment_at)
		var page := upgrade_uri if fragment_at < 0 else upgrade_uri.substr(0, fragment_at)
		upgrade_uri = page + ("&" if page.contains("?") else "?") + "provider=" + provider_hint + fragment

	var expires_at := _clock.now() + expires_in
	var poll_interval := _poll_interval(interval)
	_report(on_progress, Auth4GuestUpgradeProgress.Stage.OPENING_BROWSER, upgrade_uri, expires_at, poll_interval, 0)
	_browser_launcher.call(upgrade_uri)

	var transient_failures := 0
	var attempt := 0
	while true:
		attempt += 1
		_report(
			on_progress,
			Auth4GuestUpgradeProgress.Stage.WAITING_FOR_PLAYER,
			upgrade_uri,
			expires_at,
			poll_interval,
			attempt - 1
		)
		if attempt > _max_poll_attempts or _clock.now() >= expires_at:
			return Auth4Result.failure("expired_token", "", 0, Auth4Result.EXPIRED)
		await _clock.delay(poll_interval, cancel)
		if _is_cancelled(cancel):
			return _cancelled()
		if _clock.now() >= expires_at:
			return Auth4Result.failure("expired_token", "", 0, Auth4Result.EXPIRED)

		# Not cancellable once sent: the token set is released exactly once, and the guest session
		# has already been revoked when it is.
		var poll := await _send(
			_json_request(
				_guest_endpoint("/upgrade-intent/token"),
				{"client_id": client_id, "intent": intent, "poll_secret": poll_secret}
			)
		)
		var body := _parse(poll.body)
		if poll.status_code == 200:
			await _gate_enter()
			var committed: Auth4Result
			if _sign_out_generation != generation or (_state != null and _state.user_id != guest.user_id):
				var tokens := _read_tokens(body)
				if tokens != null:
					await _revoke_tokens_quietly(tokens)
				committed = Auth4Result.failure(
					"invalid_state",
					"The guest signed out before the upgrade finished; sign in with the linked account."
				)
			else:
				committed = await _commit_upgrade(poll, body, guest.user_id)
			_gate_exit()
			if committed.ok:
				_report(
					on_progress,
					Auth4GuestUpgradeProgress.Stage.COMPLETED,
					upgrade_uri,
					expires_at,
					poll_interval,
					attempt
				)
			return committed

		var failure := _error_from(poll, body)
		var server_interval := _number(body, "interval")
		match failure.error:
			"authorization_pending":
				transient_failures = 0
				if server_interval > 0.0:
					poll_interval = maxi(poll_interval, _poll_interval(server_interval))
				continue
			"slow_down":
				transient_failures = 0
				poll_interval = maxi(
					poll_interval + _SLOW_DOWN_INCREMENT,
					_poll_interval(server_interval) if server_interval > 0.0 else 0
				)
				continue
			"identity_in_use":
				failure.reason = Auth4Result.CONFLICT
				return failure
			"access_denied":
				failure.reason = Auth4Result.DENIED
				return failure
			"expired_token":
				failure.reason = Auth4Result.EXPIRED
				return failure
		if failure.is_transient() and transient_failures < _max_transient_failures:
			transient_failures += 1
			poll_interval = _backoff(poll_interval)
			continue
		return failure
	return null


func _upgrade_guest_in_window(
	provider_hint: String, on_progress: Callable, cancel: Auth4CancelToken
) -> Auth4Result:
	# Nothing awaits before the window opens, so the caller's user gesture still applies.
	var guest := _state
	if guest == null:
		return Auth4Result.failure("login_required", "No session is active.")
	if not guest.is_guest or guest.user_id.is_empty():
		return Auth4Result.failure("invalid_state", "Only an active guest session can be upgraded.")
	if _is_cancelled(cancel):
		return _cancelled()
	if _web_window != null and _web_window.result == null:
		return Auth4Result.failure("invalid_state", "Another auth4.dev window is already open.")

	# The URL names only the tenant and client; the guest token travels by postMessage.
	var query := {"tenant_id": tenant_id, "client_id": client_id}
	if not provider_hint.is_empty():
		query["provider"] = provider_hint
	var upgrade_uri := _endpoint("/login/upgrade?" + _query_string(query))
	_report(on_progress, Auth4GuestUpgradeProgress.Stage.OPENING_BROWSER, upgrade_uri, INF, 0, 0)
	var window := _open_web_window(cancel)
	window.handle = _web_bridge.open_upgrade_window(
		upgrade_uri,
		auth_origin,
		_on_upgrade_event.bind(window, _sign_out_generation, guest.user_id, upgrade_uri, on_progress)
	)
	if window.handle == 0:
		_end_web_window(window, false)
		return Auth4Result.failure("invalid_state", "The upgrade window could not be opened.")
	return await window.wait()


## Replaces any earlier window, which may still be listening after a CONFLICT.
func _open_web_window(cancel: Auth4CancelToken) -> _WebWindow:
	if _web_window != null:
		_end_web_window(_web_window, false)
	var window := _WebWindow.new()
	_web_window = window
	if cancel != null:
		var on_cancel := func() -> void:
			if not window.stopped:
				_end_web_window(window, true)
				window.finish(_cancelled())
		cancel.cancelled.connect(on_cancel, CONNECT_ONE_SHOT)
	return window


## Stops listening to the window; `close` also closes it, otherwise the page shows its outcome.
func _end_web_window(window: _WebWindow, close: bool) -> void:
	if window.stopped:
		return
	window.stopped = true
	if window.handle != 0:
		if close:
			_web_bridge.close_window(window.handle)
		else:
			_web_bridge.release_window(window.handle)
	if _web_window == window:
		_web_window = null


func _on_sign_in_event(kind: String, data: String, window: _WebWindow) -> void:
	if window.stopped:
		return
	match kind:
		"callback":
			_end_web_window(window, false)
			window.finish(Auth4Result.success(data))
		"blocked":
			_end_web_window(window, false)
			window.finish(_popup_blocked())
		"closed":
			_end_web_window(window, false)
			window.finish(_window_closed())


func _on_upgrade_event(
	kind: String,
	data: String,
	window: _WebWindow,
	generation: int,
	guest_user_id: String,
	upgrade_uri: String,
	on_progress: Callable
) -> void:
	if window.stopped:
		return
	match kind:
		"opened":
			_report(
				on_progress, Auth4GuestUpgradeProgress.Stage.WAITING_FOR_PLAYER, upgrade_uri, INF, 0, 0
			)
		"ready":
			var ready := _parse(data)
			if _string(ready, "tenant_id") == tenant_id and _string(ready, "client_id") == client_id:
				_send_guest_token(window, generation, guest_user_id)
		"complete":
			_complete_window_upgrade(
				window, _parse(data), generation, guest_user_id, upgrade_uri, on_progress
			)
		"error":
			if data == "identity_in_use":
				# The window offers to link a different account, so keep answering it.
				window.finish(Auth4Result.failure("identity_in_use", "", 409, Auth4Result.CONFLICT))
			elif data == "invalid_session":
				_end_web_window(window, false)
				window.finish(_session_ended())
		"cancelled":
			_end_web_window(window, false)
			window.finish(Auth4Result.failure("access_denied", "", 0, Auth4Result.DENIED))
		"blocked":
			_end_web_window(window, false)
			window.finish(_popup_blocked())
		"closed":
			_end_web_window(window, false)
			window.finish(_window_closed())


## Answers the window's ready message, only while the guest that started the upgrade is live.
func _send_guest_token(window: _WebWindow, generation: int, guest_user_id: String) -> void:
	var token: Auth4Result = null
	if _guest_is_live(generation, guest_user_id):
		token = await get_access_token()
	if window.stopped:
		return
	if token != null and token.ok and _guest_is_live(generation, guest_user_id):
		_web_bridge.send_access_token(window.handle, token.value)
		return
	_end_web_window(window, false)
	window.finish(token if token != null and token.is_transient() else _session_ended())


func _complete_window_upgrade(
	window: _WebWindow,
	json: Dictionary,
	generation: int,
	guest_user_id: String,
	upgrade_uri: String,
	on_progress: Callable
) -> void:
	# Stop listening first, so a repeated message cannot commit twice. The guest session is already
	# revoked on the server, so the new credentials are committed even if the caller cancelled.
	_end_web_window(window, false)
	await _gate_enter()
	var committed: Auth4Result
	if _sign_out_generation != generation or (_state != null and _state.user_id != guest_user_id):
		var tokens := _read_tokens(json)
		if tokens != null:
			await _revoke_tokens_quietly(tokens)
		committed = Auth4Result.failure(
			"invalid_state",
			"The guest signed out before the upgrade finished; sign in with the linked account."
		)
	else:
		committed = await _commit_upgrade(Auth4HttpTransport.Response.new(200), json, guest_user_id)
	_gate_exit()
	if committed.ok:
		_report(on_progress, Auth4GuestUpgradeProgress.Stage.COMPLETED, upgrade_uri, INF, 0, 0)
	window.finish(committed)


func _guest_is_live(generation: int, guest_user_id: String) -> bool:
	return (
		_sign_out_generation == generation
		and _state != null
		and _state.is_guest
		and _state.user_id == guest_user_id
	)


## Caller holds the gate. Replaces the guest token set with the upgraded one, so storage and memory
## switch together. The local guest session may already be gone if a refresh hit the revoked guest
## token meanwhile; it is replaced all the same.
func _commit_upgrade(
	response: Auth4HttpTransport.Response, json: Dictionary, guest_user_id: String
) -> Auth4Result:
	var tokens := _read_tokens(json)
	if tokens == null:
		return _invalid_response(response.status_code, "The token response is malformed.")
	var identity := _object(json, "identity")
	var user_id := _string(json, "user_id")
	if user_id != guest_user_id or identity.is_empty():
		await _revoke_tokens_quietly(tokens)
		await _clear_local()
		return _invalid_response(response.status_code, "The upgrade did not preserve the guest user.")
	tokens.user_id = user_id
	tokens.is_guest = false
	var upgraded := Auth4GuestUpgradeResult.new()
	upgraded.session = await _commit(tokens)
	upgraded.identity_id = _string(identity, "identity_id")
	upgraded.provider = _string(identity, "provider")
	return Auth4Result.success(upgraded)


func _refresh_core() -> Auth4Result:
	await _gate_enter()
	var current := _state
	if current == null or current.refresh_token.is_empty():
		_gate_exit()
		return Auth4Result.failure("login_required", "No refresh credential is available.")

	var response := await _send(
		_form_request(
			_token_endpoint(),
			{"grant_type": "refresh_token", "client_id": client_id, "refresh_token": current.refresh_token}
		)
	)
	var json := _parse(response.body)
	var result: Auth4Result
	if response.status_code == 200:
		var next := _read_tokens(json)
		if next == null:
			result = _invalid_response(response.status_code, "The token response is malformed.")
		else:
			next.user_id = current.user_id
			next.is_guest = current.is_guest
			if next.session_id.is_empty():
				next.session_id = current.session_id
			result = Auth4Result.success(await _commit(next))
	else:
		result = _error_from(response, json)
		if result.error == "invalid_grant" or result.error == "account_suspended":
			result.reason = Auth4Result.SESSION_EXPIRED
			if result.error == "account_suspended":
				result.reason = Auth4Result.SUSPENDED
			await _clear_local()
	_gate_exit()
	return result


func _adopt_new_session(tokens: _TokenState) -> Auth4Result:
	await _gate_enter()
	var result: Auth4Result
	if _state != null:
		await _revoke_tokens_quietly(tokens)
		result = Auth4Result.failure(
			"invalid_state", "Another session became active; sign out before signing in again."
		)
	else:
		result = Auth4Result.success(await _commit(tokens))
	_gate_exit()
	return result


## Caller holds the gate. Storage is written before memory so the stored and live tokens agree.
func _commit(next: _TokenState) -> Auth4Session:
	var stored := true
	if next.refresh_token.is_empty():
		stored = await _storage_delete()
	else:
		var record := {
			"v": "1",
			"refresh_token": next.refresh_token,
			"user_id": next.user_id,
			"guest": "true" if next.is_guest else "false",
		}
		stored = await _storage_save(JSON.stringify(record))
	if not stored:
		# A stale stored token would be replayed after restart and revoke the family; drop it.
		await _delete_stored_quietly()
	_state = next
	var session := next.to_session(is_refresh_persistent())
	session_changed.emit(session)
	return session


func _clear_local() -> void:
	var had_session := _state != null
	_state = null
	await _delete_stored_quietly()
	if had_session:
		session_changed.emit(null)


func _storage_load() -> Variant:
	if _secure_storage == null:
		return _memory.get(_storage_key)
	return await _secure_storage.read(_storage_key)


func _storage_save(value: String) -> bool:
	if _secure_storage == null:
		_memory[_storage_key] = value
		return true
	return await _secure_storage.write(_storage_key, value)


func _storage_delete() -> bool:
	if _secure_storage == null:
		_memory.erase(_storage_key)
		return true
	return await _secure_storage.delete(_storage_key)


func _delete_stored_quietly() -> void:
	# Storage adapters may be unavailable; the in-memory session is still cleared.
	await _storage_delete()


func _revoke_tokens_quietly(tokens: _TokenState) -> bool:
	var has_refresh := not tokens.refresh_token.is_empty()
	return await _revoke_quietly(tokens.refresh_token if has_refresh else tokens.access_token, has_refresh)


func _revoke_quietly(token: String, is_refresh_token: bool) -> bool:
	if token.is_empty():
		return true
	var response := await _send(
		_form_request(
			_endpoint("/oauth/revoke?tenant_id=" + tenant_id.uri_encode()),
			{
				"client_id": client_id,
				"token": token,
				"token_type_hint": "refresh_token" if is_refresh_token else "access_token",
			}
		)
	)
	return _is_success(response)


func _gate_enter() -> void:
	while _gate_busy:
		await _gate_opened
	_gate_busy = true


func _gate_exit() -> void:
	_gate_busy = false
	_gate_opened.emit()


func _report(
	on_progress: Callable,
	stage: Auth4GuestUpgradeProgress.Stage,
	upgrade_uri: String,
	expires_at: float,
	interval: int,
	attempts: int
) -> void:
	if not on_progress.is_valid():
		return
	var progress := Auth4GuestUpgradeProgress.new()
	progress.stage = stage
	progress.upgrade_uri = upgrade_uri
	progress.expires_at = expires_at
	progress.interval_seconds = interval
	progress.poll_attempts = attempts
	on_progress.call(progress)


func _read_tokens(json: Dictionary) -> _TokenState:
	var access_token := _string(json, "access_token")
	var expires_in := _number(json, "expires_in")
	if (
		access_token.is_empty()
		or _string(json, "token_type").to_lower() != "bearer"
		or expires_in <= 0.0
		or expires_in > _MAX_TOKEN_LIFETIME
	):
		return null
	var tokens := _TokenState.new()
	tokens.access_token = access_token
	tokens.access_token_expires_at = _clock.now() + expires_in
	tokens.refresh_token = _string(json, "refresh_token")
	tokens.scope = _string(json, "scope")
	tokens.session_id = _string(json, "session_id")
	return tokens


func _send(request: Dictionary) -> Auth4HttpTransport.Response:
	var response: Auth4HttpTransport.Response = await _transport.send(
		"POST", request.url, PackedStringArray(request.headers), request.body
	)
	return response if response != null else Auth4HttpTransport.Response.new()


func _form_request(url: String, fields: Dictionary) -> Dictionary:
	return {
		"url": url,
		"headers": ["Content-Type: application/x-www-form-urlencoded", "Accept: application/json"],
		"body": _query_string(fields),
	}


func _json_request(url: String, fields: Dictionary) -> Dictionary:
	return {
		"url": url,
		"headers": ["Content-Type: application/json", "Accept: application/json"],
		"body": JSON.stringify(fields),
	}


func _flow_request(
	flow: Auth4GuestUpgradeFlow, path: String, fields: Dictionary, with_origin: bool
) -> Dictionary:
	var request := _json_request(_endpoint("/t/" + tenant_id.uri_encode() + path), fields)
	request.headers.append("Cookie: " + _FLOW_COOKIE_PREFIX + flow.browser_flow_id + "=" + flow._flow_cookie)
	if with_origin:
		# Hosted-login endpoints require the auth origin as a CSRF check. Native HTTP has no ambient
		# browser credentials; the flow cookie is held only by this client.
		request.headers.append("Origin: " + auth_origin)
	return request


func _token_endpoint() -> String:
	return _endpoint("/oauth/token?tenant_id=" + tenant_id.uri_encode())


func _guest_endpoint(suffix: String) -> String:
	return _endpoint("/t/" + tenant_id.uri_encode() + "/guest" + suffix)


func _endpoint(path_and_query: String) -> String:
	return auth_origin + path_and_query


func _same_origin_uri(value: String) -> String:
	if value.is_empty() or not value.to_lower().begins_with(auth_origin.to_lower() + "/"):
		return ""
	for character in [" ", "\t", "\n", "\r", "\\"]:
		if value.contains(character):
			return ""
	return value


func _uri_path(uri: String) -> String:
	if uri.is_empty():
		return ""
	var path := uri.substr(auth_origin.length())
	for separator in ["?", "#"]:
		var index := path.find(separator)
		if index >= 0:
			path = path.substr(0, index)
	return path


func _refuse_if_signed_in() -> Auth4Result:
	if not configuration_error.is_empty():
		return _misconfigured()
	if _state != null:
		return Auth4Result.failure(
			"invalid_state",
			"A session is already active. Upgrade the guest or sign out before signing in again."
		)
	return null


func _refuse_flow(flow: Auth4GuestUpgradeFlow) -> Auth4Result:
	if not configuration_error.is_empty():
		return _misconfigured()
	if flow == null:
		return Auth4Result.failure("invalid_argument", "flow is required.")
	if _clock.now() >= flow.expires_at:
		return Auth4Result.failure("expired_token", "The guest upgrade expired; begin a new upgrade.")
	return null


func _misconfigured() -> Auth4Result:
	return Auth4Result.failure("invalid_configuration", configuration_error)


func _is_web() -> bool:
	return _web_bridge != null and _web_bridge.is_supported()


func _issuer() -> String:
	return auth_origin + "/t/" + tenant_id


static func _popup_blocked() -> Auth4Result:
	return Auth4Result.failure("popup_blocked", "The browser blocked the auth4.dev window.")


static func _window_closed() -> Auth4Result:
	return Auth4Result.failure("window_closed", "The player closed the auth4.dev window.")


static func _session_ended() -> Auth4Result:
	return Auth4Result.failure("invalid_session", "The guest session ended during the upgrade.")


static func _is_cancelled(cancel: Auth4CancelToken) -> bool:
	return cancel != null and cancel.is_cancelled


static func _cancelled() -> Auth4Result:
	return Auth4Result.failure("cancelled", "", 0, Auth4Result.CANCELLED)


static func _is_success(response: Auth4HttpTransport.Response) -> bool:
	return response.status_code >= 200 and response.status_code <= 299


static func _error_from(response: Auth4HttpTransport.Response, json: Dictionary) -> Auth4Result:
	var error := _string(json, "error")
	if error.is_empty():
		if response.status_code == 0:
			return Auth4Result.failure("network_error", "The auth4.dev API could not be reached.")
		error = "server_error" if response.status_code >= 500 else "invalid_response"
	return Auth4Result.failure(error, _string(json, "error_description"), response.status_code)


static func _invalid_response(status: int, description: String) -> Auth4Result:
	return Auth4Result.failure("invalid_response", description, status)


static func _backoff(interval: int) -> int:
	return maxi(interval, mini(interval * 2, _MAX_TRANSIENT_BACKOFF))


static func _poll_interval(seconds: float) -> int:
	return mini(_MAX_POLL_INTERVAL, maxi(_MINIMUM_POLL_INTERVAL, ceili(seconds)))


static func _parse(text: String) -> Dictionary:
	if text.is_empty():
		return {}
	var parsed: Variant = JSON.parse_string(text)
	return parsed if parsed is Dictionary else {}


static func _string(json: Dictionary, key: String) -> String:
	var value: Variant = json.get(key)
	return value if value is String else ""


static func _number(json: Dictionary, key: String, fallback := 0.0) -> float:
	var value: Variant = json.get(key)
	return float(value) if value is float or value is int else fallback


static func _object(json: Dictionary, key: String) -> Dictionary:
	var value: Variant = json.get(key)
	return value if value is Dictionary else {}


static func _find_cookie(set_cookie_headers: PackedStringArray, cookie_name: String) -> String:
	for header in set_cookie_headers:
		# Some stacks fold several Set-Cookie headers into one comma-separated value.
		for cookie in header.split(","):
			var pair := cookie.split(";")[0].strip_edges()
			var separator := pair.find("=")
			if separator > 0 and pair.substr(0, separator) == cookie_name and separator < pair.length() - 1:
				return pair.substr(separator + 1)
	return ""


static func _new_browser_flow_id() -> String:
	var bytes := Crypto.new().generate_random_bytes(24)
	return "flw_" + Marshalls.raw_to_base64(bytes).replace("+", "-").replace("/", "_").trim_suffix("=")


## A base64url value from 32 random bytes, for PKCE verifiers and state.
static func _random_value() -> String:
	var bytes := Crypto.new().generate_random_bytes(32)
	return Marshalls.raw_to_base64(bytes).replace("+", "-").replace("/", "_").replace("=", "")


static func _code_challenge(verifier: String) -> String:
	var hashing := HashingContext.new()
	hashing.start(HashingContext.HASH_SHA256)
	hashing.update(verifier.to_ascii_buffer())
	var digest := hashing.finish()
	return Marshalls.raw_to_base64(digest).replace("+", "-").replace("/", "_").replace("=", "")


static func _query_string(fields: Dictionary) -> String:
	var parts := PackedStringArray()
	for key in fields:
		parts.append(String(key).uri_encode() + "=" + String(fields[key]).uri_encode())
	return "&".join(parts)


## Every value of every parameter in a query string such as "?code=...&state=...".
static func _parse_query(query: String) -> Dictionary:
	var values := {}
	for part in query.trim_prefix("?").split("&", false):
		var separator := part.find("=")
		var key := part if separator < 0 else part.substr(0, separator)
		var value := "" if separator < 0 else part.substr(separator + 1)
		key = key.replace("+", " ").uri_decode()
		if not values.has(key):
			values[key] = []
		values[key].append(value.replace("+", " ").uri_decode())
	return values


static func _is_redirect_uri(value: String) -> bool:
	var found := RegEx.create_from_string("^(https?://[^/?#@\\s\\\\]+)(/[^#\\s\\\\]*)?$").search(value)
	return found != null and not _normalize_origin(found.get_string(1)).is_empty()


static func _matches(pattern: String, value: String) -> bool:
	return RegEx.create_from_string(pattern).search(value) != null


static func _normalize_origin(value: String) -> String:
	var found := RegEx.create_from_string("^(https?)://([^/?#@\\s\\\\]+)/?$").search(value.strip_edges())
	if found == null:
		return ""
	var scheme := found.get_string(1).to_lower()
	var authority := found.get_string(2).to_lower()
	if scheme == "http":
		var host := authority
		if host.begins_with("["):
			host = host.substr(0, host.find("]") + 1)
		elif host.contains(":"):
			host = host.substr(0, host.find(":"))
		if host != "localhost" and host != "127.0.0.1" and host != "[::1]":
			return ""
	return scheme + "://" + authority


static func _normalize_scope(scope: String) -> String:
	var values := PackedStringArray()
	for part in scope.replace("\t", " ").replace("\n", " ").replace("\r", " ").split(" ", false):
		if not values.has(part):
			values.append(part)
	return " ".join(values) if values.has("openid") else ""
