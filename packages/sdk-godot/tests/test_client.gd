extends SceneTree
## GDScript suite for the auth4.dev Godot addon. It drives real Auth4Client instances, with the
## default HTTPRequest transport, against tests/mock-server.mjs. A fake clock makes polling and
## token expiry instant. Run through tests/run.mjs, which passes the mock origin as --origin=...

const TENANT_ID := "ten_godotmocktenant0001"
const CLIENT_ID := "cli_godotmockclient0001"
const REDIRECT_URI := "https://game.example/auth4-callback.html"

const TESTS := [
	"test_rejects_invalid_configuration",
	"test_device_sign_in_polls_and_slows_down",
	"test_device_denied_and_expired",
	"test_device_rejects_foreign_verification_uri",
	"test_device_cancel_can_resume",
	"test_guest_sign_in",
	"test_refuses_second_sign_in",
	"test_refresh_rotates_once_for_concurrent_callers",
	"test_refresh_rejected_clears_session",
	"test_refresh_transient_failure_keeps_session",
	"test_in_game_email_upgrade",
	"test_in_game_email_upgrade_conflict",
	"test_browser_upgrade_with_provider_hint",
	"test_browser_upgrade_conflict_and_denied",
	"test_memory_storage_is_not_persistent",
	"test_secure_storage_restore_and_sign_out",
	"test_restore_retries_after_transient_failure",
	"test_restore_concurrent_callers_share_one_refresh",
	"test_restore_revoked_credential_is_cleared",
	"test_restore_sign_out_cannot_resurrect_session",
	"test_sign_out_offline_clears_session",
	"test_web_sign_in_with_pkce",
	"test_web_sign_in_failures",
	"test_web_guest_upgrade_in_window",
	"test_web_upgrade_conflict_then_success",
	"test_web_upgrade_cancel_and_session_end",
	"test_web_refuses_native_only_paths",
]


class FakeClock:
	extends Auth4Clock
	var time := 1800000000.0
	var delays: Array[float] = []

	func now() -> float:
		return time

	func delay(seconds: float, cancel: Auth4CancelToken) -> void:
		delays.append(seconds)
		time += seconds
		if cancel != null and cancel.is_cancelled:
			return
		await (Engine.get_main_loop() as SceneTree).process_frame


class DictionaryStorage:
	extends Auth4SecureStorage
	var values := {}

	func read(key: String) -> Variant:
		return values.get(key)

	func write(key: String, value: String) -> bool:
		values[key] = value
		return true

	func delete(key: String) -> bool:
		values.erase(key)
		return true


class SwitchableTransport:
	extends Auth4HttpTransport
	var offline := false
	var _inner: Auth4HttpRequestTransport

	func _init(host: Node) -> void:
		_inner = Auth4HttpRequestTransport.new(host)

	func send(method: String, url: String, headers: PackedStringArray, body: String) -> Response:
		if offline:
			return Response.new()
		return await _inner.send(method, url, headers, body)


## Plays the browser side of a web export (AUTH4D-219): records what the client asks the popup
## bridge to do and lets a test raise the window events that Auth4WebBridge would. The JavaScript
## side itself runs in tests/e2e/auth4d-219.godot-web.spec.ts.
class FakeWebBridge:
	extends Auth4WebBridge
	var supported := true
	var accept := true
	var opened: Array[String] = []
	var redirects: Array[String] = []
	var sent_tokens: Array[String] = []
	var closed: Array[int] = []
	var released: Array[int] = []
	var _on_event := Callable()
	var _handle := 0

	func is_supported() -> bool:
		return supported

	func open_upgrade_window(url: String, _auth_origin: String, on_event: Callable) -> int:
		return _record(url, on_event)

	func open_sign_in_window(
		url: String, _auth_origin: String, redirect_uri: String, on_event: Callable
	) -> int:
		redirects.append(redirect_uri)
		return _record(url, on_event)

	func send_access_token(handle: int, access_token: String) -> void:
		if handle == _handle:
			sent_tokens.append(access_token)

	func close_window(handle: int) -> void:
		closed.append(handle)

	func release_window(handle: int) -> void:
		released.append(handle)

	func emit(kind: String, data := "") -> void:
		_on_event.call(kind, data)

	func _record(url: String, on_event: Callable) -> int:
		opened.append(url)
		if not accept:
			return 0
		_on_event = on_event
		_handle += 1
		return _handle


var origin := ""
var clock: FakeClock
var failures := 0
var checks := 0
var _clients: Array[Auth4Client] = []
var _events: Array = []


func _initialize() -> void:
	for argument in OS.get_cmdline_user_args():
		if argument.begins_with("--origin="):
			origin = argument.trim_prefix("--origin=")
	_run.call_deferred()


func _run() -> void:
	if origin.is_empty():
		printerr("Pass the mock server origin: -- --origin=http://127.0.0.1:port")
		quit(2)
		return
	var failed: Array[String] = []
	for test_name in TESTS:
		await _mock("/__mock/reset", {})
		clock = FakeClock.new()
		_events.clear()
		var before := failures
		await call(test_name)
		for client in _clients:
			client.queue_free()
		_clients.clear()
		# Let queued HTTPRequest nodes and clients free before the next test.
		await process_frame
		if failures == before:
			print("ok   ", test_name)
		else:
			print("FAIL ", test_name)
			failed.append(test_name)
	print("%d tests, %d checks, %d failed" % [TESTS.size(), checks, failed.size()])
	quit(1 if failures > 0 else 0)


# ----- Tests -----


func test_rejects_invalid_configuration() -> void:
	var options := _options()
	options.tenant_id = "tenant"
	_expect(not Auth4Client.new(options).configuration_error.is_empty(), "bad tenant ID")
	options = _options()
	options.auth_origin = "http://auth.example.com"
	_expect(not Auth4Client.new(options).configuration_error.is_empty(), "plain http off loopback")
	options = _options()
	options.auth_origin = "https://auth.auth4.dev/t/ten_x"
	_expect(not Auth4Client.new(options).configuration_error.is_empty(), "origin with a path")
	options = _options()
	options.default_scope = "profile"
	_expect(not Auth4Client.new(options).configuration_error.is_empty(), "scope without openid")
	options = _options()
	options.auth_origin = "https://Auth.Auth4.dev/"
	var client := Auth4Client.new(options)
	_expect(client.configuration_error.is_empty(), "valid options")
	_expect(client.auth_origin == "https://auth.auth4.dev", "origin is normalized")
	var misconfigured := _client_from(_options_with("tenant_id", "x"))
	var result: Auth4Result = await misconfigured.sign_in_as_guest()
	_expect(result.error == "invalid_configuration", "calls fail when misconfigured")


func test_device_sign_in_polls_and_slows_down() -> void:
	await _mock(
		"/__mock/reset",
		{"device": ["authorization_pending", "slow_down", "unavailable", "approve"]}
	)
	var client := _client()
	var shown: Array = []
	var result: Auth4Result = await client.sign_in_with_device(func(a): shown.append(a))
	_expect(result.ok, "device sign-in succeeds: %s" % result)
	_expect(shown.size() == 1, "the code is shown once")
	var authorization: Auth4DeviceAuthorization = shown[0]
	_expect(authorization.user_code == "WXYZ-1234", "user code")
	_expect(authorization.verification_uri == origin + "/device", "verification URI")
	_expect(authorization.is_completed(), "authorization is completed")
	_expect(clock.delays == [5.0, 5.0, 10.0, 20.0], "interval, slow_down and backoff: %s" % [clock.delays])
	var session: Auth4Session = result.value
	_expect(not session.is_guest and session.can_refresh, "session can refresh")
	_expect(not session.is_refresh_persistent, "memory-only by default")
	_expect(_events.size() == 1 and _events[0] == session, "session_changed fired once")
	var state := await _mock_state()
	var device_request: Dictionary = state.requests[0]
	_expect(device_request.path == "/device/authorization", "device endpoint")
	_expect(device_request.tenant == TENANT_ID, "tenant in the query")


func test_device_denied_and_expired() -> void:
	await _mock("/__mock/reset", {"device": ["access_denied"]})
	var client := _client()
	var result: Auth4Result = await client.sign_in_with_device(func(_a): pass)
	_expect(not result.ok and result.reason == Auth4Result.DENIED, "denied: %s" % result)
	await _mock("/__mock/reset", {"device": ["expired_token"]})
	result = await client.sign_in_with_device(func(_a): pass)
	_expect(result.reason == Auth4Result.EXPIRED, "expired by the server: %s" % result)
	await _mock("/__mock/reset", {"device": ["authorization_pending"]})
	result = await client.sign_in_with_device(func(_a): pass)
	_expect(result.reason == Auth4Result.EXPIRED, "expired by the clock: %s" % result)
	_expect(client.get_current_session() == null, "still signed out")


func test_device_rejects_foreign_verification_uri() -> void:
	await _mock(
		"/__mock/reset", {"deviceResponse": {"verification_uri": "https://evil.example/device"}}
	)
	var result: Auth4Result = await _client().start_device_authorization()
	_expect(result.error == "invalid_response", "cross-origin verification URI is rejected")
	result = await _client().start_device_authorization("profile")
	_expect(result.error == "invalid_argument", "scope must include openid")


func test_device_cancel_can_resume() -> void:
	await _mock("/__mock/reset", {"device": ["authorization_pending", "approve"]})
	var client := _client()
	var started: Auth4Result = await client.start_device_authorization()
	var cancel := Auth4CancelToken.new()
	cancel.cancel()
	var result: Auth4Result = await client.poll_device_authorization(started.value, cancel)
	_expect(result.reason == Auth4Result.CANCELLED, "cancelled: %s" % result)
	_expect(not started.value.is_completed(), "a cancelled authorization can be resumed")
	result = await client.poll_device_authorization(started.value)
	_expect(result.ok, "resumed polling succeeds: %s" % result)


func test_guest_sign_in() -> void:
	var client := _client()
	var result: Auth4Result = await client.sign_in_as_guest()
	_expect(result.ok, "guest sign-in: %s" % result)
	var session: Auth4Session = result.value
	_expect(session.is_guest and session.user_id == "usr_guest_1", "guest session")
	_expect(client.get_current_session().user_id == "usr_guest_1", "current session")
	var token: Auth4Result = await client.get_access_token()
	_expect(token.ok and String(token.value).begins_with("at_"), "access token available")


func test_refuses_second_sign_in() -> void:
	var client := _client()
	await client.sign_in_as_guest()
	var result: Auth4Result = await client.sign_in_as_guest()
	_expect(result.error == "invalid_state", "a guest is never replaced silently")
	result = await client.start_device_authorization()
	_expect(result.error == "invalid_state", "device sign-in refuses too")


func test_refresh_rotates_once_for_concurrent_callers() -> void:
	var client := _client()
	var first: Auth4Result = await client.sign_in_as_guest()
	var original: String = (await client.get_access_token()).value
	clock.time += 600.0
	var results: Array = []
	var collect := func() -> void: results.append(await client.get_access_token())
	collect.call()
	collect.call()
	collect.call()
	while results.size() < 3:
		await process_frame
	for result: Auth4Result in results:
		_expect(result.ok and result.value != original, "rotated access token: %s" % result)
	_expect(results[0].value == results[1].value and results[1].value == results[2].value, "one token")
	var state := await _mock_state()
	var refreshes: Array = state.requests.filter(func(r): return r.grant == "refresh_token")
	_expect(refreshes.size() == 1, "one refresh request for three callers")
	_expect(state.reuse == 0, "no refresh token reuse")
	clock.time += 600.0
	var again: Auth4Result = await client.refresh()
	_expect(again.ok, "the rotated refresh token works")
	_expect(client.get_current_session().user_id == first.value.user_id, "user unchanged")
	state = await _mock_state()
	_expect(state.reuse == 0, "still no reuse after a second rotation")


func test_refresh_rejected_clears_session() -> void:
	var client := _client()
	await client.sign_in_as_guest()
	_events.clear()
	await _mock_patch({"refresh": "reject"})
	clock.time += 600.0
	var result: Auth4Result = await client.get_access_token()
	_expect(result.error == "invalid_grant" and result.reason == Auth4Result.SESSION_EXPIRED, "%s" % result)
	_expect(client.get_current_session() == null, "session cleared")
	_expect(_events == [null], "session_changed(null) fired")


func test_refresh_transient_failure_keeps_session() -> void:
	var client := _client()
	await client.sign_in_as_guest()
	await _mock_patch({"refresh": "unavailable"})
	clock.time += 600.0
	var result: Auth4Result = await client.refresh()
	_expect(not result.ok and result.is_transient(), "transient: %s" % result)
	_expect(client.get_current_session() != null, "session kept")


func test_in_game_email_upgrade() -> void:
	var client := _client()
	var guest: Auth4Result = await client.sign_in_as_guest()
	var begun: Auth4Result = await client.begin_guest_upgrade()
	_expect(begun.ok, "linking intent: %s" % begun)
	var flow: Auth4GuestUpgradeFlow = begun.value
	_expect(flow.guest_user_id == "usr_guest_1", "flow is bound to the guest")
	var started: Auth4Result = await client.start_email_verification(flow, " player@example.com ")
	_expect(started.ok, "code sent: %s" % started)
	var wrong: Auth4Result = await client.confirm_email_verification(flow, "player@example.com", "000000")
	_expect(wrong.error == "invalid_code", "wrong code is reported")
	var confirmed: Auth4Result = await client.confirm_email_verification(flow, "player@example.com", "123456")
	_expect(confirmed.ok and confirmed.value == "prf_mock_email_proof", "proof: %s" % confirmed)
	var completed: Auth4Result = await client.complete_guest_upgrade(flow, confirmed.value)
	_expect(completed.ok, "upgrade: %s" % completed)
	var upgraded: Auth4GuestUpgradeResult = completed.value
	_expect(upgraded.session.user_id == guest.value.user_id, "same user ID")
	_expect(not upgraded.session.is_guest, "no longer a guest")
	_expect(upgraded.provider == "email" and upgraded.identity_id == "idn_mock_email", "identity")
	var state := await _mock_state()
	for request: Dictionary in state.requests:
		if request.path.contains("/email/verification/"):
			_expect(request.cookie == "present" and request.origin == origin, "flow cookie and Origin")
		if request.path.ends_with("/guest/upgrade"):
			_expect(request.cookie == "present" and request.authorization == "present", "cookie and bearer")
			_expect(request.origin == "", "no Origin on the upgrade call")
	clock.time += 600.0
	var refreshed: Auth4Result = await client.refresh()
	_expect(refreshed.ok and not refreshed.value.is_guest, "the replacement refresh token works")


func test_in_game_email_upgrade_conflict() -> void:
	await _mock("/__mock/reset", {"emailInUse": true})
	var client := _client()
	await client.sign_in_as_guest()
	var flow: Auth4GuestUpgradeFlow = (await client.begin_guest_upgrade()).value
	await client.start_email_verification(flow, "taken@example.com")
	var proof: String = (await client.confirm_email_verification(flow, "taken@example.com", "123456")).value
	var result: Auth4Result = await client.complete_guest_upgrade(flow, proof)
	_expect(result.error == "identity_in_use" and result.reason == Auth4Result.CONFLICT, "%s" % result)
	_expect(client.get_current_session().is_guest, "guest session unchanged")
	clock.time = flow.expires_at
	result = await client.start_email_verification(flow, "other@example.com")
	_expect(result.error == "expired_token", "expired flows are refused")


func test_browser_upgrade_with_provider_hint() -> void:
	await _mock("/__mock/reset", {"upgrade": ["authorization_pending", "slow_down", "approve"]})
	var opened: Array[String] = []
	var client := _client(null, func(url: String) -> void: opened.append(url))
	var guest: Auth4Result = await client.sign_in_as_guest()
	var stages: Array = []
	var result: Auth4Result = await client.upgrade_guest(
		"steam", func(p: Auth4GuestUpgradeProgress) -> void: stages.append(p.stage)
	)
	_expect(result.ok, "browser upgrade: %s" % result)
	_expect(opened.size() == 1, "browser opened once")
	_expect(opened[0].begins_with(origin + "/login/upgrade?intent=gui_"), "hosted page")
	_expect(opened[0].ends_with("&provider=steam"), "provider hint")
	_expect(not opened[0].contains("gps_"), "the poll secret never leaves the game")
	_expect(stages.front() == Auth4GuestUpgradeProgress.Stage.OPENING_BROWSER, "opening stage")
	_expect(stages.back() == Auth4GuestUpgradeProgress.Stage.COMPLETED, "completed stage")
	_expect(clock.delays == [5.0, 5.0, 10.0], "server interval and slow_down: %s" % [clock.delays])
	var upgraded: Auth4GuestUpgradeResult = result.value
	_expect(upgraded.session.user_id == guest.value.user_id and not upgraded.session.is_guest, "upgraded")
	_expect(upgraded.provider == "steam", "linked provider")
	for provider in ["epic", "google", "apple", "microsoft"]:
		await _mock("/__mock/reset", {"upgrade": ["approve"]})
		var preset_opened: Array[String] = []
		var preset_client := _client(null, func(url: String) -> void: preset_opened.append(url))
		await preset_client.sign_in_as_guest()
		var preset_result: Auth4Result = await preset_client.upgrade_guest(provider)
		_expect(preset_result.ok, "%s upgrade: %s" % [provider, preset_result])
		_expect(preset_opened.size() == 1, "%s browser opened once" % provider)
		_expect(preset_opened[0].ends_with("&provider=" + provider), "%s provider hint" % provider)
	var invalid: Auth4Result = await client.upgrade_guest("twitch")
	_expect(invalid.error == "invalid_argument", "unknown provider hint")
	invalid = await client.upgrade_guest()
	_expect(invalid.error == "invalid_state", "only guests can upgrade")


func test_browser_upgrade_conflict_and_denied() -> void:
	await _mock("/__mock/reset", {"upgrade": ["conflict"]})
	var client := _client(null, func(_url: String) -> void: pass)
	await client.sign_in_as_guest()
	var result: Auth4Result = await client.upgrade_guest()
	_expect(result.reason == Auth4Result.CONFLICT, "conflict: %s" % result)
	_expect(client.get_current_session().is_guest, "guest kept after conflict")
	await _mock_patch({"upgrade": ["access_denied"]})
	result = await client.upgrade_guest()
	_expect(result.reason == Auth4Result.DENIED, "denied: %s" % result)
	await _mock_patch({"upgrade": ["authorization_pending"]})
	var cancel := Auth4CancelToken.new()
	var cancel_soon := func(p: Auth4GuestUpgradeProgress) -> void:
		if p.poll_attempts >= 2:
			cancel.cancel()
	result = await client.upgrade_guest("", cancel_soon, cancel)
	_expect(result.reason == Auth4Result.CANCELLED, "cancelled: %s" % result)
	_expect(client.get_current_session().is_guest, "guest kept after cancel")


func test_memory_storage_is_not_persistent() -> void:
	var client := _client()
	await client.sign_in_as_guest()
	_expect(not client.is_refresh_persistent(), "not persistent without an adapter")
	var restarted := _client()
	var restored: Auth4Result = await restarted.try_restore_session()
	_expect(restored.ok and restored.value == false, "nothing to restore in a new client")


func test_secure_storage_restore_and_sign_out() -> void:
	var storage := DictionaryStorage.new()
	var client := _client(storage)
	var guest: Auth4Result = await client.sign_in_as_guest()
	_expect(guest.value.is_refresh_persistent, "persistent with an adapter")
	var key := "auth4.%s.%s.session" % [TENANT_ID, CLIENT_ID]
	var stored: Dictionary = JSON.parse_string(storage.values[key])
	_expect(String(stored.refresh_token).begins_with("rt_"), "refresh token stored")
	_expect(not stored.has("access_token"), "access token never stored")
	_expect(stored.guest == "true" and stored.user_id == "usr_guest_1", "user ID and guest flag")

	var restarted := _client(storage)
	var restored: Auth4Result = await restarted.try_restore_session()
	_expect(restored.ok and restored.value == true, "restored: %s" % restored)
	var session := restarted.get_current_session()
	_expect(session.is_guest and session.user_id == "usr_guest_1", "restored guest")
	_expect(JSON.parse_string(storage.values[key]).refresh_token != stored.refresh_token, "rotated on restore")

	_expect(await restarted.sign_out(), "revocation confirmed")
	_expect(not storage.values.has(key), "storage cleared")
	_expect(restarted.get_current_session() == null, "signed out")
	var state := await _mock_state()
	_expect(state.revoked == ["refresh_token"], "refresh token revoked")
	var after: Auth4Result = await _client(storage).try_restore_session()
	_expect(after.ok and after.value == false, "nothing to restore after sign-out")


func test_restore_retries_after_transient_failure() -> void:
	var storage := DictionaryStorage.new()
	await _client(storage).sign_in_as_guest()
	var key := "auth4.%s.%s.session" % [TENANT_ID, CLIENT_ID]
	var stored_token: String = JSON.parse_string(storage.values[key]).refresh_token
	var restarted := _client(storage)
	await _mock_patch({"refresh": "unavailable"})
	var failed: Auth4Result = await restarted.try_restore_session()
	_expect(not failed.ok and failed.is_transient(), "transient failure is reported: %s" % failed)
	_expect(restarted.get_current_session() == null, "no usable session after the failure")
	_expect(JSON.parse_string(storage.values[key]).refresh_token == stored_token, "credential kept")

	await _mock_patch({"refresh": "rotate"})
	var retried: Auth4Result = await restarted.try_restore_session()
	_expect(retried.ok and retried.value == true, "retry restores: %s" % retried)
	var token: Auth4Result = await restarted.get_access_token()
	_expect(token.ok and not String(token.value).is_empty(), "usable access token")
	_expect(restarted.get_current_session() != null, "session available")
	var state := await _mock_state()
	var refreshes: Array = state.requests.filter(func(r): return r.grant == "refresh_token")
	_expect(refreshes.size() == 2, "the second restore refreshed again")
	_expect(state.reuse == 0, "no refresh token reuse")


func test_restore_concurrent_callers_share_one_refresh() -> void:
	var storage := DictionaryStorage.new()
	await _client(storage).sign_in_as_guest()
	var restarted := _client(storage)
	var results: Array = []
	var collect := func() -> void: results.append(await restarted.try_restore_session())
	collect.call()
	collect.call()
	collect.call()
	_expect(restarted.get_current_session() == null, "nothing usable while the refresh is pending")
	while results.size() < 3:
		await process_frame
	for result: Auth4Result in results:
		_expect(result.ok and result.value == true, "restored: %s" % result)
	var state := await _mock_state()
	var refreshes: Array = state.requests.filter(func(r): return r.grant == "refresh_token")
	_expect(refreshes.size() == 1, "one refresh request for three callers")
	_expect(state.reuse == 0, "no refresh token reuse")


func test_restore_revoked_credential_is_cleared() -> void:
	var storage := DictionaryStorage.new()
	await _client(storage).sign_in_as_guest()
	await _mock_patch({"refresh": "reject"})
	var restarted := _client(storage)
	var results: Array = []
	var collect := func() -> void: results.append(await restarted.try_restore_session())
	collect.call()
	collect.call()
	while results.size() < 2:
		await process_frame
	for result: Auth4Result in results:
		_expect(result.ok and result.value == false, "restoration failed: %s" % result)
	_expect(storage.values.is_empty(), "credential cleared")
	_expect(restarted.get_current_session() == null, "no session")


func test_restore_sign_out_cannot_resurrect_session() -> void:
	var storage := DictionaryStorage.new()
	await _client(storage).sign_in_as_guest()
	var restarted := _client(storage)
	var results: Array = []
	var restore := func() -> void: results.append(await restarted.try_restore_session())
	restore.call()
	var signed_out: Array = []
	var sign_out := func() -> void: signed_out.append(await restarted.sign_out())
	sign_out.call()
	while results.is_empty() or signed_out.is_empty():
		await process_frame
	_expect(restarted.get_current_session() == null, "still signed out after the late response")
	_expect(storage.values.is_empty(), "storage stays cleared")
	var after: Auth4Result = await restarted.get_access_token()
	_expect(after.error == "login_required", "no token without a session: %s" % after)
	var again: Auth4Result = await restarted.try_restore_session()
	_expect(again.ok and again.value == false, "nothing to restore after sign-out")


func test_sign_out_offline_clears_session() -> void:
	var options := _options()
	options.auth_origin = "http://127.0.0.1:9"
	var unreachable := _client_from(options)
	var guest: Auth4Result = await unreachable.sign_in_as_guest()
	_expect(guest.error == "network_error" and guest.is_transient(), "unreachable: %s" % guest)

	var transport := SwitchableTransport.new(root)
	options = _options()
	options.transport = transport
	var client := _client_from(options)
	_expect((await client.sign_in_as_guest()).ok, "signed in online")
	transport.offline = true
	_expect(not await client.sign_out(), "revocation not confirmed offline")
	_expect(client.get_current_session() == null, "local session cleared anyway")


# ----- Web exports (AUTH4D-219) -----


func test_web_sign_in_with_pkce() -> void:
	var bridge := FakeWebBridge.new()
	var client := _web_client(bridge)
	var pending := _start(client.sign_in_with_browser.bind("discord"))
	_expect(bridge.opened.size() == 1, "the popup opens before the first await")
	var url := bridge.opened[0]
	_expect(url.begins_with(origin + "/oauth/authorize?tenant_id=" + TENANT_ID + "&"), "authorize: %s" % url)
	var query := _query(url)
	_expect(query.response_type == "code" and query.client_id == CLIENT_ID, "code flow for the client")
	_expect(query.redirect_uri == REDIRECT_URI and bridge.redirects == [REDIRECT_URI], "redirect URI")
	_expect(query.code_challenge_method == "S256", "S256")
	_expect(String(query.code_challenge).length() == 43, "SHA-256 challenge")
	_expect(String(query.state).length() == 43, "random state")
	_expect(query.provider_hint == "discord", "provider hint")
	_expect(query.scope == "openid offline_access", "default scope")
	_expect(not query.has("code_verifier"), "the verifier never leaves the game")

	var redirect := {"challenge": query.code_challenge, "redirect_uri": REDIRECT_URI}
	await _mock_patch({"codes": {"ac_mock_code": redirect}})
	bridge.emit("opened")
	var issuer := origin + "/t/" + TENANT_ID
	bridge.emit("callback", "?code=ac_mock_code&state=%s&iss=%s" % [query.state, issuer.uri_encode()])
	var result := await _settle(pending)
	_expect(result.ok, "browser sign-in: %s" % result)
	var session: Auth4Session = result.value
	_expect(not session.is_guest and session.can_refresh, "refreshable session")
	_expect(not session.is_refresh_persistent, "tokens stay in memory")
	_expect(_events.size() == 1 and _events[0] == session, "session_changed fired once")
	_expect(bridge.released == [1] and bridge.closed.is_empty(), "the bridge closes its own popup")
	var state := await _mock_state()
	var exchanges: Array = state.requests.filter(func(r): return r.grant == "authorization_code")
	_expect(exchanges.size() == 1 and exchanges[0].tenant == TENANT_ID, "one code exchange")
	clock.time += 600.0
	_expect((await client.refresh()).ok, "the refresh token works")
	var again: Auth4Result = await client.sign_in_with_browser()
	_expect(again.error == "invalid_state" and bridge.opened.size() == 1, "no second sign-in")


func test_web_sign_in_failures() -> void:
	var bridge := FakeWebBridge.new()
	var client := _web_client(bridge)
	var pending := _start(client.sign_in_with_browser)
	bridge.emit("callback", "?code=ac_mock_code&state=forged")
	var result := await _settle(pending)
	_expect(result.error == "invalid_response", "state mismatch: %s" % result)

	pending = _start(client.sign_in_with_browser)
	var state: String = _query(bridge.opened.back()).state
	bridge.emit("callback", "?code=ac_mock_code&state=%s&iss=%s" % [state, "https%3A%2F%2Fevil.example%2Ft%2Fx"])
	result = await _settle(pending)
	_expect(result.error == "invalid_response", "issuer mismatch: %s" % result)

	pending = _start(client.sign_in_with_browser)
	state = _query(bridge.opened.back()).state
	bridge.emit("callback", "?error=access_denied&state=" + state)
	result = await _settle(pending)
	_expect(result.reason == Auth4Result.DENIED, "denied: %s" % result)

	pending = _start(client.sign_in_with_browser)
	state = _query(bridge.opened.back()).state
	bridge.emit("callback", "?code=ac_unknown_code&state=" + state)
	result = await _settle(pending)
	_expect(result.error == "invalid_grant", "unknown code: %s" % result)

	pending = _start(client.sign_in_with_browser)
	var second: Auth4Result = await client.sign_in_with_browser()
	_expect(second.error == "invalid_state", "one window at a time")
	bridge.emit("closed")
	result = await _settle(pending)
	_expect(result.error == "window_closed", "closed: %s" % result)

	pending = _start(client.sign_in_with_browser)
	bridge.emit("blocked")
	result = await _settle(pending)
	_expect(result.error == "popup_blocked", "blocked: %s" % result)

	var cancel := Auth4CancelToken.new()
	pending = _start(client.sign_in_with_browser.bind("", "", cancel))
	cancel.cancel()
	result = await _settle(pending)
	_expect(result.reason == Auth4Result.CANCELLED, "cancelled: %s" % result)
	_expect(bridge.closed == [7], "cancel closes the window: %s" % [bridge.closed])

	bridge.accept = false
	result = await client.sign_in_with_browser()
	_expect(result.error == "invalid_configuration", "redirect URI refused by the bridge: %s" % result)
	_expect(client.get_current_session() == null and _events.is_empty(), "still signed out")

	var options := _options()
	options.web_bridge = bridge
	result = await _client_from(options).sign_in_with_browser()
	_expect(result.error == "invalid_configuration", "redirect_uri is required")
	options.redirect_uri = "game.example/callback"
	_expect(not Auth4Client.new(options).configuration_error.is_empty(), "relative redirect_uri")
	options.redirect_uri = "https://game.example/callback#done"
	_expect(not Auth4Client.new(options).configuration_error.is_empty(), "redirect_uri with a fragment")
	options.redirect_uri = "http://game.example/callback"
	_expect(not Auth4Client.new(options).configuration_error.is_empty(), "plain http off loopback")


func test_web_guest_upgrade_in_window() -> void:
	var bridge := FakeWebBridge.new()
	var launched: Array[String] = []
	var client := _web_client(bridge, func(url: String) -> void: launched.append(url))
	var guest: Auth4Result = await client.sign_in_as_guest()
	_events.clear()
	var stages: Array = []
	var pending := _start(
		client.upgrade_guest.bind("steam", func(p: Auth4GuestUpgradeProgress) -> void: stages.append(p.stage))
	)
	var expected := "%s/login/upgrade?tenant_id=%s&client_id=%s&provider=steam" % [origin, TENANT_ID, CLIENT_ID]
	_expect(bridge.opened == [expected], "hosted upgrade window: %s" % [bridge.opened])
	_expect(launched.is_empty(), "no system browser in web exports")
	_expect(stages == [Auth4GuestUpgradeProgress.Stage.OPENING_BROWSER], "opening stage")
	bridge.emit("opened")
	_expect(stages.back() == Auth4GuestUpgradeProgress.Stage.WAITING_FOR_PLAYER, "waiting stage")

	bridge.emit("ready", JSON.stringify({"tenant_id": TENANT_ID, "client_id": "cli_someoneelse000000"}))
	await _frames(3)
	_expect(bridge.sent_tokens.is_empty(), "no token for another client")
	bridge.emit("ready", JSON.stringify({"tenant_id": TENANT_ID, "client_id": CLIENT_ID}))
	await _frames(3)
	var token: String = (await client.get_access_token()).value
	_expect(bridge.sent_tokens == [token], "the guest token answers ready")

	var completed := await _mock("/__mock/upgrade-result", {"access_token": token})
	bridge.emit("complete", JSON.stringify(completed))
	var result := await _settle(pending)
	_expect(result.ok, "window upgrade: %s" % result)
	var upgraded: Auth4GuestUpgradeResult = result.value
	_expect(upgraded.session.user_id == guest.value.user_id, "same user ID")
	_expect(not upgraded.session.is_guest and upgraded.provider == "email", "linked")
	_expect(_events.size() == 1 and _events[0] == upgraded.session, "session_changed fired once")
	_expect(stages.back() == Auth4GuestUpgradeProgress.Stage.COMPLETED, "completed stage")
	_expect(bridge.released == [1] and bridge.closed.is_empty(), "the page stays open to show it")
	var state := await _mock_state()
	var intents: Array = state.requests.filter(func(r): return r.path.contains("upgrade-intent"))
	_expect(intents.is_empty(), "no upgrade intent in window mode")
	clock.time += 600.0
	_expect((await client.refresh()).ok, "the replacement refresh token works")


func test_web_upgrade_conflict_then_success() -> void:
	var bridge := FakeWebBridge.new()
	var client := _web_client(bridge)
	await client.sign_in_as_guest()
	_events.clear()
	var pending := _start(client.upgrade_guest)
	var ready := JSON.stringify({"tenant_id": TENANT_ID, "client_id": CLIENT_ID})
	bridge.emit("ready", ready)
	bridge.emit("error", "identity_in_use")
	var result := await _settle(pending)
	_expect(result.error == "identity_in_use" and result.reason == Auth4Result.CONFLICT, "%s" % result)
	_expect(client.get_current_session().is_guest, "guest kept after conflict")
	_expect(bridge.released.is_empty(), "still answering the window")

	# The player links another account in the same window.
	bridge.emit("ready", ready)
	await _frames(3)
	_expect(bridge.sent_tokens.size() == 2, "the window gets the token again")
	var completed := await _mock("/__mock/upgrade-result", {"access_token": bridge.sent_tokens[1]})
	bridge.emit("complete", JSON.stringify(completed))
	await _until(func() -> bool: return not _events.is_empty())
	_expect(not client.get_current_session().is_guest, "a later success still upgrades")
	_expect(bridge.released == [1], "then the client stops listening")


func test_web_upgrade_cancel_and_session_end() -> void:
	var bridge := FakeWebBridge.new()
	var client := _web_client(bridge)
	var result: Auth4Result = await client.upgrade_guest()
	_expect(result.error == "login_required" and bridge.opened.is_empty(), "signed out: %s" % result)
	await client.sign_in_as_guest()

	var pending := _start(client.upgrade_guest)
	bridge.emit("cancelled")
	result = await _settle(pending)
	_expect(result.reason == Auth4Result.DENIED, "Not now: %s" % result)

	var cancel := Auth4CancelToken.new()
	pending = _start(client.upgrade_guest.bind("", Callable(), cancel))
	cancel.cancel()
	result = await _settle(pending)
	_expect(result.reason == Auth4Result.CANCELLED and bridge.closed == [2], "cancel closes: %s" % result)

	pending = _start(client.upgrade_guest)
	bridge.emit("blocked")
	_expect((await _settle(pending)).error == "popup_blocked", "blocked")
	pending = _start(client.upgrade_guest)
	bridge.emit("closed")
	_expect((await _settle(pending)).error == "window_closed", "closed")

	pending = _start(client.upgrade_guest)
	bridge.emit("error", "invalid_session")
	_expect((await _settle(pending)).error == "invalid_session", "server ended the session")

	# A result for another user is never adopted.
	pending = _start(client.upgrade_guest)
	var forged := {
		"user_id": "usr_someone_else",
		"access_token": "at_forged",
		"token_type": "Bearer",
		"expires_in": 300,
		"identity": {"identity_id": "idn_forged", "provider": "email"},
	}
	bridge.emit("complete", JSON.stringify(forged))
	result = await _settle(pending)
	_expect(result.error == "invalid_response", "foreign user: %s" % result)
	_expect(client.get_current_session() == null, "the local session is cleared")

	await client.sign_in_as_guest()
	pending = _start(client.upgrade_guest)
	await client.sign_out()
	bridge.emit("ready", JSON.stringify({"tenant_id": TENANT_ID, "client_id": CLIENT_ID}))
	result = await _settle(pending)
	_expect(result.error == "invalid_session", "signed out mid-upgrade: %s" % result)
	_expect(bridge.sent_tokens.is_empty(), "no token after sign-out")


func test_web_refuses_native_only_paths() -> void:
	var bridge := FakeWebBridge.new()
	var client := _web_client(bridge)
	await client.sign_in_as_guest()
	var result: Auth4Result = await client.begin_guest_upgrade()
	_expect(result.error == "unsupported_platform", "in-game email steps: %s" % result)
	var native := _client()
	result = await native.sign_in_with_browser()
	_expect(result.error == "unsupported_platform", "browser sign-in off the web: %s" % result)


# ----- Helpers -----


func _options() -> Auth4ClientOptions:
	var options := Auth4ClientOptions.new()
	options.tenant_id = TENANT_ID
	options.client_id = CLIENT_ID
	options.auth_origin = origin
	options.clock = clock
	return options


func _options_with(property: String, value: Variant) -> Auth4ClientOptions:
	var options := _options()
	options.set(property, value)
	return options


func _client(storage: Auth4SecureStorage = null, launcher := Callable()) -> Auth4Client:
	var options := _options()
	options.secure_storage = storage
	options.browser_launcher = launcher
	return _client_from(options)


func _client_from(options: Auth4ClientOptions) -> Auth4Client:
	var client := Auth4Client.new(options)
	client.session_changed.connect(func(session: Auth4Session) -> void: _events.append(session))
	root.add_child(client)
	_clients.append(client)
	return client


func _web_client(bridge: FakeWebBridge, launcher := Callable()) -> Auth4Client:
	var options := _options()
	options.web_bridge = bridge
	options.redirect_uri = REDIRECT_URI
	options.browser_launcher = launcher
	return _client_from(options)


## Starts a client call without awaiting it, so the test can raise window events meanwhile.
func _start(call: Callable) -> Array:
	var box := []
	var run := func() -> void: box.append(await call.call())
	run.call()
	return box


func _settle(box: Array) -> Auth4Result:
	await _until(func() -> bool: return not box.is_empty())
	return box[0] if not box.is_empty() else Auth4Result.failure("test_timeout")


func _until(condition: Callable) -> void:
	for _frame in 600:
		if condition.call():
			return
		await process_frame


func _frames(count: int) -> void:
	for _frame in count:
		await process_frame


## The query parameters of a URL, one value each.
func _query(url: String) -> Dictionary:
	var values := {}
	for part in url.substr(url.find("?") + 1).split("&", false):
		var pair := part.split("=")
		values[pair[0].uri_decode()] = pair[1].uri_decode() if pair.size() > 1 else ""
	return values


func _expect(condition: bool, message: String) -> void:
	checks += 1
	if not condition:
		failures += 1
		printerr("  expected: ", message)


func _mock(path: String, body: Dictionary) -> Dictionary:
	var request := HTTPRequest.new()
	root.add_child(request)
	request.request(
		origin + path,
		PackedStringArray(["Content-Type: application/json"]),
		HTTPClient.METHOD_POST,
		JSON.stringify(body)
	)
	var completed: Array = await request.request_completed
	request.queue_free()
	var parsed: Variant = JSON.parse_string(completed[3].get_string_from_utf8())
	return parsed if parsed is Dictionary else {}


## Changes the scenario without forgetting issued tokens.
func _mock_patch(changes: Dictionary) -> void:
	await _mock("/__mock/patch", changes)


func _mock_state() -> Dictionary:
	return await _mock("/__mock/state", {})
