# auth4.dev Godot SDK guide

A GDScript addon for Godot 4.3 and later (verified on 4.7). It mirrors the Unity package's
`Auth4Client`: device sign-in, guest play, guest upgrades by email, social-provider hints, and
rotating refresh tokens kept in memory unless you supply a secure storage adapter. Web exports sign
in and upgrade guests in popup windows instead (see [Web exports](#web-exports)).

## Install

Copy `addons/auth4` from this directory into your project's `addons/` folder. Then enable
**auth4.dev Authentication** under **Project Settings > Plugins** (optional: the classes are
global either way).

Create a **Game (device sign-in)** application in the auth4.dev console and tick `offline_access`.
Native applications are public clients: there is no client secret, and the addon can't send one.

## Client

```gdscript
var options := Auth4ClientOptions.new()
options.tenant_id = "ten_…"
options.client_id = "cli_…"
options.auth_origin = "https://auth.auth4.dev" # http is accepted only for loopback hosts
var client := Auth4Client.new(options)
if not client.configuration_error.is_empty():
	push_error(client.configuration_error)
add_child(client) # the default transport needs the client in the scene tree
```

Every dependency is injectable through `Auth4ClientOptions`: `transport` (`Auth4HttpTransport`),
`clock` (`Auth4Clock`), `secure_storage` (`Auth4SecureStorage`), `browser_launcher` (a
`Callable` that takes the page URL; the default is `OS.shell_open`) and `web_bridge`
(`Auth4WebBridge`, used in web exports).

GDScript has no exceptions. Every call is a coroutine that returns an `Auth4Result`: check `ok`,
then read `value`. On failure, `error` holds the OAuth error code (or `network_error`,
`login_required`, `invalid_response`, `invalid_state`, `invalid_argument`, `cancelled`,
`unsupported_platform`, and in web exports `popup_blocked`, `window_closed` and
`invalid_session`), `is_transient()` is true for network failures and 5xx responses, and
`reason` is one of `Auth4Result.DENIED`, `EXPIRED`, `CONFLICT`, `CANCELLED` or `SESSION_EXPIRED`
when a flow ended in a known way. `description` is for developers; don't show it to players.

## Device sign-in

```gdscript
var cancel := Auth4CancelToken.new() # call cancel.cancel() from a Cancel button
# _show_code(authorization: Auth4DeviceAuthorization) displays user_code and verification_uri.
var result := await client.sign_in_with_device(_show_code, "", cancel)
if result.ok:
	var session: Auth4Session = result.value
elif result.reason == Auth4Result.DENIED:
	pass # the player declined
elif result.reason == Auth4Result.EXPIRED:
	pass # the code timed out; offer to start again
```

Polling waits the server interval (at least five seconds), adds five seconds on every `slow_down`,
backs off on network and 5xx errors (`max_consecutive_transient_poll_failures`), and stops at the
code's expiry or after `max_device_poll_attempts`. Verification URLs from another origin are
rejected. `start_device_authorization()` and `poll_device_authorization()` are available
separately; a cancelled poll can be resumed until the code expires.

## Guest sessions and upgrades

```gdscript
var guest := await client.sign_in_as_guest() # guest.value.user_id is stable

# In the system browser, offer an enabled social provider first (for example "google", "apple",
# "microsoft", "epic", "discord" or "steam"). The player still chooses and confirms.
# _on_progress(progress: Auth4GuestUpgradeProgress) can offer "Open again" with progress.upgrade_uri.
var upgraded := await client.upgrade_guest("google", _on_progress)
if upgraded.ok:
	var linked: Auth4GuestUpgradeResult = upgraded.value # same user_id; provider is the linked method
elif upgraded.reason == Auth4Result.CONFLICT:
	pass # the account already belongs to another player; nothing was merged
```

Or link an email address without leaving the game:

```gdscript
var flow: Auth4GuestUpgradeFlow = (await client.begin_guest_upgrade()).value
await client.start_email_verification(flow, email)
var proof := await client.confirm_email_verification(flow, email, code)
var result := await client.complete_guest_upgrade(flow, proof.value)
# result.error == "identity_in_use" (reason CONFLICT) leaves the guest session unchanged.
```

Sign-in calls fail with `invalid_state` while a session is active, so a guest is never abandoned
silently. On a successful upgrade the tokens are replaced in one step, in memory and in secure
storage, and `session_changed` fires once.

## Tokens

```gdscript
var token := await client.get_access_token() # refreshes shortly before expiry
if token.ok:
	headers.append("Authorization: Bearer " + token.value)
elif token.reason == Auth4Result.SESSION_EXPIRED:
	pass # the session is already cleared: sign in again
elif token.is_transient():
	pass # network or server problem; the session is kept
```

Concurrent callers share one refresh request, so parallel requests never trigger refresh-token
reuse detection. `sign_out()` revokes the refresh token, always clears local state, and returns
`false` when the server couldn't confirm revocation.

## Token storage

By default the refresh token lives only in memory. To keep players signed in across restarts,
extend `Auth4SecureStorage` (`read`, `write`, `delete`; each may be a coroutine) over a platform
protected store, such as the iOS Keychain, Android Keystore-backed encryption, Windows DPAPI or a
console's protected save API, usually through a GDExtension or a platform plugin. Then:

```gdscript
options.secure_storage = MyKeychainStorage.new()
var restored := await client.try_restore_session() # value is false when nothing usable is stored
```

`try_restore_session()` reports `true` only after the refresh returned a usable access token.
`false` means nothing usable is stored or the server rejected the credential, which is then
cleared. A transient failure (network, 5xx) comes back as an error, keeps the stored credential and
leaves no session, so call `try_restore_session()` again to retry. Concurrent calls share one
refresh, and a `sign_out()` that happens while a restore is pending is never undone by the late
response.

Never store tokens in `user://`, `ConfigFile`, `ProjectSettings` or logs. `FileAccess` encryption
with a password in the game binary is not protected storage. The addon stores only the refresh
token, user ID and guest flag; access tokens are never persisted.

## Web exports

A web export already runs in a browser, so it uses popup windows, as the browser SDK and Unity WebGL
builds do. Tokens stay in memory, and nothing is written to a URL, cookies or browser storage.

Use a **browser** application, not the game (device sign-in) one. Register the page the popup
returns to under **Redirect URIs** (any page on the game's own origin works; a small blank one such
as `auth4-callback.html` next to `index.html` loads fastest) and the game's origin under
**Allowed origins**. The token, revocation and guest endpoints accept only those origins. To keep
refresh tokens, turn on **Allow refresh tokens in the browser** and add `offline_access` under
**Scopes**; otherwise set `default_scope = "openid"`.

```gdscript
options.client_id = "cli_…" # the browser application
options.redirect_uri = "https://game.example/auth4-callback.html"

# In a button handler. The popup opens before the first await, inside the input event.
var signed_in := await client.sign_in_with_browser() # or ("discord") to offer Discord first
var guest := await client.sign_in_as_guest()
var upgraded := await client.upgrade_guest("steam")  # the hosted upgrade page, in a popup
```

- `sign_in_with_browser()` uses the authorization code flow with S256 PKCE. The popup goes to the
  hosted login page and back to `redirect_uri`; the addon reads the code from the popup, closes it
  and exchanges the code in the game. A wrong `state` or issuer is refused.
- `upgrade_guest()` opens `/login/upgrade?tenant_id=…&client_id=…` in a popup and answers the page's
  ready message with the guest access token, posted only to the exact auth origin. Messages from
  any other window or origin are ignored. No upgrade intent is created. After `CONFLICT` the window
  lets the player link another account; a later success still replaces the session and emits
  `session_changed`.
- Browsers open popups only during an input event, and Godot handles input a frame later. When the
  browser no longer counts the input as a gesture, the popup opens on the player's next pointer-up
  or touch-end. Set `action_mode = BaseButton.ACTION_MODE_BUTTON_PRESS` on the button, so that the
  release of the same press opens it.
- A blocked popup fails with `popup_blocked`, a closed one with `window_closed`, and a guest whose
  session ended during the upgrade with `invalid_session`. Cancelling your `Auth4CancelToken`
  closes the popup.
- `begin_guest_upgrade()` and the in-game email steps fail with `unsupported_platform`: they need
  cookie and `Origin` headers that the browser controls. Use `upgrade_guest()`.
- Export without **Thread Support** (the default since Godot 4.3). Threaded exports need
  `Cross-Origin-Opener-Policy: same-origin`, which cuts the game off from its popups.
- Device sign-in is for native builds: the device authorization endpoint doesn't accept requests
  from game origins.

## Platform limits

- Social providers can only be linked through `upgrade_guest()`, which needs a system browser or,
  in web exports, a popup.
- Web exports keep sessions in memory, so players sign in again after reloading the page. Don't
  pass a `secure_storage` adapter there: browsers have no protected store.

## Verify

```sh
GODOT_BIN=/path/to/godot node packages/sdk-godot/tests/run.mjs
```

This runs `tests/test_client.gd` headless against `tests/mock-server.mjs`, a local stand-in for the
auth4.dev endpoints. The report goes to `.generated/auth4d-152/godot-sdk.json`. The web tests in
that suite replace the popup with a fake `Auth4WebBridge`.

## Licence

MIT. See [LICENSE](LICENSE).
