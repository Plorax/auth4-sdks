class_name Auth4ClientOptions
extends RefCounted
## Settings for Auth4Client. Only tenant_id, client_id and auth_origin are required.

## Project (tenant) ID, for example ten_xxxxxxxxxxxxxxxx.
var tenant_id := ""

## Public client ID: a native application, or a browser application for web exports. Public
## clients never hold a client secret.
var client_id := ""

## Auth API origin, for example https://auth.auth4.dev. Plain HTTP is allowed only for loopback hosts.
var auth_origin := ""

## Scopes requested by device authorization and browser sign-in when none are passed explicitly.
var default_scope := "openid offline_access"

## HTTP transport. Defaults to Auth4HttpRequestTransport, which needs the client in the scene tree.
var transport: Auth4HttpTransport = null

## Clock and delay source. Defaults to the system clock and scene-tree timers.
var clock: Auth4Clock = null

## Secure platform storage for the refresh credential. When null, credentials are kept in memory
## only and the player signs in again after the game restarts.
var secure_storage: Auth4SecureStorage = null

## Opens the hosted page for upgrade_guest(). Receives the page URL as a String. When not set, the
## client uses OS.shell_open, except in web exports, which use a popup window instead.
var browser_launcher := Callable()

## Web exports only: the page that hosted sign-in returns to, for sign_in_with_browser(). It must be
## on the game page's own origin and registered as a redirect URI of a browser application. Any
## page works; a small blank one loads fastest. The client reads the result and closes the popup.
var redirect_uri := ""

## Opens popup windows in web exports. Defaults to Auth4WebBridge, which uses JavaScriptBridge.
var web_bridge: Auth4WebBridge = null

## Refresh this many seconds before the access token expires.
var access_token_refresh_margin := 30.0

## Upper bound on token requests for one device authorization or upgrade intent.
var max_device_poll_attempts := 240

## Consecutive network or 5xx failures tolerated while polling.
var max_consecutive_transient_poll_failures := 5
