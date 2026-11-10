class_name Auth4Result
extends RefCounted
## The outcome of every Auth4Client call. GDScript has no exceptions, so check ok before using value.
## Messages never contain token values.

## The player declined the device code or chose Not now on the hosted page.
const DENIED := "denied"
## The device code or upgrade intent expired before the player finished.
const EXPIRED := "expired"
## The email, Discord or Steam account already belongs to another player. Nothing was merged.
const CONFLICT := "conflict"
## The cancel token fired. A cancelled device authorization can be polled again until it expires.
const CANCELLED := "cancelled"
## The refresh credential was rejected; the local session and stored credential have been cleared.
const SESSION_EXPIRED := "session_expired"
## The player has an active ban (error account_suspended). Show that the account is suspended; the
## ban's reason is never sent to the game. After a refresh the local session has been cleared.
const SUSPENDED := "suspended"

var ok := false

## The call's result: an Auth4Session, Auth4DeviceAuthorization, Auth4GuestUpgradeFlow,
## Auth4GuestUpgradeResult, String or bool, as documented on each method.
var value: Variant = null

## OAuth error code, or a client code: network_error, login_required, invalid_response,
## invalid_state (a call made in the wrong state), invalid_argument, cancelled or
## unsupported_platform.
var error := ""

## A developer-facing description. Don't show it to players.
var description := ""

## HTTP status, or 0 when no response was received.
var status_code := 0

## One of the constants above when the failure ends a flow in a known way, otherwise "".
var reason := ""


static func success(result_value: Variant = null) -> Auth4Result:
	var result := Auth4Result.new()
	result.ok = true
	result.value = result_value
	return result


static func failure(
	error_code: String, error_description := "", status := 0, failure_reason := ""
) -> Auth4Result:
	var result := Auth4Result.new()
	result.error = error_code
	result.description = error_description
	result.status_code = status
	result.reason = failure_reason
	return result


## True for failures that may succeed if retried later. Transient errors keep the session.
func is_transient() -> bool:
	return (
		not ok
		and (
			error == "network_error"
			or error == "temporarily_unavailable"
			or error == "server_error"
			or status_code >= 500
		)
	)


func _to_string() -> String:
	if ok:
		return "Auth4Result(ok)"
	return "Auth4Result(%s%s)" % [error, "" if description.is_empty() else ": " + description]
