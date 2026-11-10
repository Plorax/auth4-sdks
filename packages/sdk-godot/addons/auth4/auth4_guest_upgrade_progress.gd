class_name Auth4GuestUpgradeProgress
extends RefCounted
## Reported by Auth4Client.upgrade_guest(). Carries no secret: the page URL holds only a public handle.

enum Stage {
	## The upgrade intent exists and the browser is about to open.
	OPENING_BROWSER,
	## The browser is open; the game is polling while the player links an account.
	WAITING_FOR_PLAYER,
	## The upgraded session replaced the guest session.
	COMPLETED,
}

var stage := Stage.OPENING_BROWSER
## The hosted page, so the game can offer "Open again" if the player closed it.
var upgrade_uri := ""
## Unix time in seconds.
var expires_at := 0.0
## Seconds until the next poll, as set by the server.
var interval_seconds := 0
var poll_attempts := 0
