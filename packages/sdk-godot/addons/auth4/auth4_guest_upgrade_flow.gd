class_name Auth4GuestUpgradeFlow
extends RefCounted
## A linking intent for upgrading the current guest in the game. It holds the flow cookie in memory
## only and is bound to the guest session that created it. Don't store or log it.

var browser_flow_id := ""
var guest_user_id := ""
## When the linking intent expires (Unix seconds); begin a new upgrade after this time.
var expires_at := 0.0

var _flow_cookie := ""
var _session_id := ""
