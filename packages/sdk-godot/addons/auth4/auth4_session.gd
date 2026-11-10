class_name Auth4Session
extends RefCounted
## A snapshot of the signed-in session. It deliberately carries no access or refresh token; use
## Auth4Client.get_access_token() when calling the game server.

## The tenant user ID when the API returned it (guest and upgrade flows); otherwise "".
var user_id := ""
var session_id := ""
var scope := ""
var is_guest := false
## Unix time in seconds.
var access_token_expires_at := 0.0
var can_refresh := false
## True only when a secure storage adapter holds the refresh credential.
var is_refresh_persistent := false
