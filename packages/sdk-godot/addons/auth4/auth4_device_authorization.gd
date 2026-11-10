class_name Auth4DeviceAuthorization
extends RefCounted
## A pending device authorization. Show user_code and verification_uri to the player.

enum _State { IDLE, POLLING, COMPLETED }

var user_code := ""
var verification_uri := ""
## Verification URL with the code included, suitable for a QR code. May be "".
var verification_uri_complete := ""
## Unix time in seconds.
var expires_at := 0.0
var interval_seconds := 5
var scope := ""

var _device_code := ""
var _state := _State.IDLE


## True once polling finished with a session or a terminal error.
func is_completed() -> bool:
	return _state == _State.COMPLETED
