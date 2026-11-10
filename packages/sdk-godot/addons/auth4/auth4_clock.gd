class_name Auth4Clock
extends RefCounted
## Time and delay source for Auth4Client. Override it in tests to control polling and expiry.

const _STEP := 0.25


## Seconds since the Unix epoch.
func now() -> float:
	return Time.get_unix_time_from_system()


## Waits about `seconds`, returning early once `cancel` fires.
func delay(seconds: float, cancel: Auth4CancelToken) -> void:
	var tree := Engine.get_main_loop() as SceneTree
	var remaining := seconds
	while remaining > 0.0 and not (cancel != null and cancel.is_cancelled):
		var step := minf(_STEP, remaining)
		await tree.create_timer(step, true, false, true).timeout
		remaining -= step
