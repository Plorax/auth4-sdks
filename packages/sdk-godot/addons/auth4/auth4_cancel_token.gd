class_name Auth4CancelToken
extends RefCounted
## Pass to a client call to stop waiting, for example when the player presses Cancel. Requests
## already sent are allowed to finish when their result must not be lost.

signal cancelled

var is_cancelled := false


func cancel() -> void:
	if is_cancelled:
		return
	is_cancelled = true
	cancelled.emit()
