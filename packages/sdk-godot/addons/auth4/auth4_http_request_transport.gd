class_name Auth4HttpRequestTransport
extends Auth4HttpTransport
## Default transport built on HTTPRequest nodes. Each request adds a temporary child to `host`,
## so the host (normally the Auth4Client) must be inside the scene tree.

const _METHODS := {"GET": HTTPClient.METHOD_GET, "POST": HTTPClient.METHOD_POST}

var timeout_seconds := 30.0
var _host: Node


func _init(host: Node) -> void:
	_host = host


func send(method: String, url: String, headers: PackedStringArray, body: String) -> Response:
	if not is_instance_valid(_host) or not _host.is_inside_tree():
		push_error("Add the Auth4Client to the scene tree before calling it.")
		return Response.new()
	var request := HTTPRequest.new()
	request.timeout = timeout_seconds
	request.accept_gzip = false
	_host.add_child(request)
	var started := request.request(url, headers, _METHODS.get(method, HTTPClient.METHOD_POST), body)
	if started != OK:
		request.queue_free()
		return Response.new()
	var completed: Array = await request.request_completed
	request.queue_free()
	if completed[0] != HTTPRequest.RESULT_SUCCESS:
		return Response.new()
	var raw: PackedByteArray = completed[3]
	return Response.new(completed[1], completed[2], raw.get_string_from_utf8())
