class_name Auth4HttpTransport
extends RefCounted
## Sends one HTTP request for Auth4Client. Extend it to route requests through your own HTTP stack.


class Response:
	extends RefCounted
	## HTTP status, or 0 when the server could not be reached.
	var status_code := 0
	var headers := PackedStringArray()
	var body := ""

	func _init(status := 0, response_headers := PackedStringArray(), response_body := "") -> void:
		status_code = status
		headers = response_headers
		body = response_body

	## Values of every Set-Cookie header.
	func set_cookie_headers() -> PackedStringArray:
		var values := PackedStringArray()
		for header in headers:
			var separator := header.find(":")
			if separator > 0 and header.substr(0, separator).strip_edges().to_lower() == "set-cookie":
				values.append(header.substr(separator + 1).strip_edges())
		return values


## Sends a request and returns its response. Return Response.new() (status 0) when the server could
## not be reached. Never log the headers or body: they carry credentials.
func send(_method: String, _url: String, _headers: PackedStringArray, _body: String) -> Response:
	push_error("Auth4HttpTransport.send() is not implemented.")
	return Response.new()
