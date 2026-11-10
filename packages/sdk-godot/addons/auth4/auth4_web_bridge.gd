class_name Auth4WebBridge
extends RefCounted
## Opens auth4.dev windows in web exports through JavaScriptBridge (AUTH4D-219). Auth4Client uses it
## for sign_in_with_browser() and the popup path of upgrade_guest() whenever is_supported() is true.
## Extend it to run the client against another window host, as the tests do.
##
## The JavaScript side (SOURCE) accepts upgrade-window messages only from the popup it opened and
## only when event.origin is exactly the auth origin, and posts the guest access token only to that
## origin. It reads the sign-in result from the popup once the popup is back on the game's origin.
## Nothing is written to a URL or to browser storage.

## Installed once per page as window.auth4GodotBridge. ES5 and no backslashes, so it survives the
## GDScript string and every browser Godot exports to.
const SOURCE := """
(function () {
  if (window.auth4GodotBridge) return;
  var FEATURES = "popup,width=480,height=720";
  var CLOSED_POLL_MS = 500;
  var LOCATION_POLL_MS = 200;
  var GESTURE_EVENTS = ["pointerup", "touchend"];
  var states = {};

  // Hands one event to GDScript. A GDScript error must not unwind into the browser's dispatch.
  function emit(state, kind, data) {
    if (state.stopped) return;
    try {
      state.callback(state.handle, kind, data);
    } catch (error) {
      // Ignored.
    }
  }

  function disarm(state) {
    if (!state.onGesture) return;
    for (var i = 0; i < GESTURE_EVENTS.length; i++) {
      window.removeEventListener(GESTURE_EVENTS[i], state.onGesture, true);
    }
    state.onGesture = null;
  }

  function stop(state) {
    state.stopped = true;
    disarm(state);
    if (state.onMessage) window.removeEventListener("message", state.onMessage);
    if (state.poll) clearInterval(state.poll);
    state.onMessage = null;
    state.poll = 0;
    if (states[state.handle] === state) delete states[state.handle];
  }

  function isClosed(popup) {
    try {
      return popup.closed;
    } catch (error) {
      // Treat an inaccessible window as closed.
      return true;
    }
  }

  // The sign-in result, once the popup has been redirected back to the game's own origin. Only the
  // query is passed on; the popup is closed at once, so the one-time code is not left on screen.
  function callbackQuery(state) {
    var href = null;
    try {
      href = state.popup.location.href;
    } catch (error) {
      // Still on the auth origin, which this page cannot read.
      return null;
    }
    var at = null;
    try {
      at = new URL(href);
    } catch (error) {
      return null;
    }
    if (at.origin !== state.redirect.origin || at.pathname !== state.redirect.pathname) return null;
    return at.search.length > 1 ? at.search : null;
  }

  function watch(state) {
    if (state.redirect) {
      var query = callbackQuery(state);
      if (query) {
        emit(state, "callback", query);
        try {
          state.popup.close();
        } catch (error) {
          // Already closed.
        }
        stop(state);
        return;
      }
    }
    if (isClosed(state.popup)) {
      emit(state, "closed", "");
      stop(state);
    }
  }

  // Must run inside a browser user gesture, or the popup is blocked.
  function open(state) {
    disarm(state);
    if (state.stopped) return;
    var popup = null;
    try {
      // Without noopener: the hosted upgrade page needs window.opener for the handshake, and the
      // sign-in popup must stay readable once it returns to this origin.
      popup = window.open(state.url, state.name, FEATURES);
    } catch (error) {
      popup = null;
    }
    if (!popup) {
      emit(state, "blocked", "");
      stop(state);
      return;
    }
    state.popup = popup;
    if (!state.redirect) {
      state.onMessage = function (event) {
        receive(state, event);
      };
      window.addEventListener("message", state.onMessage);
    }
    state.poll = setInterval(function () {
      watch(state);
    }, state.redirect ? LOCATION_POLL_MS : CLOSED_POLL_MS);
    emit(state, "opened", "");
  }

  function receive(state, event) {
    // Every message must come from the upgrade window, on the exact auth origin.
    if (state.stopped || event.origin !== state.authOrigin || event.source !== state.popup) return;
    var message = event.data;
    if (!message || typeof message !== "object") return;
    switch (message.type) {
      case "auth4:guest-upgrade:ready":
        if (typeof message.tenant_id === "string" && typeof message.client_id === "string") {
          emit(state, "ready", JSON.stringify({ tenant_id: message.tenant_id, client_id: message.client_id }));
        }
        return;
      case "auth4:guest-upgrade:complete":
        if (message.result && typeof message.result === "object") {
          emit(state, "complete", JSON.stringify(message.result));
        }
        return;
      case "auth4:guest-upgrade:error":
        if (typeof message.error === "string") emit(state, "error", message.error);
        return;
      case "auth4:guest-upgrade:cancelled":
        emit(state, "cancelled", "");
        return;
      default:
        return;
    }
  }

  function hasUserActivation() {
    var activation = typeof navigator === "undefined" ? null : navigator.userActivation;
    return !!(activation && activation.isActive);
  }

  // Godot handles input a frame after the browser event has returned. When the browser no longer
  // counts that input as a user gesture, the popup opens on the player's next pointer-up or
  // touch-end, which the browser does count.
  function start(state) {
    if (states[state.handle]) stop(states[state.handle]);
    states[state.handle] = state;
    if (hasUserActivation()) {
      open(state);
      return;
    }
    state.onGesture = function () {
      open(state);
    };
    for (var i = 0; i < GESTURE_EVENTS.length; i++) {
      // Capture phase, so the Godot canvas cannot swallow the event first.
      window.addEventListener(GESTURE_EVENTS[i], state.onGesture, true);
    }
  }

  // The URL when it is exactly on the auth origin at the expected path, otherwise null.
  function authPage(url, authOrigin, path) {
    try {
      var parsed = new URL(url);
      if (new URL(authOrigin).origin !== authOrigin) return null;
      if (parsed.origin !== authOrigin || parsed.pathname !== path || parsed.hash) return null;
      return parsed;
    } catch (error) {
      return null;
    }
  }

  function newState(handle, url, authOrigin, callback, name) {
    return {
      handle: handle,
      url: url,
      authOrigin: authOrigin,
      callback: callback,
      name: name,
      redirect: null,
      popup: null,
      onGesture: null,
      onMessage: null,
      poll: 0,
      stopped: false
    };
  }

  window.auth4GodotBridge = {
    // Opens {authOrigin}/login/upgrade?tenant_id&client_id. Returns 0 when the URL is unsafe.
    openUpgrade: function (handle, url, authOrigin, callback) {
      var parsed = authPage(url, authOrigin, "/login/upgrade");
      if (!parsed) return 0;
      start(newState(handle, parsed.href, authOrigin, callback, "auth4-guest-upgrade"));
      return 1;
    },

    // Opens {authOrigin}/oauth/authorize and waits for the redirect back to redirectUri, which must
    // be on this page's origin. Returns 0 when either URL is unsafe.
    openSignIn: function (handle, url, authOrigin, redirectUri, callback) {
      var parsed = authPage(url, authOrigin, "/oauth/authorize");
      if (!parsed) return 0;
      var redirect = null;
      try {
        redirect = new URL(redirectUri);
      } catch (error) {
        return 0;
      }
      if (redirect.origin !== window.location.origin || redirect.hash) return 0;
      if (parsed.searchParams.get("redirect_uri") !== redirectUri) return 0;
      var state = newState(handle, parsed.href, authOrigin, callback, "auth4-sign-in");
      state.redirect = redirect;
      start(state);
      return 1;
    },

    // Answers a ready message. The token goes only to the popup, with the auth origin as target.
    sendToken: function (handle, accessToken) {
      var state = states[handle];
      if (!state || !state.popup || state.redirect) return 0;
      try {
        state.popup.postMessage({ type: "auth4:guest-upgrade:token", access_token: accessToken }, state.authOrigin);
        return 1;
      } catch (error) {
        // The window navigated away; it repeats the handshake when it returns.
        return 0;
      }
    },

    // Closes the window (or stops waiting for the gesture) and stops listening.
    close: function (handle) {
      var state = states[handle];
      if (!state) return;
      try {
        if (state.popup) state.popup.close();
      } catch (error) {
        // Already closed.
      }
      stop(state);
    },

    // Stops listening but leaves the window open, so the hosted page can show its outcome.
    release: function (handle) {
      var state = states[handle];
      if (state) stop(state);
    }
  };
})();
"""

var _bridge: JavaScriptObject = null
## JavaScript callbacks by handle. Godot frees a callback once nothing references it.
var _callbacks := {}
var _next_handle := 0


## True in a web export, where JavaScriptBridge can open browser windows.
func is_supported() -> bool:
	return OS.has_feature("web")


## Opens the hosted guest-upgrade page in a popup. `on_event` receives (kind: String, data: String)
## for opened, blocked, ready, complete, error, cancelled and closed. Returns a handle, or 0 when
## the page is not /login/upgrade on the auth origin.
func open_upgrade_window(url: String, auth_origin: String, on_event: Callable) -> int:
	return _open("openUpgrade", [url, auth_origin], on_event)


## Opens the authorization URL in a popup. `on_event` receives opened, blocked, closed, or callback
## with the query string of the redirect to `redirect_uri`, which must be on the page's origin.
## Returns a handle, or 0 when either URL is refused.
func open_sign_in_window(
	url: String, auth_origin: String, redirect_uri: String, on_event: Callable
) -> int:
	return _open("openSignIn", [url, auth_origin, redirect_uri], on_event)


## Posts the guest access token to the upgrade window, targeting the auth origin.
func send_access_token(handle: int, access_token: String) -> void:
	var bridge := _interface()
	if bridge != null and _callbacks.has(handle) and not access_token.is_empty():
		bridge.call("sendToken", handle, access_token)


## Closes the window and stops listening.
func close_window(handle: int) -> void:
	var bridge := _interface()
	if bridge != null and _callbacks.erase(handle):
		bridge.call("close", handle)


## Stops listening but leaves the window open, so the hosted page can show its outcome.
func release_window(handle: int) -> void:
	var bridge := _interface()
	if bridge != null and _callbacks.erase(handle):
		bridge.call("release", handle)


func _open(method: String, arguments: Array, on_event: Callable) -> int:
	var bridge := _interface()
	if bridge == null:
		return 0
	_next_handle += 1
	var handle := _next_handle
	var callback := JavaScriptBridge.create_callback(
		func(args: Array) -> void: _dispatch(handle, args, on_event)
	)
	_callbacks[handle] = callback
	var opened: Variant = bridge.callv(method, [handle] + arguments + [callback])
	if not (opened is float or opened is int) or int(opened) != 1:
		_callbacks.erase(handle)
		return 0
	return handle


func _dispatch(handle: int, args: Array, on_event: Callable) -> void:
	if not _callbacks.has(handle) or args.size() < 2:
		return
	var kind := str(args[1])
	var data := str(args[2]) if args.size() > 2 and args[2] != null else ""
	if kind == "blocked" or kind == "closed" or kind == "callback":
		# The JavaScript side has already stopped; drop the callback once this call returns.
		_forget.call_deferred(handle)
	on_event.call(kind, data)


func _forget(handle: int) -> void:
	_callbacks.erase(handle)


func _interface() -> JavaScriptObject:
	if _bridge == null and is_supported():
		JavaScriptBridge.eval(SOURCE, true)
		_bridge = JavaScriptBridge.get_interface("auth4GodotBridge")
	return _bridge
