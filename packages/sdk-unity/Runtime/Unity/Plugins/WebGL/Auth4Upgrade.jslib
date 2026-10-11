// auth4.dev guest upgrade bridge for Unity WebGL (AUTH4D-69), used by Auth4.Unity.WebGLUpgradeWindow.
// It runs the opener side of the hosted /login/upgrade window protocol (docs/api-spec/auth4d-23.md).
// Messages are accepted only from the popup this bridge opened and only when event.origin is exactly
// the auth origin; the guest access token is posted only to that origin. Nothing is written to a URL
// or to browser storage. ES5 only, so every Unity Emscripten toolchain accepts it.
var Auth4UpgradeLibrary = {
  $Auth4Upgrade: {
    windowName: "auth4-guest-upgrade",
    windowFeatures: "popup,width=480,height=720",
    closedPollMs: 500,
    gestureEvents: ["pointerup", "touchend"],
    states: {},

    // Hands one event to C#. Strings live in the wasm heap only for the call; the payload, which
    // may hold the upgraded token set, is zeroed before it is freed.
    emit: function (state, kind, data) {
      if (state.stopped) return;
      var callback = state.callback;
      var kindSize = lengthBytesUTF8(kind) + 1;
      var dataSize = lengthBytesUTF8(data) + 1;
      var kindPtr = _malloc(kindSize);
      var dataPtr = _malloc(dataSize);
      stringToUTF8(kind, kindPtr, kindSize);
      stringToUTF8(data, dataPtr, dataSize);
      try {
        {{{ makeDynCall('viii', 'callback') }}}(state.handle, kindPtr, dataPtr);
      } finally {
        HEAPU8.fill(0, dataPtr, dataPtr + dataSize);
        _free(kindPtr);
        _free(dataPtr);
      }
    },

    disarm: function (state) {
      if (!state.onGesture) return;
      for (var i = 0; i < Auth4Upgrade.gestureEvents.length; i++) {
        window.removeEventListener(Auth4Upgrade.gestureEvents[i], state.onGesture, true);
      }
      state.onGesture = null;
    },

    stop: function (state) {
      state.stopped = true;
      Auth4Upgrade.disarm(state);
      if (state.onMessage) window.removeEventListener("message", state.onMessage);
      if (state.poll) clearInterval(state.poll);
      state.onMessage = null;
      state.poll = 0;
      delete Auth4Upgrade.states[state.handle];
    },

    // Must run inside a browser user gesture, or the popup is blocked.
    open: function (state) {
      Auth4Upgrade.disarm(state);
      if (state.stopped) return;
      var popup = null;
      try {
        // Without noopener: the hosted page needs window.opener for the handshake.
        popup = window.open(state.url, Auth4Upgrade.windowName, Auth4Upgrade.windowFeatures);
      } catch (error) {
        popup = null;
      }
      if (!popup) {
        Auth4Upgrade.emit(state, "blocked", "");
        Auth4Upgrade.stop(state);
        return;
      }
      state.popup = popup;
      state.onMessage = function (event) {
        Auth4Upgrade.receive(state, event);
      };
      window.addEventListener("message", state.onMessage);
      state.poll = setInterval(function () {
        var closed = true;
        try {
          closed = popup.closed;
        } catch (error) {
          // Treat an inaccessible window as closed.
        }
        if (closed) {
          Auth4Upgrade.emit(state, "closed", "");
          Auth4Upgrade.stop(state);
        }
      }, Auth4Upgrade.closedPollMs);
      Auth4Upgrade.emit(state, "opened", "");
    },

    receive: function (state, event) {
      // Every message must come from the upgrade window, on the exact auth origin.
      if (state.stopped || event.origin !== state.authOrigin || event.source !== state.popup) return;
      var message = event.data;
      if (!message || typeof message !== "object") return;
      switch (message.type) {
        case "auth4:guest-upgrade:ready":
          if (typeof message.tenant_id === "string" && typeof message.client_id === "string") {
            Auth4Upgrade.emit(
              state,
              "ready",
              JSON.stringify({ tenant_id: message.tenant_id, client_id: message.client_id })
            );
          }
          return;
        case "auth4:guest-upgrade:complete":
          if (message.result && typeof message.result === "object") {
            Auth4Upgrade.emit(state, "complete", JSON.stringify(message.result));
          }
          return;
        case "auth4:guest-upgrade:error":
          if (typeof message.error === "string") Auth4Upgrade.emit(state, "error", message.error);
          return;
        case "auth4:guest-upgrade:cancelled":
          Auth4Upgrade.emit(state, "cancelled", "");
          return;
        default:
          return;
      }
    },

    hasUserActivation: function () {
      var activation = typeof navigator === "undefined" ? null : navigator.userActivation;
      return !!(activation && activation.isActive);
    },
  },

  // Opens {authOrigin}/login/upgrade?tenant_id&client_id for the C# handle. Returns 0 when the
  // arguments are unsafe. When the browser no longer counts the current input as a user gesture
  // (Unity handles input a frame after the browser event), the popup opens on the player's next
  // pointer-up or touch-end, which the browser does count.
  Auth4Upgrade_Open: function (handle, urlPtr, authOriginPtr, callback) {
    var url = UTF8ToString(urlPtr);
    var authOrigin = UTF8ToString(authOriginPtr);
    var parsed;
    try {
      parsed = new URL(url);
      if (new URL(authOrigin).origin !== authOrigin) return 0;
    } catch (error) {
      return 0;
    }
    if (parsed.origin !== authOrigin || parsed.pathname !== "/login/upgrade" || parsed.hash) return 0;
    if (Auth4Upgrade.states[handle]) Auth4Upgrade.stop(Auth4Upgrade.states[handle]);

    var state = {
      handle: handle,
      url: parsed.href,
      authOrigin: authOrigin,
      callback: callback,
      popup: null,
      onGesture: null,
      onMessage: null,
      poll: 0,
      stopped: false,
    };
    Auth4Upgrade.states[handle] = state;
    if (Auth4Upgrade.hasUserActivation()) {
      Auth4Upgrade.open(state);
    } else {
      state.onGesture = function () {
        Auth4Upgrade.open(state);
      };
      for (var i = 0; i < Auth4Upgrade.gestureEvents.length; i++) {
        // Capture phase, so the Unity canvas cannot swallow the event first.
        window.addEventListener(Auth4Upgrade.gestureEvents[i], state.onGesture, true);
      }
    }
    return 1;
  },

  // Answers a ready message. The token goes only to the popup, with the auth origin as target.
  Auth4Upgrade_SendToken: function (handle, tokenPtr) {
    var state = Auth4Upgrade.states[handle];
    if (!state || !state.popup) return 0;
    try {
      state.popup.postMessage(
        { type: "auth4:guest-upgrade:token", access_token: UTF8ToString(tokenPtr) },
        state.authOrigin
      );
      return 1;
    } catch (error) {
      // The window navigated away; it repeats the handshake when it returns.
      return 0;
    }
  },

  // Closes the window (or stops waiting for the gesture) and stops listening.
  Auth4Upgrade_Close: function (handle) {
    var state = Auth4Upgrade.states[handle];
    if (!state) return;
    try {
      if (state.popup) state.popup.close();
    } catch (error) {
      // Already closed.
    }
    Auth4Upgrade.stop(state);
  },

  // Stops listening but leaves the window open, so the hosted page can show its outcome.
  Auth4Upgrade_Release: function (handle) {
    var state = Auth4Upgrade.states[handle];
    if (state) Auth4Upgrade.stop(state);
  },
};

autoAddDeps(Auth4UpgradeLibrary, "$Auth4Upgrade");
mergeInto(LibraryManager.library, Auth4UpgradeLibrary);
