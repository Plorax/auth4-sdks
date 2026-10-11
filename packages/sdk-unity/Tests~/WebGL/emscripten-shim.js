// The slice of the Emscripten runtime that Runtime/Unity/Plugins/WebGL/Auth4Upgrade.jslib uses, so
// the real .jslib runs in a plain page without a Unity build (AUTH4D-69). It mirrors what the Unity
// toolchain does at build time: expand {{{ makeDynCall(...) }}}, merge the library and expose its
// functions with a leading underscore and its $-dependencies as globals.
(() => {
  const heap = new Uint8Array(1 << 20);
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const table = [null];
  const freed = [];
  let top = 8;

  Object.assign(window, {
    HEAPU8: heap,
    LibraryManager: { library: {} },
    mergeInto(target, source) {
      Object.assign(target, source);
    },
    autoAddDeps() {},
    _malloc(size) {
      const pointer = top;
      top += Math.ceil(size / 8) * 8;
      if (top > heap.length) throw new Error("Test heap exhausted.");
      return pointer;
    },
    _free(pointer) {
      freed.push(pointer);
    },
    lengthBytesUTF8(text) {
      return encoder.encode(text).length;
    },
    stringToUTF8(text, pointer, maxBytes) {
      const bytes = encoder.encode(text).subarray(0, maxBytes - 1);
      heap.set(bytes, pointer);
      heap[pointer + bytes.length] = 0;
    },
    UTF8ToString(pointer) {
      let end = pointer;
      while (heap[end] !== 0) end++;
      return decoder.decode(heap.subarray(pointer, end));
    },
    getWasmTableEntry(index) {
      return table[index];
    },
  });

  window.emscripten = {
    heap,
    freed,
    /** Registers a JS function as a wasm table entry, like a C# [MonoPInvokeCallback] pointer. */
    addFunction(fn) {
      table.push(fn);
      return table.length - 1;
    },
    /** Copies a string into the heap, as IL2CPP does when marshalling a string argument. */
    allocString(text) {
      const size = window.lengthBytesUTF8(text) + 1;
      const pointer = window._malloc(size);
      window.stringToUTF8(text, pointer, size);
      return { pointer, size };
    },
    heapContains(text) {
      const needle = encoder.encode(text);
      outer: for (let i = 0; i <= top - needle.length; i++) {
        for (let j = 0; j < needle.length; j++) if (heap[i + j] !== needle[j]) continue outer;
        return true;
      }
      return false;
    },
    async loadLibrary(url) {
      const source = (await (await fetch(url)).text()).replace(
        /\{\{\{\s*makeDynCall\('([a-z]+)',\s*'([A-Za-z_$][\w$.]*)'\)\s*\}\}\}/gu,
        "getWasmTableEntry($2)",
      );
      (0, eval)(source);
      for (const [name, value] of Object.entries(window.LibraryManager.library)) {
        if (name.startsWith("$")) window[name.slice(1)] = value;
        else window[`_${name}`] = value;
      }
    },
  };
})();
