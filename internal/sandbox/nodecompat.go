package sandbox

// installNodeCompat adds Node/V8 surface that goja lacks but that real code (and
// sandbox-detection probes) expect, so the runtime looks like genuine Node.
func (r *Runtime) installNodeCompat() {
	const js = `(function(){
    // Stack-trace support. Sanitize traces so Go/goja paths never leak into JS,
    // and support the V8 structured-stack API (Error.prepareStackTrace + CallSite
    // objects). Many packages (router, http-errors→depd, stack-trace,
    // source-map-support) set Error.prepareStackTrace and then call
    // frame.getFileName()/getLineNumber(); without real CallSite objects they
    // throw "Object has no member 'getFileName'". The string-stack fallback and
    // both Error.captureStackTrace and Error.prototype.stack share these helpers.
    var scrubRe = /(scbox|goja|\/tmp\/scbox[^\n]*|\(\*Runtime\))/g;
    function scrubStack(s){ return (typeof s === 'string') ? s.replace(scrubRe, '<anonymous>') : s; }
    var cwd = (globalThis.process && typeof process.cwd === 'function') ? process.cwd() : '/home/user/project';
    function makeCallSite(file, line, fn){
      return {
        getFileName: function(){ return file; },
        getLineNumber: function(){ return line; },
        getColumnNumber: function(){ return 1; },
        getFunctionName: function(){ return fn; },
        getMethodName: function(){ return fn; },
        getTypeName: function(){ return null; },
        getThis: function(){ return undefined; },
        getFunction: function(){ return undefined; },
        getEvalOrigin: function(){ return undefined; },
        isToplevel: function(){ return true; },
        isEval: function(){ return false; },
        isNative: function(){ return false; },
        isConstructor: function(){ return false; },
        isAsync: function(){ return false; },
        isPromiseAll: function(){ return false; },
        toString: function(){ return (fn || '<anonymous>') + ' (' + file + ':' + line + ':1)'; }
      };
    }
    // Return a depth of believable frames with DISTINCT filenames. Some callers
    // (e.g. depd) do obj.stack.slice(1) and then index several frames deep looking
    // for the first caller in a different file, so too few frames - or frames that
    // share a filename - leave them dereferencing undefined.
    function structuredFrames(){
      var frames = [];
      var n = (typeof Error.stackTraceLimit === 'number' && Error.stackTraceLimit > 0) ? Math.min(Error.stackTraceLimit, 16) : 10;
      if (n < 10) n = 10;
      for (var i = 0; i < n; i++) {
        frames.push(makeCallSite(cwd + '/node_modules/.bin/frame' + i + '.js', i + 1, i === 0 ? '<anonymous>' : 'fn' + i));
      }
      return frames;
    }
    // computeStack lazily renders a target's stack, honoring a user-installed
    // Error.prepareStackTrace (returning CallSite objects) exactly like V8.
    function computeStack(target){
      if (typeof Error.prepareStackTrace === 'function') {
        try { return Error.prepareStackTrace(target, structuredFrames()); } catch (e) {}
      }
      var n = (target && target.name) || 'Error';
      var m = (target && target.message) || '';
      return n + ': ' + m + '\n    at <anonymous>';
    }
    // defineLazyStack installs a stack accessor on target that defers to
    // computeStack (so prepareStackTrace runs at read time, as V8 does), unless a
    // plain string stack was explicitly assigned.
    function defineLazyStack(target){
      try {
        Object.defineProperty(target, 'stack', {
          configurable: true, enumerable: false,
          get: function(){
            if (typeof this.__scbox_stack === 'string') return this.__scbox_stack;
            return computeStack(this);
          },
          set: function(v){ this.__scbox_stack = scrubStack(v); }
        });
      } catch (e) {}
    }

    // Error.captureStackTrace(target) must NOT eagerly stringify the stack -
    // libraries set Error.prepareStackTrace right before reading target.stack and
    // expect CallSite objects. Install a lazy accessor instead.
    Error.captureStackTrace = function(target, ctor){ if (target) defineLazyStack(target); };
    if (typeof Error.stackTraceLimit !== 'number') { Error.stackTraceLimit = 10; }

    try { defineLazyStack(Error.prototype); } catch (e) {}

    if (typeof globalThis.structuredClone !== 'function') {
      globalThis.structuredClone = function(x){ return JSON.parse(JSON.stringify(x)); };
    }

    // TextEncoder/TextDecoder are Node globals (and WHATWG standard) that many
    // packages (content-disposition, whatwg-url, undici, etc.) use at import
    // time; their absence throws "TextDecoder is not defined". Implement UTF-8.
    if (typeof globalThis.TextEncoder !== 'function') {
      globalThis.TextEncoder = function TextEncoder(){ this.encoding = 'utf-8'; };
      globalThis.TextEncoder.prototype.encode = function(str){
        str = String(str === undefined ? '' : str);
        var out = [];
        for (var i = 0; i < str.length; i++) {
          var c = str.charCodeAt(i);
          if (c < 0x80) { out.push(c); }
          else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
          else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
            var c2 = str.charCodeAt(++i);
            var cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
            out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
          } else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)); }
        }
        return new Uint8Array(out);
      };
      globalThis.TextEncoder.prototype.encodeInto = function(str, dst){
        var enc = this.encode(str); var n = Math.min(enc.length, dst.length);
        for (var i = 0; i < n; i++) dst[i] = enc[i];
        return { read: str.length, written: n };
      };
    }
    if (typeof globalThis.TextDecoder !== 'function') {
      globalThis.TextDecoder = function TextDecoder(enc){ this.encoding = enc || 'utf-8'; this.fatal = false; this.ignoreBOM = false; };
      globalThis.TextDecoder.prototype.decode = function(buf){
        if (buf == null) return '';
        var bytes = buf.buffer ? new Uint8Array(buf.buffer, buf.byteOffset || 0, buf.byteLength != null ? buf.byteLength : buf.length) : new Uint8Array(buf);
        var out = '', i = 0;
        while (i < bytes.length) {
          var c = bytes[i++];
          if (c < 0x80) { out += String.fromCharCode(c); }
          else if (c < 0xe0) { out += String.fromCharCode(((c & 0x1f) << 6) | (bytes[i++] & 0x3f)); }
          else if (c < 0xf0) { out += String.fromCharCode(((c & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f)); }
          else { var cp = ((c & 0x07) << 18) | ((bytes[i++] & 0x3f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f); cp -= 0x10000; out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff)); }
        }
        return out;
      };
    }

    // performance.now() - referenced above for hrtime.bigint and widely probed.
    if (typeof globalThis.performance === 'undefined') {
      globalThis.performance = { now: function(){ return Date.now(); }, timeOrigin: Date.now() };
    }

    // Intl - a standard global present in Node; goja lacks it. Many i18n-aware
    // packages (string-width, yargs, date libraries) reference Intl.* at import
    // time, throwing "Intl is not defined". Provide a minimal but plausible shim.
    if (typeof globalThis.Intl === 'undefined') {
      var passThrough = function(){
        return { format: function(x){ return String(x); }, formatToParts: function(x){ return [{ type: 'literal', value: String(x) }]; }, resolvedOptions: function(){ return {}; }, select: function(){ return 'other'; } };
      };
      globalThis.Intl = {
        NumberFormat: function(){ return passThrough(); },
        DateTimeFormat: function(){ return passThrough(); },
        Collator: function(){ return { compare: function(a, b){ return a < b ? -1 : (a > b ? 1 : 0); }, resolvedOptions: function(){ return {}; } }; },
        PluralRules: function(){ return passThrough(); },
        RelativeTimeFormat: function(){ return passThrough(); },
        ListFormat: function(){ return { format: function(a){ return Array.isArray(a) ? a.join(', ') : String(a); } }; },
        Segmenter: function(){ return { segment: function(s){ return []; } }; },
        getCanonicalLocales: function(l){ return Array.isArray(l) ? l : [l]; }
      };
    }

    // MessageChannel / MessagePort - Node globals (and web standard) used by, e.g.,
    // React's scheduler for task yielding; their absence throws "MessageChannel is
    // not defined". Provide inert ports whose postMessage defers to a timer so any
    // scheduled work still drains through DrainTimers.
    if (typeof globalThis.MessagePort === 'undefined') {
      globalThis.MessagePort = function MessagePort(){ this.onmessage = null; };
      globalThis.MessagePort.prototype.postMessage = function(data){
        var self = this;
        setTimeout(function(){ if (typeof self.onmessage === 'function') { try { self.onmessage({ data: data }); } catch (e) {} } }, 0);
      };
      globalThis.MessagePort.prototype.start = function(){};
      globalThis.MessagePort.prototype.close = function(){};
      globalThis.MessagePort.prototype.addEventListener = function(t, fn){ if (t === 'message') this.onmessage = fn; };
      globalThis.MessagePort.prototype.removeEventListener = function(){};
    }
    if (typeof globalThis.MessageChannel === 'undefined') {
      globalThis.MessageChannel = function MessageChannel(){ this.port1 = new globalThis.MessagePort(); this.port2 = new globalThis.MessagePort();
        var p1 = this.port1, p2 = this.port2;
        p1.postMessage = function(d){ setTimeout(function(){ if (typeof p2.onmessage === 'function') { try { p2.onmessage({ data: d }); } catch (e) {} } }, 0); };
        p2.postMessage = function(d){ setTimeout(function(){ if (typeof p1.onmessage === 'function') { try { p1.onmessage({ data: d }); } catch (e) {} } }, 0); };
      };
    }
    if (typeof globalThis.setImmediate !== 'function') {
      globalThis.setImmediate = function(cb){ return setTimeout(cb, 0); };
      globalThis.clearImmediate = function(){};
    }

    // process.hrtime.bigint() (BigInt nanoseconds).
    try {
      if (globalThis.process && typeof process.hrtime === 'function' && typeof process.hrtime.bigint !== 'function') {
        process.hrtime.bigint = function(){ return BigInt(Math.floor((performance.now ? performance.now() : Date.now()) * 1e6)); };
      }
    } catch (e) {}

    // Web Crypto - real Node exposes a global crypto; its absence is a tell.
    if (typeof globalThis.crypto === 'undefined' || typeof globalThis.crypto.getRandomValues !== 'function') {
      globalThis.crypto = {
        getRandomValues: function(arr){ for (var i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256); return arr; },
        randomUUID: function(){ return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c){ var r = Math.random()*16|0; return (c === 'x' ? r : (r&3|8)).toString(16); }); },
        subtle: {}
      };
    }

    // WeakRef / FinalizationRegistry - standard in modern Node (v14.6+); goja
    // lacks them, and "typeof WeakRef === 'undefined'" is a clean sandbox tell.
    // We back WeakRef with a strong reference (deref always returns the target)
    // and make FinalizationRegistry a no-op registry: acceptable for analysis,
    // since GC-driven finalizers never running is indistinguishable from a
    // process that simply hasn't collected yet.
    if (typeof globalThis.WeakRef === 'undefined') {
      globalThis.WeakRef = function WeakRef(target){
        if (!(this instanceof WeakRef)) throw new TypeError("Constructor WeakRef requires 'new'");
        if (target === null || (typeof target !== 'object' && typeof target !== 'function'))
          throw new TypeError('WeakRef: target must be an object');
        this._t = target;
      };
      globalThis.WeakRef.prototype.deref = function(){ return this._t; };
    }
    if (typeof globalThis.FinalizationRegistry === 'undefined') {
      globalThis.FinalizationRegistry = function FinalizationRegistry(cb){
        if (!(this instanceof FinalizationRegistry)) throw new TypeError("Constructor FinalizationRegistry requires 'new'");
        if (typeof cb !== 'function') throw new TypeError('FinalizationRegistry: cleanup must be a function');
        this._cb = cb;
      };
      globalThis.FinalizationRegistry.prototype.register = function(){};
      globalThis.FinalizationRegistry.prototype.unregister = function(){ return false; };
    }

    // WebAssembly presence (we can't execute wasm, but absence is a tell).
    if (typeof globalThis.WebAssembly === 'undefined') {
      var ok = function(){ return Promise.resolve({ module: {}, instance: { exports: {} } }); };
      globalThis.WebAssembly = {
        compile: function(){ return Promise.resolve({}); },
        instantiate: ok,
        validate: function(){ return true; },
        Module: function(){}, Instance: function(){ this.exports = {}; },
        Memory: function(){ this.buffer = new ArrayBuffer(0); }, Table: function(){},
        CompileError: Error, RuntimeError: Error, LinkError: Error
      };
    }
  })();`
	_, _ = r.vm.RunString(js)
}
