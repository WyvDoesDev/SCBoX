package sandbox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"

	"scbox/internal/third_party/goja"

	"scbox/internal/trace"
)

// reDecodedHost matches a hostname (api.jsonstorage.net, www.foo.io, …) inside a
// decoded blob.
var reDecodedHost = regexp.MustCompile(`(?i)\b([a-z0-9-]+\.)+[a-z]{2,}\b`)

// highSignalDecoded reports whether a decoded blob looks like a real payload worth
// capturing even during the force-exec fuzz sweep: it carries a network endpoint
// (URL/host) or a loader/exec token. Synthetic fuzz inputs decode to high-entropy
// garbage that lacks these, so this keeps fuzz noise out while still recording a
// package's own base64-hidden C2 URL or staged loader.
func highSignalDecoded(s string) bool {
	if strings.Contains(s, "://") {
		return true
	}
	ls := strings.ToLower(s)
	for _, t := range []string{"child_process", "spawn", "exec(", "eval(", "require(",
		"function(", "curl ", "wget ", "powershell", "/bin/sh", "atob(", "http"} {
		if strings.Contains(ls, t) {
			return true
		}
	}
	return reDecodedHost.MatchString(s)
}

// installGlobals wires the non-module globals a Node script expects: console,
// Buffer, atob/btoa, and the timer family. Each is a logged stub.
func (r *Runtime) installGlobals() {
	g := r.vm.GlobalObject()

	// global / globalThis self-reference, as Node scripts often probe these.
	set(g, "global", g)
	set(g, "globalThis", g)

	r.installConsole(g)
	r.installBuffer(g)
	r.installTimers(g)
	r.installFetch(g)
	r.installWebGlobals(g)
}

// installWebGlobals adds browser/runtime network globals that packages reach for
// outside the Node core modules: WebSocket, XMLHttpRequest. Each is logged.
func (r *Runtime) installWebGlobals(g *goja.Object) {
	must(r.vm.Set("__trace_net", r.fn(func(call goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatNet, argStr(call.Argument(0)), argStr(call.Argument(1)))
		return goja.Undefined()
	})))
	const js = `(function(){
    var _net = globalThis.__trace_net;  // captured before the global is deleted
    globalThis.WebSocket = function(url, protocols){
      _net('WebSocket', String(url));
      this.url = url; this.readyState = 1;
      this.send = function(d){ _net('WebSocket.send', typeof d === 'string' ? d : ''); };
      this.close = function(){}; this.addEventListener = function(){};
      this.on = function(){ return this; };
    };
    globalThis.XMLHttpRequest = function(){
      var u = '', m = '';
      this.open = function(method, url){ m = method || ''; u = url || ''; _net('XHR.open', m + ' ' + u); };
      this.send = function(body){ _net('XHR.send', body === undefined ? u : String(body)); };
      this.setRequestHeader = function(){}; this.addEventListener = function(){};
      this.getAllResponseHeaders = function(){ return ''; };
      Object.defineProperty(this, 'responseText', { get: function(){ return ''; } });
      Object.defineProperty(this, 'status', { get: function(){ return 200; } });
    };
    globalThis.importScripts = function(){ for (var i=0;i<arguments.length;i++) _net('importScripts', String(arguments[i])); };
    // EventSource (SSE) - a long-poll C2/exfil channel; record the endpoint.
    globalThis.EventSource = function(url){
      _net('EventSource', String(url));
      this.url = url; this.readyState = 1; this.withCredentials = false;
      this.addEventListener = function(){}; this.removeEventListener = function(){};
      this.close = function(){}; this.onmessage = null; this.onerror = null; this.onopen = null;
    };
  })();`
	if _, err := r.vm.RunString(js); err != nil {
		panic("sandbox: web globals failed: " + err.Error())
	}

	// navigator: checked for hardwareConcurrency (a count of 1 screams sandbox).
	nav := r.obj()
	set(nav, "hardwareConcurrency", r.profile.CPU.Threads)
	set(nav, "userAgent", "Mozilla/5.0 (X11; Linux x86_64) Node.js/20.11.0")
	set(nav, "platform", "Linux x86_64")
	set(nav, "language", "en-US")
	set(nav, "languages", r.vm.NewArray("en-US", "en"))
	set(nav, "deviceMemory", int(r.profile.TotalMem>>30))
	// sendBeacon is a fire-and-forget exfil primitive (no response to await);
	// record the endpoint and body like any other network egress.
	set(nav, "sendBeacon", r.fn(func(call goja.FunctionCall) goja.Value {
		url := argStr(call.Argument(0))
		r.tr.Record(trace.CatNet, "navigator.sendBeacon", url)
		if b := call.Argument(1); !goja.IsUndefined(b) && !goja.IsNull(b) {
			r.tr.AddPayload(argStr(b))
		}
		return r.vm.ToValue(true)
	}))
	set(g, "navigator", nav)
}

// isString reports whether a value is a JS string primitive.
func isString(v goja.Value) bool {
	if v == nil {
		return false
	}
	t := v.ExportType()
	return t != nil && t.Kind().String() == "string"
}

func (r *Runtime) stringifyValue(v goja.Value) string {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return ""
	}
	if stringify := r.jsonStringify(); stringify != nil {
		if s, err := stringify(goja.Undefined(), v); err == nil && s != nil && !goja.IsUndefined(s) {
			return s.String()
		}
	}
	return argStr(v)
}

func (r *Runtime) stringifyArgs(args []goja.Value) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, r.stringifyValue(a))
	}
	return out
}

func (r *Runtime) jsonStringify() goja.Callable {
	jsonObj := r.vm.GlobalObject().Get("JSON").ToObject(r.vm)
	if jsonObj == nil {
		return nil
	}
	stringify, _ := goja.AssertFunction(jsonObj.Get("stringify"))
	return stringify
}

// installFetch provides a logged fetch() that returns a resolved Response-like
// promise so async exfil chains keep running.
func (r *Runtime) installFetch(g *goja.Object) {
	set(g, "fetch", r.fn(func(call goja.FunctionCall) goja.Value {
		url := argStr(call.Argument(0))
		r.tr.Record(trace.CatNet, "fetch", url)
		if opts := call.Argument(1); !goja.IsUndefined(opts) {
			if o := opts.ToObject(r.vm); o != nil {
				if b := o.Get("body"); b != nil && !goja.IsUndefined(b) {
					r.tr.Record(trace.CatNet, "fetch.body", argStr(b))
					r.tr.AddPayload(argStr(b))
				}
				if h := o.Get("headers"); h != nil && !goja.IsUndefined(h) {
					r.tr.AddHeader(argStr(h))
				}
			}
		}
		resp := r.obj()
		set(resp, "ok", true)
		set(resp, "status", 200)
		set(resp, "statusText", "OK")
		set(resp, "headers", r.obj())
		set(resp, "text", r.fn(func(goja.FunctionCall) goja.Value { return r.resolvedPromise(r.vm.ToValue(fetchedJSON)) }))
		set(resp, "json", r.fn(func(goja.FunctionCall) goja.Value { return r.resolvedPromise(r.markerData()) }))
		set(resp, "arrayBuffer", r.fn(func(goja.FunctionCall) goja.Value { return r.resolvedPromise(r.makeBuffer([]byte("/* fetched */"))) }))
		set(resp, "clone", r.fn(func(goja.FunctionCall) goja.Value { return resp }))
		// body is a readable stream a download-and-execute chain pipes/reads
		// (`fetch(c2).then(r => r.body.pipe(fs.createWriteStream(...)))`); without it
		// the chain dereferences undefined and the payload write is never seen.
		body := r.newEmitter().ToObject(r.vm)
		set(body, "pipe", r.fn(func(c goja.FunctionCall) goja.Value { return c.Argument(0) }))
		set(body, "getReader", r.fn(func(goja.FunctionCall) goja.Value {
			rd := r.obj()
			done := false
			set(rd, "read", r.fn(func(goja.FunctionCall) goja.Value {
				res := r.obj()
				if done {
					set(res, "done", true)
					set(res, "value", goja.Undefined())
				} else {
					done = true
					set(res, "done", false)
					set(res, "value", r.makeBuffer([]byte(fetchedJSON)))
				}
				return r.resolvedPromise(res)
			}))
			set(rd, "releaseLock", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
			return rd
		}))
		set(resp, "body", body)
		r.emitLater(body, "data", r.makeBuffer([]byte(fetchedJSON)))
		r.emitLater(body, "end")
		return r.resolvedPromise(resp)
	}))
}

func (r *Runtime) installConsole(g *goja.Object) {
	con := r.obj()
	logf := func(level string) goja.Value {
		return r.fn(func(call goja.FunctionCall) goja.Value {
			r.tr.Record(trace.CatConsole, level, r.stringifyArgs(call.Arguments)...)
			return goja.Undefined()
		})
	}
	for _, lvl := range []string{"log", "info", "warn", "error", "debug", "trace", "dir"} {
		set(con, lvl, logf(lvl))
	}
	set(g, "console", con)
}

// makeTimerHandle mimics the Node Timeout object setTimeout returns (browsers
// return a number; returning a number in "Node" is a sandbox tell).
func (r *Runtime) makeTimerHandle() goja.Value {
	o := r.obj()
	self := r.vm.ToValue(o)
	ret := func(goja.FunctionCall) goja.Value { return self }
	set(o, "ref", r.fn(ret))
	set(o, "unref", r.fn(ret))
	set(o, "refresh", r.fn(ret))
	set(o, "hasRef", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(true) }))
	set(o, "close", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(o, "_idleTimeout", 1)
	set(o, "_destroyed", false)
	return self
}

// maxPendingTimers caps how many scheduled callbacks may sit in the pending
// queue at once. The drain loop only ever runs cfg.MaxTimers of them, so a
// hostile `for(;;) setTimeout(()=>{},0)` (interruptible, but it appends until
// the budget fires) would otherwise grow this slice to millions of entries and
// spike host memory for no analytical benefit. Beyond the cap we drop new
// schedulings - the payload's scheduling intent is already recorded by the
// timer IOCs.
const maxPendingTimers = 100000

// queueCallback enqueues a zero-delay callback (nextTick/microtask).
func (r *Runtime) queueCallback(cb goja.Callable) {
	if len(r.pending) >= maxPendingTimers {
		return
	}
	r.pending = append(r.pending, timerJob{cb: cb, muted: r.tr.Muted()})
}

// queueTimer enqueues a callback with its scheduled delay so the virtual clock
// can advance when it runs. Extra args are the values Node forwards to the
// callback: setTimeout(cb, delay, ...args).
func (r *Runtime) queueTimer(cb goja.Callable, delay float64, args ...goja.Value) {
	if delay < 0 {
		delay = 0
	}
	if len(r.pending) >= maxPendingTimers {
		return
	}
	r.pending = append(r.pending, timerJob{cb: cb, delay: delay, args: args, muted: r.tr.Muted()})
}

func (r *Runtime) installTimers(g *goja.Object) {
	schedule := func(name string) goja.Value {
		return r.fn(func(call goja.FunctionCall) goja.Value {
			a0 := call.Argument(0)
			delay := call.Argument(1).ToFloat()
			if delay != delay { // NaN
				delay = 0
			}
			if cb, ok := goja.AssertFunction(a0); ok {
				r.tr.Record(trace.CatTimer, name)
				// Node forwards setTimeout(cb, delay, ...args) to the callback;
				// passing them through keeps callbacks that dereference their first
				// parameter from throwing "Value is not an object: undefined".
				var extra []goja.Value
				if len(call.Arguments) > 2 {
					extra = call.Arguments[2:]
				}
				r.queueTimer(cb, delay, extra...)
				return r.makeTimerHandle()
			} else if isString(a0) {
				// setTimeout("code", t) executes the string as code - a common
				// way to hide eval. Queue a synthetic callback that runs it.
				code := a0.String()
				r.tr.Record(trace.CatTimer, name+"(string)", code)
				r.queueTimer(func(this goja.Value, args ...goja.Value) (goja.Value, error) {
					v, _ := r.RunString(name+"-string", code)
					if v == nil {
						return goja.Undefined(), nil
					}
					return v, nil
				}, delay)
				return r.makeTimerHandle()
			}
			return r.makeTimerHandle()
		})
	}
	set(g, "setTimeout", schedule("setTimeout"))
	set(g, "setInterval", schedule("setInterval"))
	set(g, "setImmediate", schedule("setImmediate"))
	set(g, "queueMicrotask", schedule("queueMicrotask"))
	noop := r.fn(func(call goja.FunctionCall) goja.Value { return goja.Undefined() })
	set(g, "clearTimeout", noop)
	set(g, "clearInterval", noop)
	set(g, "clearImmediate", noop)
}

// ---- Buffer / base64 ----

// fetchedMarker is the sentinel our fake network responses carry. A
// download-and-execute loader pulls a remote stage and runs it; by serving this
// marker as the "fetched" body we can recognize it when it lands in an eval /
// Function / require sink. Loaders routinely transform the body first
// (Buffer.from(stage,'base64').toString(), atob(stage)), which would shred the
// literal - so the decode stubs below detect a marker-bearing input and pass the
// marker through unchanged, keeping the taint intact across the transform.
const fetchedMarker = "/* fetched */"

// fetchedJSON is a JSON-encoded response body whose common payload fields all
// carry the marker. Loaders that buffer a raw HTTP response and JSON.parse it
// before reading a field (JSON.parse(data).session, manifest.cookie) need a body
// that survives a real parse with the marker reachable under whatever key they
// pick; loaders that eval the body directly still see the marker in the string.
const fetchedJSON = `{"cookie":"/* fetched */","content":"/* fetched */","content_o":"/* fetched */","data":"/* fetched */","code":"/* fetched */","payload":"/* fetched */","session":"/* fetched */","script":"/* fetched */","token":"/* fetched */","message":"/* fetched */","errCode":"/* fetched */"}`

// markerData returns the any-property-marker proxy (res.json() etc.).
func (r *Runtime) markerData() goja.Value {
	if fn, ok := goja.AssertFunction(r.fetchedData); ok {
		if v, err := fn(goja.Undefined()); err == nil {
			return v
		}
	}
	return r.obj()
}

// makeBuffer wraps raw bytes in a Node-Buffer-like object. It is backed by a
// real Uint8Array so indexing (b[i]), .length, iteration and typed-array
// methods behave like a genuine Buffer (which subclasses Uint8Array) - a plain
// object would make b[i] undefined, an easy sandbox/foulup tell.
func (r *Runtime) makeBuffer(b []byte) *goja.Object {
	o := r.newByteArray(b)
	if o == nil {
		o = r.obj()
		set(o, "length", len(b))
	}
	// live reads the CURRENT bytes of the buffer. The buffer is a real Uint8Array,
	// so a script's in-place byte writes (`out[i] = x`) land in its backing store -
	// but the methods below must read THAT store, not the slice `b` captured at
	// construction. Closing over `b` was a real blind spot: the javascript-obfuscator
	// XOR-deobfuscation idiom `out = Buffer.allocUnsafe(n); for(...) out[i] = src[i] ^
	// key[i]; out.toString('utf8')` returned the original (dirty/zero) allocUnsafe
	// bytes instead of the XOR result, so the decoded second stage was garbage and a
	// whole malware family (bn-math/ultra-base64-math/animatecss-style loaders) read
	// as clean. Export() of a Uint8Array yields its live []byte.
	live := func() []byte {
		if bb, ok := o.Export().([]byte); ok {
			return bb
		}
		return b
	}
	set(o, "__isBuffer", true)
	set(o, "toString", r.fn(func(call goja.FunctionCall) goja.Value {
		cur := live()
		enc := "utf8"
		if a := call.Argument(0); !goja.IsUndefined(a) {
			enc = a.String()
		}
		switch enc {
		case "base64":
			return r.vm.ToValue(base64.StdEncoding.EncodeToString(cur))
		case "base64url":
			return r.vm.ToValue(base64.RawURLEncoding.EncodeToString(cur))
		case "hex":
			return r.vm.ToValue(hex.EncodeToString(cur))
		default:
			return r.vm.ToValue(string(cur))
		}
	}))
	// Expose indexed byte access loosely via a "bytes" array for scripts that
	// inspect contents.
	set(o, "toJSON", r.fn(func(call goja.FunctionCall) goja.Value {
		cur := live()
		arr := make([]any, len(cur))
		for i, by := range cur {
			arr[i] = int(by)
		}
		return r.vm.ToValue(map[string]any{"type": "Buffer", "data": arr})
	}))
	set(o, "equals", r.fn(func(call goja.FunctionCall) goja.Value {
		other := call.Argument(0).ToObject(r.vm)
		return r.vm.ToValue(other != nil && other.Get("length") != nil && int(other.Get("length").ToInteger()) == len(live()))
	}))
	set(o, "slice", r.fn(func(call goja.FunctionCall) goja.Value {
		cur := live()
		start := int(call.Argument(0).ToInteger())
		end := len(cur)
		if a := call.Argument(1); !goja.IsUndefined(a) {
			end = int(a.ToInteger())
		}
		if start < 0 || start > len(cur) {
			start = 0
		}
		if end < start || end > len(cur) {
			end = len(cur)
		}
		return r.makeBuffer(cur[start:end])
	}))
	return o
}

// newByteArray builds a real Uint8Array containing b, or nil on failure.
func (r *Runtime) newByteArray(b []byte) *goja.Object {
	ctorVal := r.vm.Get("Uint8Array")
	ctor, ok := goja.AssertConstructor(ctorVal)
	if !ok {
		return nil
	}
	vals := make([]interface{}, len(b))
	for i, by := range b {
		vals[i] = int64(by)
	}
	arr, err := ctor(nil, r.vm.ToValue(vals))
	if err != nil || arr == nil {
		return nil
	}
	return arr
}

func (r *Runtime) bufferFrom(call goja.FunctionCall) goja.Value {
	arg := call.Argument(0)
	enc := "utf8"
	if a := call.Argument(1); !goja.IsUndefined(a) {
		enc = a.String()
	}
	// Array of byte values, e.g. Buffer.from([104,105]).
	if raw, ok := arg.Export().([]any); ok {
		b := make([]byte, len(raw))
		for i, v := range raw {
			switch n := v.(type) {
			case int64:
				b[i] = byte(n)
			case float64:
				b[i] = byte(int64(n))
			}
		}
		return r.makeBuffer(b)
	}
	s := arg.String()
	// Preserve the fetched-payload taint across the decode: a loader that does
	// Buffer.from(res.data.x, 'base64').toString() to recover its stage must still
	// hand the marker to the eval/Function sink that follows.
	if strings.Contains(s, fetchedMarker) {
		return r.makeBuffer([]byte(fetchedMarker))
	}
	var b []byte
	switch enc {
	case "base64", "base64url":
		// Try standard then URL-safe (and unpadded) base64 - `base64url` is a real
		// Node encoding, and payloads use the URL alphabet to avoid +/= in URLs.
		if dec, ok := decodeBase64Any(s); ok {
			b = dec
		} else {
			b = []byte(s)
		}
		if len(b) >= 6 {
			r.tr.AddDecoded(string(b))
		}
		r.tr.Record(trace.CatEval, "Buffer.from(base64)", string(b))
	case "hex":
		if dec, err := hex.DecodeString(s); err == nil {
			b = dec
			if len(b) >= 6 {
				r.tr.AddDecoded(string(b))
			}
			r.tr.Record(trace.CatEval, "Buffer.from(hex)", string(b))
		} else {
			b = []byte(s)
		}
	default:
		b = []byte(s)
	}
	return r.makeBuffer(b)
}

// decodeBase64Any tries standard, raw-standard, URL-safe, and raw-URL base64 - the
// forms a payload uses (incl. Node's `base64url`) to slip past + / = filtering.
func decodeBase64Any(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if dec, err := enc.DecodeString(s); err == nil {
			return dec, true
		}
	}
	return nil, false
}

func (r *Runtime) installBuffer(g *goja.Object) {
	buf := r.obj()
	set(buf, "from", r.fn(r.bufferFrom))
	set(buf, "alloc", r.fn(func(call goja.FunctionCall) goja.Value {
		n := int(call.Argument(0).ToInteger())
		if n < 0 || n > 1<<24 {
			n = 0
		}
		return r.makeBuffer(make([]byte, n))
	}))
	// allocUnsafe / allocUnsafeSlow return UNINITIALIZED memory in real Node - the
	// bytes are whatever was on the reused heap page, usually non-zero. Returning a
	// zero-filled buffer (like alloc) is a faked-allocator tell that evasive code
	// checks (Buffer.allocUnsafe(n) all-zero ⇒ "I'm in a sandbox"). Hand back dirty
	// pseudo-random bytes so it looks like a real allocation.
	allocUnsafe := r.fn(func(call goja.FunctionCall) goja.Value {
		n := int(call.Argument(0).ToInteger())
		if n < 0 || n > 1<<24 {
			n = 0
		}
		b := make([]byte, n)
		_, _ = rand.Read(b)
		return r.makeBuffer(b)
	})
	set(buf, "allocUnsafe", allocUnsafe)
	set(buf, "allocUnsafeSlow", allocUnsafe)
	set(buf, "isBuffer", r.fn(func(call goja.FunctionCall) goja.Value {
		o := call.Argument(0).ToObject(r.vm)
		return r.vm.ToValue(o != nil && o.Get("__isBuffer") != nil && o.Get("__isBuffer").ToBoolean())
	}))
	set(buf, "concat", r.fn(func(call goja.FunctionCall) goja.Value {
		// Actually concatenate the chunk bytes - a chunked decoder
		// (`eval(Buffer.concat(parts).toString())`) is a common loader shape, and a
		// stub that returned an empty buffer silently swallowed the whole payload.
		obj := call.Argument(0).ToObject(r.vm)
		if obj == nil || obj.ClassName() != "Array" {
			return r.makeBuffer(nil)
		}
		var out []byte
		n := int(obj.Get("length").ToInteger())
		// Clamp the element count: n comes straight from JS, and when the elements
		// are empty/undefined the 16MB output cap below never trips, so a hostile
		// `Buffer.concat({length: 2**31})` would spin billions of uninterruptible
		// iterations (the goja interrupt cannot break this Go loop). No legitimate
		// concat has anywhere near 1M buffers.
		if n < 0 {
			n = 0
		} else if n > 1<<20 {
			n = 1 << 20
		}
		for i := 0; i < n && len(out) < 1<<24; i++ {
			out = append(out, r.valueBytes(obj.Get(strconv.Itoa(i)), "utf8")...)
		}
		if len(out) >= 6 {
			r.tr.AddDecoded(string(out))
		}
		return r.makeBuffer(out)
	}))
	set(g, "Buffer", buf)

	set(g, "atob", r.fn(func(call goja.FunctionCall) goja.Value {
		in := call.Argument(0).String()
		// Keep the fetched-payload taint alive through atob(stage) decoding.
		if strings.Contains(in, fetchedMarker) {
			return r.vm.ToValue(fetchedMarker)
		}
		dec, err := base64.StdEncoding.DecodeString(in)
		if err != nil {
			return r.vm.ToValue("")
		}
		// atob driven by our ForceExecute fuzzing (feeding synthetic strings into a
		// library's decoders/regex builders) is a sandbox artifact - zod emitted
		// 628 such events, which falsely read as "heavy deobfuscation / packed". Skip
		// the noisy CatEval record while fuzzing - BUT still capture the decoded blob
		// when it is high-signal (a URL/host/loader token), because a DPRK loader
		// hides its C2 URL in base64 and only decodes it when its export is
		// force-executed; dropping that would be a false negative.
		if len(dec) >= 6 && (!r.exploreQuiet || highSignalDecoded(string(dec))) {
			r.tr.AddDecoded(string(dec))
		}
		if !r.exploreQuiet {
			r.tr.Record(trace.CatEval, "atob", string(dec))
		}
		return r.vm.ToValue(string(dec))
	}))
	set(g, "btoa", r.fn(func(call goja.FunctionCall) goja.Value {
		return r.vm.ToValue(base64.StdEncoding.EncodeToString([]byte(call.Argument(0).String())))
	}))
}
