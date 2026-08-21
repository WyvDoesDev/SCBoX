package sandbox

import (
	"fmt"
	"strings"
	"time"

	"scbox/internal/third_party/goja"

	"scbox/internal/trace"
	"scbox/internal/vfs"
)

// maxDepth bounds how deep into nested object graphs the sweep recurses. Together
// with the per-object `visited` set it guarantees termination on cyclic graphs.
// There is deliberately NO per-file invocation cap: every reachable export is
// fuzzed so a payload can't hide behind a high export index. The ultimate
// runtime bound is the wall-clock TotalBudget (via r.stopped()), plus the
// optional whole-run cfg.MaxExplore knob (unlimited by default).
const maxDepth = 3

// maxProtoMethods caps how many prototype methods are force-invoked per object,
// bounding the cost of a class with a large method surface.
const maxProtoMethods = 64

// fuzzArgs builds a broad argument list used to coax exported functions into
// running their bodies. A noop callback is included so callback-style APIs fire.
func (r *Runtime) fuzzArgs() []goja.Value {
	// Build the noop callback in JS, not Go: a Go-backed func stringifies (and
	// reports .name) as "scbox/internal/sandbox.(*Runtime).fuzzArgs.func1",
	// which leaks the sandbox into any sample that does String(cb) or cb.name -
	// a trivial sandbox-detection vector. A JS arrow has no Go identity.
	cb := goja.Undefined()
	if v, err := r.vm.RunString("(function(){return function(){};})()"); err == nil {
		cb = v
	}
	return []goja.Value{
		r.vm.ToValue("test"),
		r.vm.ToValue(1),
		r.vm.ToValue(true),
		r.obj(),
		r.vm.NewArray(),
		cb,
	}
}

// magicLeads returns common "magic" leading-argument values that malware uses to
// gate a payload behind a specific input - e.g. `function getUniqueID(_id){ if
// (_id == 64) { …decrypt+eval… } }` (the DPRK random-string-64 family, where the
// gate value is even in the package name). Force-execution retries each export
// with these as the first argument so the gated branch actually runs. Powers of
// two and round sizes cover the overwhelming majority of such length/id gates.
func (r *Runtime) magicLeads() []goja.Value {
	nums := []int{64, 32, 16, 8, 128, 256, 512, 1024, 100, 0, 2, 4, 255}
	out := make([]goja.Value, 0, len(nums)+2)
	for _, n := range nums {
		out = append(out, r.vm.ToValue(n))
	}
	out = append(out, r.vm.ToValue("64"), r.vm.ToValue("true"))
	return out
}

// exploreExhausted reports whether the optional whole-run force-exec budget is
// spent. With cfg.MaxExplore <= 0 (the default) there is NO global cap, so the
// sweep detonates every file and fuzzes every export - full coverage, since a
// payload can hide anywhere and fire late.
func (r *Runtime) exploreExhausted() bool {
	if r.cfg.MaxExplore <= 0 {
		return false
	}
	if r.exploreCount >= r.cfg.MaxExplore {
		if !r.exploreCapNoted {
			r.exploreCapNoted = true
			r.tr.Note(trace.CatExplore, "explore-budget-reached",
				fmt.Sprintf("hit MaxExplore=%d invocations", r.cfg.MaxExplore))
		}
		return true
	}
	return false
}

// ForceExecute walks an exports value and invokes every reachable function
// (and constructs every class) with fuzzed arguments to trip payloads that are
// gated behind being called rather than running at import time.
func (r *Runtime) ForceExecute(exports goja.Value) {
	if r.exploreExhausted() {
		return
	}
	// Behavior provoked by our fuzzed arguments is noise, not sample behavior:
	// mute the tracer (events kept in the trace, excluded from the verdict) and
	// silence error-recording for the duration of the sweep.
	prevQuiet := r.setQuiet(true)
	defer r.setQuiet(prevQuiet)
	r.tr.Record(trace.CatExplore, "force-execute-begin")
	args := r.fuzzArgs()
	cbOnly := []goja.Value{args[len(args)-1]}
	leads := r.magicLeads()
	visited := map[*goja.Object]bool{}

	// budget reports whether the optional whole-run cap is hit (unlimited by
	// default). Termination otherwise comes from maxDepth + visited + stopped().
	budget := func() bool { return r.exploreExhausted() }
	// inc charges one invocation against the whole-run counter.
	inc := func() { r.exploreCount++ }

	// invokeFn drives one function through every argument shape, with `this` bound
	// to thisV (the instance, for prototype methods). It pumps the job queue after
	// each call: a variant that throws (a fuzz arg where the payload wanted an
	// array → `x.reduce` TypeError) raises an interrupt that DISCARDS goja's
	// pending jobs, which would otherwise wipe an async chain a sibling variant
	// just scheduled, so each must detonate before the next can clear it.
	invokeFn := func(fn goja.Callable, thisV goja.Value, label string) {
		invoke := func(callArgs ...goja.Value) {
			inc()
			r.safeCall("export:"+label, fn, thisV, callArgs...)
			r.guard("force-execute-pump", func() { r.pumpMicrotasks() })
		}
		invoke(args...)
		// Call with no arguments so payloads that live entirely in default
		// parameters fire: `async (tok=secret, opts=[c2a,c2b]) => opts.reduce(…)`
		// only detonates when nothing is supplied and the malicious defaults take
		// effect - fuzz args would otherwise overwrite them.
		if !budget() {
			invoke()
		}
		if !budget() {
			invoke(cbOnly...)
		}
		// Retry with each magic gate value leading, so a payload behind
		// `if (arg == 64)` runs (see magicLeads).
		for _, lead := range leads {
			if budget() || r.stopped() {
				break
			}
			invoke(append([]goja.Value{lead}, args[1:]...)...)
		}
	}

	var walk func(v goja.Value, label string, depth int)
	walk = func(v goja.Value, label string, depth int) {
		if v == nil || depth > maxDepth || budget() || r.stopped() {
			return
		}
		if goja.IsUndefined(v) || goja.IsNull(v) {
			return
		}

		if fn, ok := goja.AssertFunction(v); ok {
			r.tr.Record(trace.CatExplore, "invoke", label)
			invokeFn(fn, goja.Undefined(), label)
			// Also attempt to construct it (covers classes).
			if c, ok := goja.AssertConstructor(v); ok && !budget() {
				inc()
				if inst, err := r.tryConstruct(c, args); err == nil && inst != nil {
					walk(inst, label+"::new", depth+1)
				}
			}
		}

		o := r.safeToObject(v, label)
		if o == nil || visited[o] {
			return
		}
		visited[o] = true
		for _, k := range r.safeKeys(o, label) {
			if budget() {
				break
			}
			if strings.HasPrefix(k, "__") {
				continue
			}
			walk(r.safeGet(o, k, label+"."+k), label+"."+k, depth+1)
		}
		// Walk prototype methods too. A class hides its payload in a METHOD
		// (theta-connector's queryDBConnect: `axios.get(atob(c2)) → spawn('node') →
		// child.stdin.write(stage)`), and methods live on the prototype as
		// non-enumerable properties that o.Keys() never returns. Invoke each with
		// `this` bound to the instance so a method that uses this.* still runs.
		// Walk prototype methods only on a directly-reached object (the constructed
		// instance / exports), NOT on values returned by calls. A fluent library
		// (knex, sequelize) returns a fresh chainable object from every method, so
		// recursing into their prototypes explodes into hundreds of thousands of
		// invocations and force-runs benign builder internals that read as activity.
		// A class hiding a payload exposes it as a method on the instance one level
		// down (exports → construct → instance), so depth<=2 with a per-object cap
		// keeps the coverage while bounding the blast radius.
		if !budget() && depth <= 2 {
			objProto := r.objectProtoValue()
			invoked := 0
			for proto := o.Prototype(); proto != nil && proto != objProto && invoked < maxProtoMethods; proto = proto.Prototype() {
				for _, k := range r.safeOwnNames(proto, label) {
					if budget() || invoked >= maxProtoMethods {
						break
					}
					if k == "constructor" || strings.HasPrefix(k, "__") {
						continue
					}
					m := r.safeGet(proto, k, label+"#"+k)
					if mf, ok := goja.AssertFunction(m); ok {
						invoked++
						r.tr.Record(trace.CatExplore, "invoke", label+"#"+k)
						invokeFn(mf, o, label+"#"+k)
					}
				}
			}
		}
	}
	// Backstop: any panic the granular guards below don't catch (an unforeseen
	// goja path, a proxy trap we don't poke directly) is contained here so the
	// sweep can never crash the analyzer - no matter what the package runs.
	r.guard("force-execute", func() { walk(exports, "exports", 0) })
	// Drain async work the fuzzed calls scheduled: a payload that runs in a
	// promise continuation - buildoptimize()'s `…reduce((c,o)=>c.then(()=>req(o,cb)))`
	// chain, an `await fetch(c2)` body - only reaches its eval/exec sink once the
	// job queue advances. Without this the call returns a pending promise and the
	// download-and-execute stage never fires (a false negative).
	r.guard("force-execute-pump", func() { r.pumpMicrotasks() })
	r.tr.Record(trace.CatExplore, "force-execute-end")
}

// guard runs fn, recovering from any panic. goja surfaces uncaught JS
// exceptions, throwing proxy traps, and VM interrupts as Go panics, and the
// explore sweep deliberately pokes hostile code - so every entry point that
// drives untrusted JS is wrapped to honor the guarantee that no analyzed
// package can crash the host process.
func (r *Runtime) guard(what string, fn func()) {
	defer func() {
		if e := recover(); e != nil {
			r.tr.Note(trace.CatExplore, "halted", safePanic(e), what)
		}
	}()
	fn()
}

// safeKeys enumerates an object's own keys, recovering from a throwing Proxy
// ownKeys trap (or any other exception the enumeration triggers).
func (r *Runtime) safeKeys(o *goja.Object, label string) (keys []string) {
	defer func() {
		if e := recover(); e != nil {
			if !r.exploreQuiet {
				r.tr.Note(trace.CatExplore, "keys-halted", safePanic(e), label)
			}
			keys = nil
		}
	}()
	return o.Keys()
}

// safeOwnNames returns an object's own property names (including non-enumerable
// ones, e.g. class prototype methods), recovering from any proxy trap panic.
func (r *Runtime) safeOwnNames(o *goja.Object, label string) (keys []string) {
	defer func() {
		if e := recover(); e != nil {
			keys = nil
		}
	}()
	return o.GetOwnPropertyNames()
}

// objectProtoValue caches the realm's Object.prototype so the prototype-method
// walk stops there instead of force-calling Object.prototype built-ins.
func (r *Runtime) objectProtoValue() *goja.Object {
	if r.objectProto == nil {
		if v, err := r.vm.RunString("Object.prototype"); err == nil {
			r.objectProto = v.ToObject(r.vm)
		}
	}
	return r.objectProto
}

// safeToObject coerces a value to an object, recovering from any exception a
// Proxy/valueOf/Symbol.toPrimitive trap throws during coercion.
func (r *Runtime) safeToObject(v goja.Value, label string) (o *goja.Object) {
	defer func() {
		if e := recover(); e != nil {
			if !r.exploreQuiet {
				r.tr.Note(trace.CatExplore, "toobject-halted", safePanic(e), label)
			}
			o = nil
		}
	}()
	return v.ToObject(r.vm)
}

// safeGet reads a property, recovering from any JS exception thrown by an
// accessor (getter) so a hostile or buggy getter can't crash the sweep. goja
// surfaces uncaught JS exceptions as Go panics, and property reads invoke
// getters, so this read needs the same protection as safeCall does for calls.
func (r *Runtime) safeGet(o *goja.Object, key, label string) (ret goja.Value) {
	defer func() {
		if e := recover(); e != nil {
			if !r.exploreQuiet {
				r.tr.Note(trace.CatExplore, "get-halted", safePanic(e), label)
			}
			ret = goja.Undefined()
		}
	}()
	return o.Get(key)
}

func (r *Runtime) tryConstruct(c goja.Constructor, args []goja.Value) (ret *goja.Object, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = nil // swallow; constructor side effects already traced
			ret = nil
		}
	}()
	timer := time.AfterFunc(r.cfg.Timeout, func() { r.vm.Interrupt("timeout exceeded") })
	defer timer.Stop()
	o, e := c(nil, args...)
	r.vm.ClearInterrupt()
	return o, e
}

// CollectExplorable walks the in-memory FS under root and returns the JS-like
// files to force-execute and the shell scripts to run, skipping node_modules
// (dependency code) and type-declaration files. Separating discovery from
// execution lets callers shard the file list across parallel runtimes.
func CollectExplorable(fs *vfs.FS, root string) (jsFiles, shFiles []string) {
	fs.Walk(root, func(p string, isDir bool) {
		if isDir {
			return
		}
		// Skip anything under a node_modules directory (dependency code is probed
		// separately via RequireDeps).
		if strings.Contains(p, "/node_modules/") {
			return
		}
		lp := strings.ToLower(p)
		switch {
		case isSkippableSource(lp):
			// Pure type-declaration files transpile to no runtime code - skip them.
		case strings.HasSuffix(lp, ".js"), strings.HasSuffix(lp, ".cjs"), strings.HasSuffix(lp, ".mjs"),
			strings.HasSuffix(lp, ".ts"), strings.HasSuffix(lp, ".cts"), strings.HasSuffix(lp, ".mts"),
			strings.HasSuffix(lp, ".tsx"), strings.HasSuffix(lp, ".jsx"):
			jsFiles = append(jsFiles, p)
		case strings.HasSuffix(lp, ".sh"):
			shFiles = append(shFiles, p)
		}
	})
	return jsFiles, shFiles
}

// isSkippableSource reports whether a lower-cased path is a pure TypeScript
// type-declaration file. These hold only ambient types (interfaces, declare
// statements) and transpile to no runtime code, so force-executing them is
// wasted work with zero coverage loss. Nothing else is skipped - test,
// benchmark, and fixture files CAN carry import-time payloads and are detonated.
func isSkippableSource(lp string) bool {
	return strings.HasSuffix(lp, ".d.ts") ||
		strings.HasSuffix(lp, ".d.cts") ||
		strings.HasSuffix(lp, ".d.mts")
}

// ExploreFiles loads and force-executes each JS file and runs each shell file.
// Each file is wrapped in guard() so a hostile file can't crash the run, and
// the run aborts early once the analysis budget is exhausted. Shared by the
// sequential DetonateFiles path and the parallel explore workers.
func (r *Runtime) ExploreFiles(jsFiles, shFiles []string) {
	for _, abs := range jsFiles {
		if r.stopped() {
			return
		}
		r.tr.Record(trace.CatExplore, "detonate-file", abs)
		r.guard("detonate:"+abs, func() {
			// Force-loading a file standalone runs it OUT of its normal require
			// context (wrong entry variant, missing globals a real host provides),
			// so a top-level throw here - e.g. react-dom's deliberate "Incompatible
			// React versions" / "not supported in React Server Components" guards -
			// is a detonation artifact, not sample behavior. Its real side effects
			// (fs/net/proc/eval) are still recorded by the builtins as they run; only
			// the trailing throw is suppressed. Quiet just the load.
			prevQuiet := r.setQuiet(true)
			exports := r.ld.loadFile(abs)
			// Drain this file's deferred async (download-and-execute IIFEs, etc.)
			// NOW, before another file's interrupt can clear goja's job queue.
			r.pumpMicrotasks()
			r.setQuiet(prevQuiet)
			r.ForceExecute(exports)
		})
	}
	for _, abs := range shFiles {
		if r.stopped() {
			return
		}
		r.guard("shell:"+abs, func() { r.RunShellFile(abs) })
	}

	// Second pass: detonate dropper-catch payloads. A dropper hides its install /
	// download step in the CATCH of `try{require('x')}catch{ … }` and may even
	// declare `x` as a dependency so npm fetches it - so pass 1 (which fakes
	// declared/known deps to keep payload-after-require alive) leaves the catch
	// untaken. Re-run each file with forceThrowRequire so every unresolved require
	// throws and those catches fire. Limited to files that actually contain a
	// try/catch around a require/import, to avoid pointless re-execution.
	prevThrow := r.forceThrowRequire
	r.forceThrowRequire = true
	for _, abs := range jsFiles {
		if r.stopped() {
			break
		}
		src, ok := r.cfg.FS.Read(abs)
		if !ok || !looksLikeDropperCatch(src) {
			continue
		}
		r.guard("dropper-catch:"+abs, func() {
			delete(r.ld.cache, abs) // force a fresh execution, not the cached module
			prevQuiet := r.setQuiet(true)
			exports := r.ld.loadFile(abs)
			r.pumpMicrotasks()
			r.setQuiet(prevQuiet)
			r.ForceExecute(exports)
		})
	}
	r.forceThrowRequire = prevThrow
}

// looksLikeDropperCatch reports whether the source has a catch handler near a
// require/import - the shape whose payload only runs when the require throws.
func looksLikeDropperCatch(src []byte) bool {
	s := string(src)
	return strings.Contains(s, "catch") &&
		(strings.Contains(s, "require(") || strings.Contains(s, "import("))
}

// DetonateFiles requires every .js/.cjs file in the package so payloads hidden
// in non-entry files still run. node_modules is skipped (dependency code).
func (r *Runtime) DetonateFiles() {
	js, sh := CollectExplorable(r.cfg.FS, r.cfg.BaseDir)
	r.ExploreFiles(js, sh)
}

// RequireDeps attempts to require each declared dependency, tripping any module
// that runs malicious code at import time (most do).
func (r *Runtime) RequireDeps(deps []string) {
	for _, d := range deps {
		r.tr.Record(trace.CatExplore, "probe-dependency", d)
		d := d
		r.guard("probe:"+d, func() { r.ld.require(d, r.cfg.BaseDir) })
	}
}
