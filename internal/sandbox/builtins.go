package sandbox

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"scbox/internal/third_party/goja"

	"scbox/internal/trace"
)

// builtinRegistry maps Node core module names to lazy constructors. Security-
// critical modules get detailed fakes; the rest fall back to a logging Proxy.
func (r *Runtime) builtinRegistry() map[string]func() goja.Value {
	reg := map[string]func() goja.Value{
		"fs":             r.modFS,
		"fs/promises":    r.modFSPromises,
		"child_process":  r.modChildProcess,
		"http":           func() goja.Value { return r.modHTTP("http") },
		"https":          func() goja.Value { return r.modHTTP("https") },
		"net":            r.modNet,
		"tls":            r.modNet,
		"dns":            r.modDNS,
		"dns/promises":   r.modDNS,
		"os":             r.modOS,
		"path":           r.modPath,
		"path/posix":     r.modPath,
		"crypto":         r.modCrypto,
		"util":           r.modUtil,
		"events":         r.modEvents,
		"stream":         r.modStream,
		"vm":             r.modVM,
		"url":            r.modURL,
		"module":         r.modModule,
		"querystring":    r.modQuerystring,
		"assert":         r.modAssert,
		"perf_hooks":     r.modPerfHooks,
		"dgram":          r.modDgram,
		"http2":          r.modHTTP2,
		"worker_threads": r.modWorkerThreads,
		"zlib":           r.modZlib,
		"inspector":      r.modInspector,
	}
	// Light fakes for the long tail. These are all real Node core modules present
	// in every install; proxying them keeps a module that imports one alive instead
	// of throwing MODULE_NOT_FOUND and aborting before a later payload runs (only an
	// unknown third-party specifier should throw, to trip dropper catch-blocks).
	for _, name := range []string{
		"cluster", "readline", "readline/promises", "tty", "v8", "string_decoder",
		"constants", "process", "timers", "timers/promises", "async_hooks",
		"diagnostics_channel", "trace_events", "wasi", "punycode", "domain",
		"stream/promises", "stream/web", "stream/consumers", "util/types",
		"path/win32",
	} {
		n := name
		reg[n] = func() goja.Value { return r.callMkFake(n) }
	}
	return reg
}

// ---- helpers ----

// lastCallback returns the trailing argument if it is a function.
func (r *Runtime) lastCallback(call goja.FunctionCall) (goja.Callable, bool) {
	if n := len(call.Arguments); n > 0 {
		return goja.AssertFunction(call.Arguments[n-1])
	}
	return nil, false
}

func (r *Runtime) invoke(cb goja.Callable, args ...goja.Value) {
	r.safeCall("callback", cb, goja.Undefined(), args...)
}

// goCallback wraps a Go closure as a goja.Callable so it can be handed to the
// pending-callback queue (queueCallback), letting native mocks defer work until
// after the current script frame the same way nextTick/setTimeout do.
func (r *Runtime) goCallback(f func()) goja.Callable {
	cb, _ := goja.AssertFunction(r.fn(func(goja.FunctionCall) goja.Value {
		f()
		return goja.Undefined()
	}))
	return cb
}

// fireConnection simulates a connection/bind succeeding on a socket-or-session
// emitter: it defers the optional connectListener and emits each named "ready"
// event ('connect', 'secureConnect', 'listening', …). Everything is queued onto
// the pending list rather than called inline, because the handler carrying the
// payload (a reverse/bind shell, an exfil channel) closes over the
// `const s = net.connect(...)`/`tls.connect(...)` variable, which isn't assigned
// until the calling expression returns. Firing inline would run the handler
// before `s` exists; deferring runs it once the script frame settles. Without
// this, any behavior gated on connection success dangles and is never observed.
func (r *Runtime) fireConnection(em *goja.Object, connectListener goja.Callable, events ...string) {
	if connectListener != nil {
		r.queueCallback(r.goCallback(func() { r.invoke(connectListener) }))
	}
	for _, ev := range events {
		r.emitLater(em, ev)
	}
}

// emitLater defers `em.emit(name, args...)` onto the pending queue so a listener
// registered after the current native call (the common `x = source(); x.on(...)`
// shape) is in place before the event fires. This is the general fix for any
// async EventEmitter source the analyzer fakes - sockets, child-process stdio,
// file streams - whose data/lifecycle events would otherwise never arrive,
// leaving payloads gated on them (read-output-then-exfil) dangling and unseen.
func (r *Runtime) emitLater(em *goja.Object, name string, args ...goja.Value) {
	emit, ok := goja.AssertFunction(em.Get("emit"))
	if !ok {
		return
	}
	// Build the emit arg list now (name + payload); the buffers are created on this
	// VM thread, then replayed when the queued job runs.
	call := append([]goja.Value{r.vm.ToValue(name)}, args...)
	r.queueCallback(r.goCallback(func() {
		// emit is an EventEmitter prototype method; it reads this._ev, so bind `this`
		// to the emitter via safeCall (invoke would bind this=undefined).
		r.safeCall("emit-"+name, emit, em, call...)
	}))
}

// method sets a logged no-result method on an object.
func (r *Runtime) logged(cat trace.Category, op string, ret func() goja.Value) goja.Value {
	return r.fn(func(call goja.FunctionCall) goja.Value {
		r.tr.Record(cat, op, r.displayArgs(call)...)
		if ret != nil {
			return ret()
		}
		return goja.Undefined()
	})
}

// displayArg renders one call argument for the trace. Strings/primitives use the
// fast argStr path; objects (e.g. an fs options bag like {throwIfNoEntry:false})
// are JSON-encoded via the safe stringifier so they read meaningfully instead of
// the useless "[object Object]". Returns "" for values that should be omitted (a
// featureless/empty options object), which displayArgs drops.
func (r *Runtime) displayArg(a goja.Value) string {
	s := argStr(a)
	if s == "[object Object]" {
		if j := r.stringifyValue(a); j != "" && j != "{}" {
			return j
		}
		return "" // featureless/empty options object: omit rather than show noise
	}
	return s
}

// displayArgs renders call arguments for the trace, dropping empties so a lone
// path arg isn't trailed by blank options.
func (r *Runtime) displayArgs(call goja.FunctionCall) []string {
	out := make([]string, 0, len(call.Arguments))
	for _, a := range call.Arguments {
		if s := r.displayArg(a); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---- fs ----

func (r *Runtime) modFS() goja.Value {
	m := r.obj()

	readSync := r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "readFileSync", p)
		r.tr.AddPath(p)
		content, notExist := r.readFake(p)
		if notExist {
			// Behave like a real machine: missing file → ENOENT.
			panic(r.nodeError("ENOENT", "open", p))
		}
		if enc := call.Argument(1); !goja.IsUndefined(enc) {
			return r.vm.ToValue(content)
		}
		return r.makeBuffer([]byte(content))
	})
	set(m, "readFileSync", readSync)
	set(m, "readFile", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "readFile", p)
		r.tr.AddPath(p)
		content, notExist := r.readFake(p)
		if cb, ok := r.lastCallback(call); ok {
			if notExist {
				r.invoke(cb, r.nodeError("ENOENT", "open", p))
			} else {
				r.invoke(cb, goja.Null(), r.vm.ToValue(content))
			}
		}
		return goja.Undefined()
	}))

	writeSync := r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		data := argStr(call.Argument(1))
		r.tr.Record(trace.CatFS, "writeFileSync", p, data)
		r.tr.AddDropped(p)
		r.vfsWrite(p, data, false)
		return goja.Undefined()
	})
	set(m, "writeFileSync", writeSync)
	set(m, "writeFile", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "writeFile", p, argStr(call.Argument(1)))
		r.tr.AddDropped(p)
		r.vfsWrite(p, argStr(call.Argument(1)), false)
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null())
		}
		return goja.Undefined()
	}))
	set(m, "appendFileSync", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "appendFileSync", p, argStr(call.Argument(1)))
		r.tr.AddDropped(p)
		r.vfsWrite(p, argStr(call.Argument(1)), true)
		return goja.Undefined()
	}))
	set(m, "appendFile", m.Get("writeFile"))

	set(m, "existsSync", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "existsSync", p)
		return r.vm.ToValue(r.pathExists(p))
	}))
	set(m, "readdirSync", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "readdirSync", p)
		return r.vm.NewArray(r.fakeDirListing(p)...)
	}))
	set(m, "readdir", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "readdir", p)
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null(), r.vm.NewArray(r.fakeDirListing(p)...))
		}
		return goja.Undefined()
	}))
	set(m, "mkdirSync", r.logged(trace.CatFS, "mkdirSync", nil))

	// mkdtempSync/mkdtemp create a uniquely-named temp directory and RETURN its
	// path. Droppers stage a payload there - mkdtempSync(tmp) → writeFileSync(
	// dir/dropper.js) → spawn(node,[dir/dropper.js]) - so without this fake the
	// call hits an undefined function, throws, and the loader aborts BEFORE the
	// spawn, leaving the whole dropper unobserved (webpack-cache-clean shape).
	// Append a random suffix to the prefix (Node mkdtemp semantics) so the staged
	// write lands under a path the subsequent spawn can re-read from the vfs.
	mkdtempPath := func(call goja.FunctionCall) string {
		prefix := argStr(call.Argument(0))
		b := make([]byte, 3)
		_, _ = rand.Read(b)
		p := prefix + hex.EncodeToString(b)
		r.tr.Record(trace.CatFS, "mkdtempSync", p)
		return p
	}
	set(m, "mkdtempSync", r.fn(func(call goja.FunctionCall) goja.Value {
		return r.vm.ToValue(mkdtempPath(call))
	}))
	set(m, "mkdtemp", r.fn(func(call goja.FunctionCall) goja.Value {
		p := mkdtempPath(call)
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null(), r.vm.ToValue(p))
		}
		return goja.Undefined()
	}))

	// Deletions are destructive/anti-forensic - surface the target path as a
	// first-class IOC, logging only the path (not the options object). But a
	// deletion driven by our ForceExecute fuzzing (e.g. force-calling fs-extra's
	// remove()/rmrf() with synthetic args like "function(){}", "undefined/x") is a
	// sandbox artifact, not the sample deleting anything - recording it as a
	// destructive IOC falsely flags benign file-utility libraries (fs-extra,
	// rimraf) as "deletes N files". Record + score deletions only outside the sweep.
	delSync := func(op string) goja.Value {
		return r.fn(func(call goja.FunctionCall) goja.Value {
			p := argStr(call.Argument(0))
			r.vfsDelete(p)
			if !r.exploreQuiet {
				r.tr.Record(trace.CatFS, op, p)
				r.tr.AddDeleted(p)
			}
			return goja.Undefined()
		})
	}
	delAsync := func(op string) goja.Value {
		return r.fn(func(call goja.FunctionCall) goja.Value {
			p := argStr(call.Argument(0))
			r.vfsDelete(p)
			if !r.exploreQuiet {
				r.tr.Record(trace.CatFS, op, p)
				r.tr.AddDeleted(p)
			}
			if cb, ok := r.lastCallback(call); ok {
				r.invoke(cb, goja.Null())
			}
			return goja.Undefined()
		})
	}
	set(m, "rmSync", delSync("rmSync"))
	set(m, "rmdirSync", delSync("rmdirSync"))
	set(m, "unlinkSync", delSync("unlinkSync"))
	set(m, "rm", delAsync("rm"))
	set(m, "rmdir", delAsync("rmdir"))
	set(m, "unlink", delAsync("unlink"))
	set(m, "chmodSync", r.logged(trace.CatFS, "chmodSync", nil))
	set(m, "renameSync", r.logged(trace.CatFS, "renameSync", nil))
	// copyFileSync(src,dst): copy the (bait) source content to the destination in the
	// vfs, so a credential staged via copy-then-read-then-exfil is taint-trackable.
	copyFile := func(op string) goja.Value {
		return r.fn(func(call goja.FunctionCall) goja.Value {
			src, dst := argStr(call.Argument(0)), argStr(call.Argument(1))
			r.tr.Record(trace.CatFS, op, src, dst)
			if content, notExist := r.readFake(src); !notExist {
				r.vfsWrite(dst, content, false)
			}
			if cb, ok := r.lastCallback(call); ok {
				r.invoke(cb, goja.Null())
			}
			return goja.Undefined()
		})
	}
	set(m, "copyFileSync", copyFile("copyFileSync"))
	set(m, "copyFile", copyFile("copyFile"))
	set(m, "cpSync", copyFile("cpSync"))
	// symlink/link(target,linkPath): reading through the link reads the TARGET, so
	// record the target as accessed and make the link read back the target's (bait)
	// content - defeats the "symlink a credential into the package, then read the
	// link" path-escape evasion.
	symlink := func(op string) goja.Value {
		return r.fn(func(call goja.FunctionCall) goja.Value {
			target, link := argStr(call.Argument(0)), argStr(call.Argument(1))
			r.tr.Record(trace.CatFS, op, target, link)
			r.tr.AddPath(target)
			if content, notExist := r.readFake(target); !notExist {
				r.vfsWrite(link, content, false)
			}
			if cb, ok := r.lastCallback(call); ok {
				r.invoke(cb, goja.Null())
			}
			return goja.Undefined()
		})
	}
	set(m, "symlinkSync", symlink("symlinkSync"))
	set(m, "linkSync", symlink("linkSync"))
	set(m, "symlink", symlink("symlink"))
	set(m, "link", symlink("link"))

	statObj := func() goja.Value {
		s := r.obj()
		set(s, "isDirectory", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(false) }))
		set(s, "isFile", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(true) }))
		set(s, "isSymbolicLink", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(false) }))
		set(s, "size", 2048) // non-zero - a zero-byte stat is a sandbox tell
		set(s, "mode", 0o644)
		set(s, "mtime", r.vm.ToValue(0))
		return s
	}
	set(m, "statSync", r.logged(trace.CatFS, "statSync", statObj))
	set(m, "lstatSync", r.logged(trace.CatFS, "lstatSync", statObj))

	// realpath resolves to the input path in our virtual FS. Node exposes a
	// `.native` variant on both the sync and async forms (fs.realpathSync.native);
	// TypeScript's bundled compiler reads `fs.realpathSync.native` directly, so a
	// missing .native there throws "Cannot read property 'native' of undefined"
	// and aborts the whole module. Attach it to keep such code running.
	realpathSync := func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "realpathSync", p)
		return r.vm.ToValue(p)
	}
	rpSync := r.fn(realpathSync)
	set(rpSync.ToObject(r.vm), "native", r.fn(realpathSync))
	set(m, "realpathSync", rpSync)
	realpath := func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "realpath", p)
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null(), r.vm.ToValue(p))
		}
		return goja.Undefined()
	}
	rp := r.fn(realpath)
	set(rp.ToObject(r.vm), "native", r.fn(realpath))
	set(m, "realpath", rp)

	// createReadStream is a file READ: record the path (like readFileSync) and
	// deliver the file's content through 'data'/'end' so a sample that streams a
	// credential file and exfiltrates it on those events runs instead of dangling.
	set(m, "createReadStream", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "createReadStream", p)
		r.tr.AddPath(p)
		rs := r.newEmitter().ToObject(r.vm)
		set(rs, "pipe", r.fn(func(w goja.FunctionCall) goja.Value { return w.Argument(0) }))
		set(rs, "setEncoding", r.fn(func(goja.FunctionCall) goja.Value { return rs }))
		set(rs, "close", r.fn(func(goja.FunctionCall) goja.Value { return rs }))
		set(rs, "destroy", r.fn(func(goja.FunctionCall) goja.Value { return rs }))
		if content, notExist := r.readFake(p); notExist {
			r.emitLater(rs, "error", r.nodeError("ENOENT", "open", p))
		} else {
			r.emitLater(rs, "open")
			if content != "" {
				r.emitLater(rs, "data", r.makeBuffer([]byte(content)))
			}
			r.emitLater(rs, "end")
			r.emitLater(rs, "close")
		}
		return rs
	}))
	// createWriteStream is a file WRITE: record the dropped path and fire the
	// open/finish lifecycle so a write-then-callback flow continues.
	set(m, "createWriteStream", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		if !r.exploreQuiet {
			r.tr.Record(trace.CatFS, "createWriteStream", p)
			r.tr.AddDropped(p)
		}
		ws := r.newEmitter().ToObject(r.vm)
		set(ws, "write", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(true) }))
		set(ws, "end", r.fn(func(goja.FunctionCall) goja.Value {
			r.emitLater(ws, "finish")
			r.emitLater(ws, "close")
			return goja.Undefined()
		}))
		set(ws, "destroy", r.fn(func(goja.FunctionCall) goja.Value { return ws }))
		r.emitLater(ws, "open")
		r.emitLater(ws, "ready")
		return ws
	}))

	// ---- fd-based I/O ----
	// A dropper can open a file then writeSync(fd, payload) instead of
	// writeFileSync; without these openSync throws (aborting the dropper) and the
	// write is never captured. Map fds to paths so fd writes/reads route through
	// the vfs and surface as the same IOCs as the path-based calls.
	flagIsWrite := func(v goja.Value) bool {
		if goja.IsUndefined(v) || goja.IsNull(v) {
			return false
		}
		// numeric flags: O_WRONLY(1)/O_RDWR(2)/O_CREAT/O_APPEND all have low bits set;
		// treat anything but a bare O_RDONLY(0) as potentially writing.
		if isNum := v.ExportType(); isNum != nil && (isNum.Kind().String() == "int64" || isNum.Kind().String() == "float64") {
			return v.ToInteger() != 0
		}
		f := strings.ToLower(argStr(v))
		return strings.ContainsAny(f, "wa") || strings.Contains(f, "+")
	}
	openSync := func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "openSync", p)
		fd := r.nextFd
		r.nextFd++
		r.fdPaths[fd] = p
		if flagIsWrite(call.Argument(1)) {
			if !r.exploreQuiet {
				r.tr.AddDropped(p)
			}
		} else {
			r.tr.AddPath(p)
		}
		return r.vm.ToValue(fd)
	}
	set(m, "openSync", r.fn(openSync))
	set(m, "open", r.fn(func(call goja.FunctionCall) goja.Value {
		fd := openSync(call)
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null(), fd)
		}
		return goja.Undefined()
	}))
	set(m, "closeSync", r.fn(func(call goja.FunctionCall) goja.Value {
		delete(r.fdPaths, call.Argument(0).ToInteger())
		return goja.Undefined()
	}))
	set(m, "close", r.fn(func(call goja.FunctionCall) goja.Value {
		delete(r.fdPaths, call.Argument(0).ToInteger())
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null())
		}
		return goja.Undefined()
	}))
	// writeSync(fd, buffer|string[, ...]) - record the payload against the fd's path
	// exactly like writeFileSync so a dropped/exfil'd value is captured.
	writeFd := func(call goja.FunctionCall) {
		fd := call.Argument(0).ToInteger()
		p := r.fdPaths[fd]
		if p == "" {
			p = "<fd:" + strconv.FormatInt(fd, 10) + ">"
		}
		data := string(r.valueBytes(call.Argument(1), "utf8"))
		if !r.exploreQuiet {
			r.tr.Record(trace.CatFS, "writeSync", p, data)
			r.tr.AddDropped(p)
		}
		r.vfsWrite(p, data, true)
	}
	set(m, "writeSync", r.fn(func(call goja.FunctionCall) goja.Value {
		writeFd(call)
		return r.vm.ToValue(len(r.valueBytes(call.Argument(1), "utf8")))
	}))
	set(m, "write", r.fn(func(call goja.FunctionCall) goja.Value {
		writeFd(call)
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null(), r.vm.ToValue(0))
		}
		return goja.Undefined()
	}))
	// readSync(fd, buffer, offset, length, position) - copy the fd path's (bait)
	// content into the supplied buffer and return the byte count, so a
	// read-credential-via-fd then exfil flow gets real bytes instead of zeros.
	set(m, "readSync", r.fn(func(call goja.FunctionCall) goja.Value {
		fd := call.Argument(0).ToInteger()
		content, notExist := r.readFake(r.fdPaths[fd])
		if notExist {
			return r.vm.ToValue(0)
		}
		n := r.fillBuffer(call.Argument(1), []byte(content), call.Argument(2), call.Argument(3))
		return r.vm.ToValue(n)
	}))
	set(m, "fstatSync", r.logged(trace.CatFS, "fstatSync", statObj))
	// accessSync probes existence/permissions: deny sandbox artifacts the same way
	// existsSync does (throwing ENOENT), so an access('/.dockerenv') check that a
	// real box fails also fails here instead of betraying the analysis environment.
	set(m, "accessSync", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "accessSync", p)
		if !r.pathExists(p) {
			panic(r.nodeError("ENOENT", "access", p))
		}
		return goja.Undefined()
	}))
	set(m, "access", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "access", p)
		if cb, ok := r.lastCallback(call); ok {
			if !r.pathExists(p) {
				r.invoke(cb, r.nodeError("ENOENT", "access", p))
			} else {
				r.invoke(cb, goja.Null())
			}
		}
		return goja.Undefined()
	}))
	// readlinkSync resolves to the path itself in our virtual FS (no symlink escape).
	set(m, "readlinkSync", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "readlinkSync", p)
		return r.vm.ToValue(p)
	}))

	set(m, "constants", r.obj())
	set(m, "promises", r.modFSPromises())
	return m
}

// fillBuffer copies src into a goja Uint8Array/Buffer at the given offset, up to
// length bytes, and returns the number copied. Used by fs.readSync to deliver
// real (bait) bytes into a caller-supplied buffer.
func (r *Runtime) fillBuffer(bufV goja.Value, src []byte, offV, lenV goja.Value) int {
	o := bufV.ToObject(r.vm)
	if o == nil {
		return 0
	}
	cap := int(o.Get("length").ToInteger())
	off := 0
	if !goja.IsUndefined(offV) && !goja.IsNull(offV) {
		off = int(offV.ToInteger())
	}
	n := len(src)
	if !goja.IsUndefined(lenV) && !goja.IsNull(lenV) {
		if l := int(lenV.ToInteger()); l >= 0 && l < n {
			n = l
		}
	}
	written := 0
	for i := 0; i < n && off+i < cap; i++ {
		if err := o.Set(strconv.Itoa(off+i), int(src[i])); err != nil {
			break
		}
		written++
	}
	return written
}

func (r *Runtime) modFSPromises() goja.Value {
	m := r.obj()
	set(m, "readFile", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "promises.readFile", p)
		r.tr.AddPath(p)
		content, notExist := r.readFake(p)
		if notExist {
			return r.rejectedPromise(r.nodeError("ENOENT", "open", p))
		}
		return r.resolvedPromise(r.vm.ToValue(content))
	}))
	set(m, "writeFile", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		if !r.exploreQuiet {
			r.tr.Record(trace.CatFS, "promises.writeFile", p, argStr(call.Argument(1)))
			r.tr.AddDropped(p)
		}
		return r.resolvedPromise(goja.Undefined())
	}))
	set(m, "readdir", r.fn(func(call goja.FunctionCall) goja.Value {
		p := argStr(call.Argument(0))
		r.tr.Record(trace.CatFS, "promises.readdir", p)
		return r.resolvedPromise(r.vm.NewArray(r.fakeDirListing(p)...))
	}))
	set(m, "mkdtemp", r.fn(func(call goja.FunctionCall) goja.Value {
		prefix := argStr(call.Argument(0))
		b := make([]byte, 3)
		_, _ = rand.Read(b)
		p := prefix + hex.EncodeToString(b)
		r.tr.Record(trace.CatFS, "promises.mkdtemp", p)
		return r.resolvedPromise(r.vm.ToValue(p))
	}))
	for _, op := range []string{"mkdir", "rm", "unlink", "stat", "chmod", "copyFile", "rename"} {
		o := op
		set(m, o, r.fn(func(call goja.FunctionCall) goja.Value {
			p := argStr(call.Argument(0))
			if o == "rm" || o == "unlink" {
				r.vfsDelete(p)
			}
			// Skip recording while the ForceExecute sweep fuzzes this library's
			// functions - otherwise a benign file utility (fs-extra, rimraf) reads
			// as "deletes N files" from synthetic-arg calls. Use displayArgs so an
			// options object renders as JSON, not "[object Object]".
			if !r.exploreQuiet {
				r.tr.Record(trace.CatFS, "promises."+o, r.displayArgs(call)...)
				if o == "rm" || o == "unlink" {
					r.tr.AddDeleted(p)
				}
			}
			return r.resolvedPromise(goja.Undefined())
		}))
	}
	return m
}

// ---- child_process ----

// fullCommandLine reconstructs the command a child_process call runs, for the
// Commands IOC the signatures scan. arg0 is the binary/command; if arg1 is an
// args ARRAY (execFile/spawn/spawnSync/fork), its elements are appended so a
// payload passed as `['-c', 'curl … | sh']` is visible, not just the interpreter.
func fullCommandLine(r *Runtime, call goja.FunctionCall) string {
	bin := argStr(call.Argument(0))
	a1 := call.Argument(1)
	if a1 == nil || goja.IsUndefined(a1) || goja.IsNull(a1) {
		return bin
	}
	obj := a1.ToObject(r.vm)
	if obj == nil || obj.ClassName() != "Array" {
		return bin // arg1 is an options object or callback, not args
	}
	parts := []string{bin}
	n := int(obj.Get("length").ToInteger())
	for i := 0; i < n; i++ {
		parts = append(parts, argStr(obj.Get(strconv.Itoa(i))))
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

// isNodeInterp reports whether a spawned binary is a JS interpreter scbox bridges
// into goja (so a child process running JS is actually executed, not faked).
func isNodeInterp(bin string) bool {
	switch strings.ToLower(filepath.Base(strings.TrimSpace(bin))) {
	case "node", "nodejs", "bun", "deno", "ts-node", "tsx", "ts-node-esm", "swc-node":
		return true
	}
	return false
}

// childArgvArray returns the args array of a child_process call (arg1), or nil if
// arg1 isn't an array (it's options or a callback).
func childArgvArray(r *Runtime, call goja.FunctionCall) []string {
	a1 := call.Argument(1)
	if a1 == nil || goja.IsUndefined(a1) || goja.IsNull(a1) {
		return nil
	}
	o := a1.ToObject(r.vm)
	if o == nil || o.ClassName() != "Array" {
		return nil
	}
	n := int(o.Get("length").ToInteger())
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, argStr(o.Get(strconv.Itoa(i))))
	}
	return out
}

// bridgeNodeChild detonates a child_process invocation of `node <script> [args]`
// (or `node -e <code>`) INSIDE the sandbox, with process.argv set to the child's,
// instead of faking the child. This closes the dominant DPRK npm evasion: the
// payload is run in a detached child node process - spawn('node',[self,'--bg'])
// (self re-exec) or spawn('node',['lib/caller.js', json]) (runner stub) - which a
// faked spawn never executes, leaving the analyzer to see only a benign wrapper.
// bin is the spawned binary, args its argument array. Returns true if it bridged.
func (r *Runtime) bridgeNodeChild(bin string, args []string, dir string) bool {
	if !isNodeInterp(bin) || len(args) == 0 {
		return false
	}
	if dir == "" {
		dir = r.cfg.VirtualBase
	}
	if r.bridgeDepth >= 6 || r.stopped() {
		return true // matched, but stop re-entering (runaway re-exec guard)
	}
	r.bridgeDepth++
	defer func() {
		r.bridgeDepth--
		_ = recover()
	}()

	// Locate `-e <code>` or the first non-flag token (the script path).
	evalCode, scriptIdx := "", -1
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-e" || a == "--eval" || a == "-p" || a == "--print" {
			if i+1 < len(args) {
				evalCode = args[i+1]
			}
			break
		}
		if strings.HasPrefix(a, "-") {
			continue // interpreter flag (e.g. --experimental-modules)
		}
		scriptIdx = i
		break
	}

	// Resolve the script to an ABSOLUTE virtual path. The child's process.argv must
	// carry that absolute path (not the raw relative arg): loaders self-reference
	// via path.resolve(process.argv[1]), and the sandbox's path.resolve does not
	// rebase a relative path onto the virtual cwd - so a relative argv[1] would
	// resolve to the wrong file and the payload would never load.
	argvList := append([]string(nil), args...)
	scriptAbs := ""
	if scriptIdx >= 0 {
		scriptAbs = args[scriptIdx]
		if !filepath.IsAbs(scriptAbs) {
			scriptAbs = filepath.Join(dir, scriptAbs)
		}
		argvList[scriptIdx] = scriptAbs
	}

	// process.argv for the child = [node, ...args]; restore afterward.
	if po := r.procObj(); po != nil {
		execPath := r.profile.Homedir + "/.nvm/versions/node/v20.11.0/bin/node"
		argv := make([]interface{}, 0, len(argvList)+1)
		argv = append(argv, execPath)
		for _, a := range argvList {
			argv = append(argv, a)
		}
		saved := po.Get("argv")
		_ = po.Set("argv", r.vm.NewArray(argv...))
		defer func() { _ = po.Set("argv", saved) }()
	}

	if evalCode != "" {
		r.RunString("child-eval", evalCode)
		return true
	}
	if scriptAbs != "" {
		// Run it FRESH: a child node process is a new interpreter, so the script's
		// top-level code must execute even if it was already require()'d (e.g. a
		// self-re-exec spawn('node',[process.argv[1],'--bg']) where the script is
		// the already-loaded entry - cached exports would skip the --bg payload).
		delete(r.ld.cache, scriptAbs)
		r.RunModuleFile(scriptAbs)
		return true
	}
	return true
}

// procObj returns the live process object (for temporarily overriding argv).
func (r *Runtime) procObj() *goja.Object {
	v := r.vm.Get("process")
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}
	return v.ToObject(r.vm)
}

func (r *Runtime) modChildProcess() goja.Value {
	m := r.obj()

	logCmd := func(op string, call goja.FunctionCall) {
		// displayArgs (not argStrs) so an options object renders as JSON, not the
		// useless "[object Object]" trailing the command in the trace.
		r.tr.Record(trace.CatProc, op, r.displayArgs(call)...)
		// AddCommand must record the FULL command line. For exec/execSync arg0 is the
		// whole command. For execFile/spawn/spawnSync/fork the payload lives in the
		// args ARRAY (arg1) - e.g. execFile('/bin/sh', ['-c','curl … | sh']) - so join
		// arg0 with the array elements; otherwise the command signatures only ever see
		// the bare interpreter ("/bin/sh") and miss the payload entirely.
		r.tr.AddCommand(fullCommandLine(r, call))
	}

	set(m, "exec", r.fn(func(call goja.FunctionCall) goja.Value {
		logCmd("exec", call)
		out := commandOutput(r, argStr(call.Argument(0)))
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null(), r.vm.ToValue(out), r.vm.ToValue(""))
		}
		return r.newChild(out)
	}))
	set(m, "execFile", r.fn(func(call goja.FunctionCall) goja.Value {
		logCmd("execFile", call)
		r.bridgeNodeChild(argStr(call.Argument(0)), childArgvArray(r, call), r.cfg.VirtualBase)
		out := commandOutput(r, strings.TrimSpace(strings.Join(argStrs(call), " ")))
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null(), r.vm.ToValue(out), r.vm.ToValue(""))
		}
		return r.newChild(out)
	}))
	set(m, "execSync", r.fn(func(call goja.FunctionCall) goja.Value {
		logCmd("execSync", call)
		return r.makeBuffer([]byte(commandOutput(r, argStr(call.Argument(0)))))
	}))
	set(m, "execFileSync", r.fn(func(call goja.FunctionCall) goja.Value {
		logCmd("execFileSync", call)
		r.bridgeNodeChild(argStr(call.Argument(0)), childArgvArray(r, call), r.cfg.VirtualBase)
		return r.makeBuffer([]byte(commandOutput(r, strings.TrimSpace(strings.Join(argStrs(call), " ")))))
	}))
	set(m, "spawn", r.fn(func(call goja.FunctionCall) goja.Value {
		logCmd("spawn", call)
		r.bridgeNodeChild(argStr(call.Argument(0)), childArgvArray(r, call), r.cfg.VirtualBase)
		return r.newChild(commandOutput(r, strings.TrimSpace(strings.Join(argStrs(call), " "))))
	}))
	set(m, "fork", r.fn(func(call goja.FunctionCall) goja.Value {
		logCmd("fork", call)
		// fork(modulePath) runs a Node module in a child process - detonate it so a
		// dropped payload (`fs.writeFileSync('/tmp/w.js', …); fork('/tmp/w.js')`)
		// actually executes and is analyzed, instead of vanishing into a no-op child.
		if p := argStr(call.Argument(0)); p != "" {
			r.forkModule(p)
		}
		return r.newChild("")
	}))
	set(m, "spawnSync", r.fn(func(call goja.FunctionCall) goja.Value {
		logCmd("spawnSync", call)
		r.bridgeNodeChild(argStr(call.Argument(0)), childArgvArray(r, call), r.cfg.VirtualBase)
		res := r.obj()
		set(res, "status", 0)
		set(res, "stdout", r.makeBuffer([]byte("")))
		set(res, "stderr", r.makeBuffer([]byte("")))
		set(res, "pid", 4242)
		return res
	}))
	return m
}

// newChild builds a fake ChildProcess. out is the command's simulated stdout,
// delivered through the stdout stream's 'data' event so a sample that reads a
// spawned command's output and exfiltrates it (recon-and-exfil) actually runs
// that handler. The child then emits 'exit'/'close' so completion handlers fire.
func (r *Runtime) newChild(out string) goja.Value {
	c := r.newEmitter().ToObject(r.vm)
	set(c, "pid", 4242)
	stdout := r.newEmitter().ToObject(r.vm)
	stderr := r.newEmitter().ToObject(r.vm)
	for _, s := range []*goja.Object{stdout, stderr} {
		st := s
		set(st, "pipe", r.fn(func(w goja.FunctionCall) goja.Value { return w.Argument(0) }))
		set(st, "setEncoding", r.fn(func(goja.FunctionCall) goja.Value { return st }))
	}
	set(c, "stdout", stdout)
	set(c, "stderr", stderr)
	stdin := r.obj()
	set(stdin, "write", r.logged(trace.CatProc, "stdin.write", nil))
	set(stdin, "end", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(c, "stdin", stdin)
	set(c, "kill", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(true) }))
	set(c, "ref", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(c, "unref", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	// Deliver stdout, then drain and signal exit - in enqueue (= fire) order so a
	// data→end→exit handler chain runs as it would on a real machine.
	if out != "" {
		r.emitLater(stdout, "data", r.makeBuffer([]byte(out)))
	}
	r.emitLater(stdout, "end")
	r.emitLater(c, "exit", r.vm.ToValue(0), goja.Null())
	r.emitLater(c, "close", r.vm.ToValue(0), goja.Null())
	return c
}

// ---- http / https ----

func (r *Runtime) modHTTP(scheme string) goja.Value {
	m := r.obj()
	request := func(call goja.FunctionCall) goja.Value {
		target := r.describeRequestTarget(scheme, call)
		r.tr.Record(trace.CatNet, scheme+".request", target)
		r.recordUnixSocket(call.Argument(0))
		var cb goja.Callable
		for _, a := range call.Arguments {
			if f, ok := goja.AssertFunction(a); ok {
				cb = f
			}
		}
		return r.newClientRequest(cb)
	}
	set(m, "request", r.fn(request))
	set(m, "get", r.fn(func(call goja.FunctionCall) goja.Value {
		target := r.describeRequestTarget(scheme, call)
		r.tr.Record(trace.CatNet, scheme+".get", target)
		r.recordUnixSocket(call.Argument(0))
		var cb goja.Callable
		for _, a := range call.Arguments {
			if f, ok := goja.AssertFunction(a); ok {
				cb = f
			}
		}
		req := r.newClientRequest(cb)
		// get() auto-ends the request, firing the response.
		if end, ok := goja.AssertFunction(req.ToObject(r.vm).Get("end")); ok {
			r.invoke(end, goja.Undefined())
		}
		return req
	}))
	set(m, "createServer", r.logged(trace.CatNet, scheme+".createServer", func() goja.Value {
		s := r.newEmitter().ToObject(r.vm)
		set(s, "listen", r.fn(func(call goja.FunctionCall) goja.Value {
			if cb, ok := r.lastCallback(call); ok {
				r.invoke(cb)
			}
			return s
		}))
		set(s, "close", r.fn(func(goja.FunctionCall) goja.Value { return s }))
		return s
	}))
	set(m, "Agent", r.fn(func(goja.FunctionCall) goja.Value { return r.obj() }))
	set(m, "globalAgent", r.obj())

	// Server / IncomingMessage / ServerResponse / ClientRequest constructors.
	// Frameworks extend their prototypes (express does
	// `Object.create(http.IncomingMessage.prototype)` in request.js/response.js),
	// so these need a real `.prototype` object - a Go-backed function value has
	// none, which throws "Object prototype may only be an Object or null:
	// undefined". Define them in JS so each gets a genuine prototype.
	ctors, err := r.vm.RunString(`(function(){
      function Server(){}
      function IncomingMessage(){}
      function ServerResponse(){}
      function ClientRequest(){}
      function OutgoingMessage(){}
      IncomingMessage.prototype = Object.create({});
      ServerResponse.prototype = Object.create(OutgoingMessage.prototype);
      return { Server: Server, IncomingMessage: IncomingMessage, ServerResponse: ServerResponse, ClientRequest: ClientRequest, OutgoingMessage: OutgoingMessage };
    })()`)
	if err == nil {
		if co := ctors.ToObject(r.vm); co != nil {
			for _, name := range []string{"Server", "IncomingMessage", "ServerResponse", "ClientRequest", "OutgoingMessage"} {
				set(m, name, co.Get(name))
			}
		}
	}

	// METHODS / STATUS_CODES are real exports of Node's http module that packages
	// read at import time - e.g. express/router do `const { METHODS } =
	// require('http'); METHODS.map(...)`, so a missing METHODS throws "Cannot read
	// property 'map' of undefined" and aborts the module. Provide Node's values.
	methods := []any{
		"ACL", "BIND", "CHECKOUT", "CONNECT", "COPY", "DELETE", "GET", "HEAD",
		"LINK", "LOCK", "M-SEARCH", "MERGE", "MKACTIVITY", "MKCALENDAR", "MKCOL",
		"MOVE", "NOTIFY", "OPTIONS", "PATCH", "POST", "PROPFIND", "PROPPATCH",
		"PURGE", "PUT", "QUERY", "REBIND", "REPORT", "SEARCH", "SOURCE", "SUBSCRIBE",
		"TRACE", "UNBIND", "UNLINK", "UNLOCK", "UNSUBSCRIBE",
	}
	set(m, "METHODS", r.vm.NewArray(methods...))
	statusCodes := map[string]string{
		"100": "Continue", "101": "Switching Protocols", "102": "Processing",
		"200": "OK", "201": "Created", "202": "Accepted", "204": "No Content",
		"301": "Moved Permanently", "302": "Found", "304": "Not Modified",
		"307": "Temporary Redirect", "308": "Permanent Redirect",
		"400": "Bad Request", "401": "Unauthorized", "403": "Forbidden",
		"404": "Not Found", "405": "Method Not Allowed", "409": "Conflict",
		"410": "Gone", "418": "I'm a Teapot", "429": "Too Many Requests",
		"500": "Internal Server Error", "501": "Not Implemented",
		"502": "Bad Gateway", "503": "Service Unavailable", "504": "Gateway Timeout",
	}
	sc := r.obj()
	for code, text := range statusCodes {
		set(sc, code, text)
	}
	set(m, "STATUS_CODES", sc)
	return m
}

// describeRequestTarget renders a loggable URL from a string or options object.
// recordUnixSocket surfaces an http request made over a Unix domain socket
// (`http.request({ socketPath: '/var/run/docker.sock', … })`) as a path access, so
// the Docker-daemon / orchestrator socket abuse (container escape, lateral
// movement) is visible to the sensitive/infostealer-path detectors.
func (r *Runtime) recordUnixSocket(a0 goja.Value) {
	if a0 == nil || goja.IsUndefined(a0) || goja.IsNull(a0) {
		return
	}
	o := a0.ToObject(r.vm)
	if o == nil {
		return
	}
	if sp := getStr(o, "socketPath"); sp != "" {
		r.tr.Record(trace.CatFS, "unix-socket", sp)
		r.tr.AddPath(sp)
	}
}

func (r *Runtime) describeRequestTarget(scheme string, call goja.FunctionCall) string {
	a0 := call.Argument(0)
	if a0.ExportType() != nil && a0.ExportType().Kind().String() == "string" {
		return a0.String()
	}
	if o := a0.ToObject(r.vm); o != nil {
		host := getStr(o, "hostname")
		if host == "" {
			host = getStr(o, "host")
		}
		port := getStr(o, "port")
		p := getStr(o, "path")
		if host != "" {
			u := scheme + "://" + host
			if port != "" {
				u += ":" + port
			}
			return u + p
		}
		if href := getStr(o, "href"); href != "" {
			return href
		}
	}
	return a0.String()
}

func (r *Runtime) newClientRequest(cb goja.Callable) goja.Value {
	req := r.newEmitter().ToObject(r.vm)
	respHandlers := []goja.Callable{}
	// Capture response handlers registered via on('response', ...).
	set(req, "on", r.fn(func(call goja.FunctionCall) goja.Value {
		ev := argStr(call.Argument(0))
		if h, ok := goja.AssertFunction(call.Argument(1)); ok && ev == "response" {
			respHandlers = append(respHandlers, h)
		}
		return req
	}))
	set(req, "write", r.fn(func(call goja.FunctionCall) goja.Value {
		d := argStr(call.Argument(0))
		r.tr.Record(trace.CatNet, "request.write", d)
		r.tr.AddPayload(d)
		return r.vm.ToValue(true)
	}))
	set(req, "setHeader", r.fn(func(call goja.FunctionCall) goja.Value {
		name, val := argStr(call.Argument(0)), argStr(call.Argument(1))
		r.tr.Record(trace.CatNet, "request.setHeader", name, val)
		r.tr.AddHeader(name + ": " + val)
		return goja.Undefined()
	}))
	set(req, "end", r.fn(func(call goja.FunctionCall) goja.Value {
		if b := argStr(call.Argument(0)); b != "" {
			r.tr.Record(trace.CatNet, "request.end", b)
			r.tr.AddPayload(b)
		}
		res := r.newNetResponse()
		for _, h := range respHandlers {
			r.invoke(h, res)
		}
		if cb != nil {
			r.invoke(cb, res)
		}
		return goja.Undefined()
	}))
	set(req, "abort", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(req, "destroy", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	return req
}

func (r *Runtime) newNetResponse() goja.Value {
	res := r.obj()
	set(res, "statusCode", 200)
	set(res, "statusMessage", "OK")
	set(res, "headers", r.obj())
	set(res, "setEncoding", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(res, "resume", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(res, "pipe", r.fn(func(call goja.FunctionCall) goja.Value { return call.Argument(0) }))
	// Deliver the fetched-payload marker on 'data' (before 'end'/'close' fire), so a
	// download-and-execute chain that buffers the response and then eval/exec's it
	// (`res.on('data',d=>s+=d); res.on('end',()=>eval(s))` or `…cp.exec(s)`) feeds
	// the marker to the eval/proc hooks and is detected. A benign fetch-then-parse
	// gets the marker too but never reaches an exec sink, so it stays clean.
	set(res, "on", r.fn(func(call goja.FunctionCall) goja.Value {
		ev := argStr(call.Argument(0))
		if h, ok := goja.AssertFunction(call.Argument(1)); ok {
			switch ev {
			case "data":
				r.invoke(h, r.makeBuffer([]byte(fetchedJSON)))
			case "end", "close":
				r.invoke(h)
			}
		}
		return res
	}))
	return res
}

// ---- net / dns ----

// newSocket builds the faked socket stream shared by net.connect and inbound
// server connections: write records the exfil payload, and pipe()/the chainable
// no-op setters let a backdoor wire the socket to a shell (`socket.pipe(sh.stdin)`)
// without throwing before the spawn is observed.
func (r *Runtime) newSocket() *goja.Object {
	sock := r.newEmitter().ToObject(r.vm)
	set(sock, "write", r.fn(func(c goja.FunctionCall) goja.Value {
		d := argStr(c.Argument(0))
		r.tr.Record(trace.CatNet, "socket.write", d)
		r.tr.AddPayload(d)
		return r.vm.ToValue(true)
	}))
	set(sock, "end", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(sock, "destroy", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(sock, "pipe", r.fn(func(c goja.FunctionCall) goja.Value { return c.Argument(0) }))
	set(sock, "setEncoding", r.fn(func(goja.FunctionCall) goja.Value { return sock }))
	set(sock, "setKeepAlive", r.fn(func(goja.FunctionCall) goja.Value { return sock }))
	set(sock, "setNoDelay", r.fn(func(goja.FunctionCall) goja.Value { return sock }))
	set(sock, "setTimeout", r.fn(func(goja.FunctionCall) goja.Value { return sock }))
	set(sock, "ref", r.fn(func(goja.FunctionCall) goja.Value { return sock }))
	set(sock, "unref", r.fn(func(goja.FunctionCall) goja.Value { return sock }))
	return sock
}

func (r *Runtime) modNet() goja.Value {
	m := r.obj()
	connect := func(call goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatNet, "net.connect", argStrs(call)...)
		sock := r.newSocket()
		// Simulate the connection succeeding so a payload gated on it actually runs
		// (see fireConnection). 'secureConnect' and 'ready' are emitted alongside
		// 'connect' because this same mock backs tls.connect - a TLS reverse shell
		// waits on 'secureConnect', a plain one on 'connect'. A listener that isn't
		// registered simply makes its emit a no-op, so emitting all three is safe.
		cb, _ := r.lastCallback(call)
		r.fireConnection(sock, cb, "connect", "secureConnect", "ready")
		return sock
	}
	set(m, "connect", r.fn(connect))
	set(m, "createConnection", r.fn(connect))
	set(m, "Socket", r.fn(func(goja.FunctionCall) goja.Value { return connect(goja.FunctionCall{}) }))

	// A TCP server - a bind shell listens and wires each inbound socket to a shell
	// (`net.createServer(s => { sh = spawn('/bin/sh'); s.pipe(sh.stdin) }).listen(p)`).
	// On listen() we deliver one fake inbound connection (to the createServer handler
	// AND any 'connection' listener) so the backdoor's shell wiring runs and is seen.
	mkServer := func(call goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatNet, "net.createServer", argStrs(call)...)
		srv := r.newEmitter().ToObject(r.vm)
		connHandler, _ := r.lastCallback(call) // createServer([opts], connectionListener)
		deliverConn := func() {
			sock := r.newSocket()
			if connHandler != nil {
				r.queueCallback(r.goCallback(func() { r.invoke(connHandler, sock) }))
			}
			r.emitLater(srv, "connection", sock)
		}
		set(srv, "listen", r.fn(func(c goja.FunctionCall) goja.Value {
			r.tr.Record(trace.CatNet, "server.listen", argStrs(c)...)
			deliverConn()
			if cb, ok := r.lastCallback(c); ok {
				r.queueCallback(r.goCallback(func() { r.invoke(cb) }))
			}
			return srv
		}))
		set(srv, "close", r.fn(func(goja.FunctionCall) goja.Value { return srv }))
		set(srv, "address", r.fn(func(goja.FunctionCall) goja.Value {
			a := r.obj()
			set(a, "port", 0)
			set(a, "address", "0.0.0.0")
			return a
		}))
		set(srv, "ref", r.fn(func(goja.FunctionCall) goja.Value { return srv }))
		set(srv, "unref", r.fn(func(goja.FunctionCall) goja.Value { return srv }))
		return srv
	}
	set(m, "createServer", r.fn(mkServer))
	set(m, "Server", r.fn(mkServer))
	return m
}

func (r *Runtime) modDNS() goja.Value {
	m := r.obj()
	lookup := func(call goja.FunctionCall) goja.Value {
		host := argStr(call.Argument(0))
		r.tr.Record(trace.CatNet, "dns.lookup", host)
		r.tr.AddDomain(host)
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null(), r.vm.ToValue("93.184.216.34"), r.vm.ToValue(4))
		}
		return goja.Undefined()
	}
	set(m, "lookup", r.fn(lookup))
	set(m, "resolve", r.fn(func(call goja.FunctionCall) goja.Value {
		host := argStr(call.Argument(0))
		r.tr.Record(trace.CatNet, "dns.resolve", host)
		r.tr.AddDomain(host)
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null(), r.vm.NewArray("93.184.216.34"))
		}
		return goja.Undefined()
	}))
	set(m, "resolve4", m.Get("resolve"))
	for _, op := range []string{"resolveTxt", "resolveMx", "resolveCname", "resolveNs", "reverse"} {
		o := op
		set(m, o, r.fn(func(call goja.FunctionCall) goja.Value {
			host := argStr(call.Argument(0))
			r.tr.Record(trace.CatNet, "dns."+o, host)
			r.tr.AddDomain(host)
			if cb, ok := r.lastCallback(call); ok {
				r.invoke(cb, goja.Null(), r.vm.NewArray())
			}
			return goja.Undefined()
		}))
	}
	// setServers redirects ALL name resolution to the given servers - a DNS hijack /
	// MITM primitive a package has no benign reason to call. Record each server.
	set(m, "setServers", r.fn(func(call goja.FunctionCall) goja.Value {
		// Record auto-scans the args, so the redirect IPs land in the IOC IP set.
		r.tr.Record(trace.CatNet, "dns.setServers", argStrs(call)...)
		return goja.Undefined()
	}))
	set(m, "setDefaultResultOrder", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(m, "getServers", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.NewArray("127.0.0.53") }))
	promises := r.obj()
	set(promises, "lookup", r.fn(func(call goja.FunctionCall) goja.Value {
		host := argStr(call.Argument(0))
		r.tr.Record(trace.CatNet, "dns.promises.lookup", host)
		r.tr.AddDomain(host)
		return r.resolvedPromise(r.vm.ToValue("93.184.216.34"))
	}))
	set(promises, "resolve", r.fn(func(call goja.FunctionCall) goja.Value {
		host := argStr(call.Argument(0))
		r.tr.Record(trace.CatNet, "dns.promises.resolve", host)
		r.tr.AddDomain(host)
		return r.resolvedPromise(r.vm.NewArray("93.184.216.34"))
	}))
	set(m, "promises", promises)
	return m
}

// modDgram fakes UDP sockets - a favorite covert exfil/C2 channel.
func (r *Runtime) modDgram() goja.Value {
	m := r.obj()
	set(m, "createSocket", r.fn(func(call goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatNet, "dgram.createSocket", argStr(call.Argument(0)))
		s := r.newEmitter().ToObject(r.vm)
		set(s, "send", r.fn(func(c goja.FunctionCall) goja.Value {
			// send(msg, [offset, length,] port, address, [cb])
			r.tr.Record(trace.CatNet, "dgram.send", argStrs(c)...)
			r.tr.AddPayload(argStr(c.Argument(0)))
			if cb, ok := r.lastCallback(c); ok {
				r.invoke(cb, goja.Null())
			}
			return goja.Undefined()
		}))
		// bind(port[, address][, cb]) - cb is registered as a one-shot 'listening'
		// listener. Fire it so a UDP C2/exfil channel that waits to bind before
		// sending runs instead of dangling.
		set(s, "bind", r.fn(func(c goja.FunctionCall) goja.Value {
			r.tr.Record(trace.CatNet, "dgram.bind", argStrs(c)...)
			cb, _ := r.lastCallback(c)
			r.fireConnection(s, cb, "listening")
			return s
		}))
		// connect(port[, address][, cb]) - a connected UDP socket; the cb fires on
		// 'connect'.
		set(s, "connect", r.fn(func(c goja.FunctionCall) goja.Value {
			r.tr.Record(trace.CatNet, "dgram.connect", argStrs(c)...)
			cb, _ := r.lastCallback(c)
			r.fireConnection(s, cb, "connect")
			return s
		}))
		set(s, "close", r.fn(func(goja.FunctionCall) goja.Value { return s }))
		set(s, "unref", r.fn(func(goja.FunctionCall) goja.Value { return s }))
		return s
	}))
	return m
}

// modHTTP2 fakes the HTTP/2 client surface.
func (r *Runtime) modHTTP2() goja.Value {
	m := r.obj()
	set(m, "connect", r.fn(func(call goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatNet, "http2.connect", argStr(call.Argument(0)))
		sess := r.newEmitter().ToObject(r.vm)
		set(sess, "request", r.fn(func(c goja.FunctionCall) goja.Value {
			r.tr.Record(trace.CatNet, "http2.request", argStr(c.Argument(0)))
			stream := r.newEmitter().ToObject(r.vm)
			// A request stream is writable: record what's pushed (the exfil body) and
			// fire 'response'/'end' so the caller's completion handler runs.
			set(stream, "write", r.fn(func(w goja.FunctionCall) goja.Value {
				d := argStr(w.Argument(0))
				r.tr.Record(trace.CatNet, "http2.stream.write", d)
				r.tr.AddPayload(d)
				return r.vm.ToValue(true)
			}))
			set(stream, "end", r.fn(func(w goja.FunctionCall) goja.Value {
				if b := argStr(w.Argument(0)); b != "" {
					r.tr.Record(trace.CatNet, "http2.stream.end", b)
					r.tr.AddPayload(b)
				}
				r.fireConnection(stream, nil, "response", "data", "end")
				return goja.Undefined()
			}))
			set(stream, "setEncoding", r.fn(func(goja.FunctionCall) goja.Value { return stream }))
			set(stream, "pipe", r.fn(func(w goja.FunctionCall) goja.Value { return w.Argument(0) }))
			return stream
		}))
		set(sess, "close", r.fn(func(goja.FunctionCall) goja.Value { return sess }))
		// http2.connect(authority[, options][, listener]) - the listener fires on
		// 'connect'. Fire it (and the event) so a session-gated payload runs.
		cb, _ := r.lastCallback(call)
		r.fireConnection(sess, cb, "connect")
		return sess
	}))
	return m
}

// modWorkerThreads fakes worker_threads. A Worker created with `{ eval: true }`
// runs its first argument as code - `new Worker("<payload>", {eval:true})` is a
// common RCE/obfuscation vector that hides the payload off the main module - so we
// record the body as dynamic code and execute it inline so it detonates and is
// scanned. A Worker given a filename is recorded as a module load. The handle is a
// logging EventEmitter (postMessage/terminate are no-ops).
func (r *Runtime) modWorkerThreads() goja.Value {
	m := r.obj()
	// Worker is a constructor (`new Worker(...)`), so it uses goja's native
	// constructor signature rather than a plain function.
	mkWorker := r.vm.ToValue(func(call goja.ConstructorCall) *goja.Object {
		var src string
		if len(call.Arguments) > 0 {
			src = argStr(call.Arguments[0])
		}
		evalMode := false
		if len(call.Arguments) > 1 {
			opts := call.Arguments[1]
			if opts != nil && !goja.IsUndefined(opts) && !goja.IsNull(opts) {
				if o := opts.ToObject(r.vm); o != nil {
					if ev := o.Get("eval"); ev != nil {
						evalMode = ev.ToBoolean()
					}
				}
			}
		}
		switch {
		case evalMode && src != "":
			r.tr.Record(trace.CatEval, "worker.eval", src)
			r.RunString("worker:eval", src) // detonate the worker payload inline
		case src != "":
			r.tr.Record(trace.CatModule, "worker.load", src)
		}
		w := r.newEmitter().ToObject(r.vm)
		set(w, "postMessage", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
		set(w, "terminate", r.fn(func(goja.FunctionCall) goja.Value { return r.resolvedPromise(goja.Undefined()) }))
		set(w, "ref", r.fn(func(goja.FunctionCall) goja.Value { return w }))
		set(w, "unref", r.fn(func(goja.FunctionCall) goja.Value { return w }))
		return w
	})
	set(m, "Worker", mkWorker)
	set(m, "isMainThread", r.vm.ToValue(true))
	set(m, "parentPort", goja.Null())
	set(m, "threadId", r.vm.ToValue(0))
	set(m, "workerData", goja.Undefined())
	set(m, "setEnvironmentData", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(m, "getEnvironmentData", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(m, "markAsUntransferable", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	return m
}

// modInspector fakes the `inspector` module. A package opening a debugger port at
// install/import time is a remote-code-execution backdoor (anyone who connects to
// the inspector can run arbitrary code in the process) - recorded so the verdict
// flags it.
func (r *Runtime) modInspector() goja.Value {
	m := r.obj()
	set(m, "open", r.fn(func(call goja.FunctionCall) goja.Value {
		port, host := argStr(call.Argument(0)), argStr(call.Argument(1))
		r.tr.Record(trace.CatProcess, "inspector.open", port, host)
		return goja.Undefined()
	}))
	set(m, "waitForDebugger", r.fn(func(goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatProcess, "inspector.waitForDebugger")
		return goja.Undefined()
	}))
	set(m, "close", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(m, "url", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(m, "console", r.obj())
	set(m, "Session", r.fn(func(goja.FunctionCall) goja.Value { return r.newEmitter() }))
	return m
}

// ---- zlib ----

// modZlib implements REAL (de)compression. Decompression matters for analysis: a
// loader ships its payload gzip/deflate-compressed and `gunzipSync(buf)+eval` it at
// runtime, so without actually decompressing, the payload is invisible. The
// recovered plaintext is recorded as a decoded blob (scanned by the signatures) and
// returned as a Buffer so the eval that follows runs it. Output is capped to defuse
// decompression bombs.
func (r *Runtime) modZlib() goja.Value {
	const maxOut = 16 << 20 // 16 MiB cap (decompression-bomb guard)
	m := r.obj()
	readAll := func(rd io.Reader) ([]byte, error) { return io.ReadAll(io.LimitReader(rd, maxOut)) }
	gunzip := func(b []byte) ([]byte, error) {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return readAll(zr)
	}
	inflate := func(b []byte) ([]byte, error) {
		zr, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return readAll(zr)
	}
	inflateRaw := func(b []byte) ([]byte, error) {
		fr := flate.NewReader(bytes.NewReader(b))
		defer fr.Close()
		return readAll(fr)
	}
	unzip := func(b []byte) ([]byte, error) {
		if out, err := gunzip(b); err == nil {
			return out, nil
		}
		return inflate(b)
	}
	deflateTo := func(b []byte, mk func(*bytes.Buffer) io.WriteCloser) []byte {
		var w bytes.Buffer
		zw := mk(&w)
		_, _ = zw.Write(b)
		_ = zw.Close()
		return w.Bytes()
	}
	decompress := func(op string, fn func([]byte) ([]byte, error)) goja.Value {
		return r.fn(func(call goja.FunctionCall) goja.Value {
			out, err := fn(r.valueBytes(call.Argument(0), "utf8"))
			if err != nil {
				out = nil
			}
			if len(out) > 0 {
				r.tr.Record(trace.CatEval, "zlib."+op, oneLineN(string(out), 200))
				r.tr.AddDecoded(string(out)) // surface the unpacked payload to the scanners
			}
			if cb, ok := r.lastCallback(call); ok { // async form: cb(err, buf)
				r.invoke(cb, goja.Null(), r.makeBuffer(out))
				return goja.Undefined()
			}
			return r.makeBuffer(out)
		})
	}
	compress := func(fn func([]byte) []byte) goja.Value {
		return r.fn(func(call goja.FunctionCall) goja.Value {
			out := fn(r.valueBytes(call.Argument(0), "utf8"))
			if cb, ok := r.lastCallback(call); ok {
				r.invoke(cb, goja.Null(), r.makeBuffer(out))
				return goja.Undefined()
			}
			return r.makeBuffer(out)
		})
	}
	gzipC := func(b []byte) []byte {
		return deflateTo(b, func(w *bytes.Buffer) io.WriteCloser { return gzip.NewWriter(w) })
	}
	deflateC := func(b []byte) []byte {
		return deflateTo(b, func(w *bytes.Buffer) io.WriteCloser { return zlib.NewWriter(w) })
	}
	deflateRawC := func(b []byte) []byte {
		return deflateTo(b, func(w *bytes.Buffer) io.WriteCloser {
			fw, _ := flate.NewWriter(w, flate.DefaultCompression)
			return fw
		})
	}
	for _, d := range []struct {
		names []string
		fn    func([]byte) ([]byte, error)
		op    string
	}{
		{[]string{"gunzipSync", "gunzip"}, gunzip, "gunzip"},
		{[]string{"unzipSync", "unzip"}, unzip, "unzip"},
		{[]string{"inflateSync", "inflate"}, inflate, "inflate"},
		{[]string{"inflateRawSync", "inflateRaw"}, inflateRaw, "inflateRaw"},
		// Go has no stdlib brotli; pass the bytes through so a brotli-wrapped payload
		// at least isn't a hard stub (best-effort).
		{[]string{"brotliDecompressSync", "brotliDecompress"}, func(b []byte) ([]byte, error) { return b, nil }, "brotli"},
	} {
		v := decompress(d.op, d.fn)
		for _, n := range d.names {
			set(m, n, v)
		}
	}
	for n, fn := range map[string]func([]byte) []byte{
		"gzipSync": gzipC, "gzip": gzipC, "deflateSync": deflateC, "deflate": deflateC,
		"deflateRawSync": deflateRawC, "deflateRaw": deflateRawC,
		"brotliCompressSync": func(b []byte) []byte { return b }, "brotliCompress": func(b []byte) []byte { return b },
	} {
		set(m, n, compress(fn))
	}
	for _, n := range []string{"createGunzip", "createUnzip", "createInflate", "createInflateRaw", "createGzip", "createDeflate", "createBrotliDecompress"} {
		set(m, n, r.fn(func(goja.FunctionCall) goja.Value { return r.newEmitter() }))
	}
	set(m, "constants", r.obj())
	return m
}

// ---- os ----

func (r *Runtime) modOS() goja.Value {
	prof := r.profile
	m := r.obj()
	str := func(op, val string) goja.Value {
		return r.fn(func(goja.FunctionCall) goja.Value {
			r.tr.Record(trace.CatOS, "os."+op)
			return r.vm.ToValue(val)
		})
	}
	set(m, "platform", str("platform", r.cfg.Platform))
	set(m, "arch", str("arch", prof.Arch))
	set(m, "hostname", str("hostname", prof.Hostname))
	set(m, "type", str("type", "Linux"))
	set(m, "release", str("release", "6.12.8-arch1-1"))
	set(m, "version", str("version", "#1 SMP PREEMPT_DYNAMIC Fri, 17 Jan 2025 18:01:36 +0000"))
	set(m, "homedir", str("homedir", prof.Homedir))
	set(m, "tmpdir", str("tmpdir", "/tmp"))
	set(m, "userInfo", r.fn(func(goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatOS, "os.userInfo")
		u := r.obj()
		set(u, "username", prof.Username)
		set(u, "homedir", prof.Homedir)
		set(u, "uid", 1000)
		set(u, "gid", 1000)
		set(u, "shell", "/bin/bash")
		return u
	}))
	// A realistic interface set - empty would itself be a sandbox tell.
	set(m, "networkInterfaces", r.fn(func(goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatOS, "os.networkInterfaces")
		mkIf := func(addr, mac, family string, internal bool) *goja.Object {
			e := r.obj()
			set(e, "address", addr)
			set(e, "netmask", "255.255.255.0")
			set(e, "family", family)
			set(e, "mac", mac)
			set(e, "internal", internal)
			set(e, "cidr", addr+"/24")
			return e
		}
		out := r.obj()
		// Real loopback carries both IPv4 and IPv6; a lone IPv4 entry is a tell.
		set(out, "lo", r.vm.NewArray(
			mkIf("127.0.0.1", "00:00:00:00:00:00", "IPv4", true),
			mkIf("::1", "00:00:00:00:00:00", "IPv6", true)))
		set(out, "eth0", r.vm.NewArray(mkIf(prof.IP, prof.MAC, "IPv4", false)))
		return out
	}))
	set(m, "cpus", r.fn(func(goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatOS, "os.cpus")
		cpus := make([]any, 0, prof.CPU.Threads)
		for i := 0; i < prof.CPU.Threads; i++ {
			c := r.obj()
			set(c, "model", prof.CPU.Model)
			set(c, "speed", 2500)
			times := r.obj()
			set(times, "user", 252020)
			set(times, "nice", 0)
			set(times, "sys", 30340)
			set(times, "idle", 1070356870)
			set(times, "irq", 0)
			set(c, "times", times)
			cpus = append(cpus, c)
		}
		return r.vm.NewArray(cpus...)
	}))
	set(m, "totalmem", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(prof.TotalMem) }))
	set(m, "freemem", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(prof.TotalMem * 6 / 10) }))
	// Advance uptime with the virtual clock so two reads aren't byte-identical (a
	// frozen uptime is a sandbox tell) and stay consistent with /proc/uptime.
	set(m, "uptime", r.fn(func(goja.FunctionCall) goja.Value {
		return r.vm.ToValue(862344 + int64(r.clockOffsetMs/1000))
	}))
	set(m, "loadavg", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.NewArray(0.08, 0.03, 0.01) }))
	set(m, "EOL", "\n")
	return m
}

// ---- path (real, safe) ----

func (r *Runtime) modPath() goja.Value {
	m := r.obj()
	set(m, "join", r.fn(func(call goja.FunctionCall) goja.Value {
		parts := make([]string, 0, len(call.Arguments))
		for _, a := range call.Arguments {
			parts = append(parts, a.String())
		}
		return r.vm.ToValue(path.Join(parts...))
	}))
	set(m, "resolve", r.fn(func(call goja.FunctionCall) goja.Value {
		out := "/"
		for _, a := range call.Arguments {
			out = path.Join(out, a.String())
		}
		return r.vm.ToValue(out)
	}))
	set(m, "normalize", r.fn(func(call goja.FunctionCall) goja.Value { return r.vm.ToValue(path.Clean(call.Argument(0).String())) }))
	set(m, "basename", r.fn(func(call goja.FunctionCall) goja.Value { return r.vm.ToValue(path.Base(call.Argument(0).String())) }))
	set(m, "dirname", r.fn(func(call goja.FunctionCall) goja.Value { return r.vm.ToValue(path.Dir(call.Argument(0).String())) }))
	set(m, "extname", r.fn(func(call goja.FunctionCall) goja.Value { return r.vm.ToValue(path.Ext(call.Argument(0).String())) }))
	set(m, "isAbsolute", r.fn(func(call goja.FunctionCall) goja.Value {
		return r.vm.ToValue(strings.HasPrefix(call.Argument(0).String(), "/"))
	}))
	set(m, "sep", "/")
	set(m, "delimiter", ":")
	set(m, "posix", m)
	return m
}

// ---- crypto (real hashing, faked ciphers) ----

func (r *Runtime) modCrypto() goja.Value {
	m := r.obj()
	set(m, "randomBytes", r.fn(func(call goja.FunctionCall) goja.Value {
		n := int(call.Argument(0).ToInteger())
		if n < 0 || n > 1<<20 {
			n = 0
		}
		b := make([]byte, n)
		_, _ = rand.Read(b)
		r.tr.Record(trace.CatCrypto, "randomBytes", fmt.Sprintf("%d bytes", n))
		buf := r.makeBuffer(b)
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null(), buf)
		}
		return buf
	}))
	set(m, "randomUUID", r.fn(func(goja.FunctionCall) goja.Value {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		return r.vm.ToValue(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
	}))
	set(m, "createHash", r.fn(func(call goja.FunctionCall) goja.Value {
		algo := argStr(call.Argument(0))
		r.tr.Record(trace.CatCrypto, "createHash", algo)
		r.tr.AddCrypto("hash:" + algo)
		return r.newHash(algo)
	}))
	set(m, "createHmac", r.fn(func(call goja.FunctionCall) goja.Value {
		algo := argStr(call.Argument(0))
		r.tr.Record(trace.CatCrypto, "createHmac", algo)
		r.tr.AddCrypto("hmac:" + algo)
		return r.newHash(algo)
	}))
	set(m, "createCipheriv", r.makeCipher("createCipheriv", false))
	set(m, "createDecipheriv", r.makeCipher("createDecipheriv", true))
	set(m, "pbkdf2Sync", r.fn(func(goja.FunctionCall) goja.Value { return r.makeBuffer(make([]byte, 32)) }))

	// RSA / asymmetric - used for the AES-key-wrapping exfil envelopes that
	// modern stealers (e.g. Shai-Hulud) use.
	rsaEnc := func(op string) goja.Value {
		return r.fn(func(call goja.FunctionCall) goja.Value {
			r.tr.Record(trace.CatCrypto, op, argStr(call.Argument(1)))
			r.tr.AddCrypto(op)
			return r.makeBuffer([]byte("encrypted"))
		})
	}
	set(m, "publicEncrypt", rsaEnc("publicEncrypt"))
	set(m, "privateDecrypt", rsaEnc("privateDecrypt"))
	set(m, "privateEncrypt", rsaEnc("privateEncrypt"))
	set(m, "publicDecrypt", rsaEnc("publicDecrypt"))
	set(m, "createPublicKey", r.fn(func(goja.FunctionCall) goja.Value { return r.obj() }))
	set(m, "createPrivateKey", r.fn(func(goja.FunctionCall) goja.Value { return r.obj() }))
	keypair := func() goja.Value {
		o := r.obj()
		set(o, "publicKey", "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----")
		set(o, "privateKey", "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----")
		return o
	}
	set(m, "generateKeyPairSync", r.fn(func(call goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatCrypto, "generateKeyPairSync", argStr(call.Argument(0)))
		return keypair()
	}))
	set(m, "generateKeyPair", r.fn(func(call goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatCrypto, "generateKeyPair", argStr(call.Argument(0)))
		if cb, ok := r.lastCallback(call); ok {
			kp := keypair().ToObject(r.vm)
			r.invoke(cb, goja.Null(), kp.Get("publicKey"), kp.Get("privateKey"))
		}
		return goja.Undefined()
	}))
	set(m, "randomFillSync", r.fn(func(call goja.FunctionCall) goja.Value { return call.Argument(0) }))
	set(m, "constants", r.obj())
	set(m, "webcrypto", r.obj())
	return m
}

// valueBytes extracts raw bytes from a goja value the way Node's crypto APIs do:
// a Buffer/TypedArray yields its bytes; a string is decoded per `enc`
// (hex/base64/latin1, else utf8). Used so real AES key/iv/ciphertext flow through.
func (r *Runtime) valueBytes(v goja.Value, enc string) []byte {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}
	switch b := v.Export().(type) {
	case []byte:
		return b
	case goja.ArrayBuffer:
		return b.Bytes()
	case []any:
		out := make([]byte, len(b))
		for i, e := range b {
			switch n := e.(type) {
			case int64:
				out[i] = byte(n)
			case float64:
				out[i] = byte(int64(n))
			}
		}
		return out
	}
	s := v.String()
	switch strings.ToLower(enc) {
	case "hex":
		if d, err := hex.DecodeString(s); err == nil {
			return d
		}
	case "base64", "base64url":
		if d, err := base64.StdEncoding.DecodeString(s); err == nil {
			return d
		}
		if d, err := base64.RawURLEncoding.DecodeString(s); err == nil {
			return d
		}
	}
	return []byte(s)
}

// encodeOut renders cipher output bytes the way Node does when an output encoding
// is given (hex/base64/utf8/…), otherwise returns a Buffer.
func (r *Runtime) encodeOut(b []byte, enc string) goja.Value {
	switch strings.ToLower(enc) {
	case "hex":
		return r.vm.ToValue(hex.EncodeToString(b))
	case "base64":
		return r.vm.ToValue(base64.StdEncoding.EncodeToString(b))
	case "utf8", "utf-8", "latin1", "binary", "ascii":
		return r.vm.ToValue(string(b))
	case "":
		return r.makeBuffer(b)
	default:
		return r.vm.ToValue(string(b))
	}
}

// makeCipher implements a REAL AES cipher/decipher (createCipheriv /
// createDecipheriv). Faking these (returning empty buffers, as before) was a
// serious blind spot: supply-chain malware routinely ships its payload AES- or
// XOR-encrypted and does `eval(decrypt(blob))` - with a fake decipher the eval
// saw an empty string and the C2 URL/command inside was never decrypted, scanned,
// or scored. We perform the actual decryption (the key + iv are in the sample),
// so the plaintext reaches the eval hook and the IOC scanners. Decrypted output
// is also filed as a decoded blob and rescanned for nested URLs/commands.
func (r *Runtime) makeCipher(op string, decrypt bool) goja.Value {
	return r.fn(func(call goja.FunctionCall) goja.Value {
		algo := strings.ToLower(argStr(call.Argument(0)))
		key := r.valueBytes(call.Argument(1), "utf8")
		iv := r.valueBytes(call.Argument(2), "utf8")
		r.tr.Record(trace.CatCrypto, op, algo)
		r.tr.AddCrypto(op + ":" + algo)

		var inBuf []byte
		var authTag []byte
		returned := 0
		// transform decrypts (or encrypts) the whole accumulated buffer; returns
		// nil if not yet possible (e.g. partial CBC block). On the finalizing call
		// (final()), an encrypt of a CBC stream applies PKCS7 padding the way Node
		// does, so a non-block-aligned plaintext still produces ciphertext.
		transform := func(final bool) []byte {
			// RC4 is a keystream cipher: no block, no IV, and enc==dec. Handle it
			// before the block-cipher path so `eval(rc4_decrypt(blob))` recovers the
			// real plaintext instead of AES garbage.
			if strings.Contains(algo, "rc4") {
				if len(inBuf) == 0 {
					return nil
				}
				c, err := rc4.NewCipher(key)
				if err != nil {
					return nil
				}
				out := make([]byte, len(inBuf))
				c.XORKeyStream(out, inBuf)
				return out
			}
			block, err := newBlockCipher(algo, key)
			if err != nil || (len(inBuf) == 0 && !final) {
				return nil
			}
			switch {
			case strings.Contains(algo, "gcm"):
				aead, err := cipher.NewGCM(block)
				if err != nil || len(iv) == 0 {
					return nil
				}
				if decrypt {
					ct := inBuf
					if len(authTag) > 0 {
						ct = append(append([]byte{}, inBuf...), authTag...)
					}
					if pt, err := aead.Open(nil, iv, ct, nil); err == nil {
						return pt
					}
					return nil
				}
				return aead.Seal(nil, iv, inBuf, nil)
			case strings.Contains(algo, "ctr"):
				out := make([]byte, len(inBuf))
				cipher.NewCTR(block, ivOrZero(iv, block.BlockSize())).XORKeyStream(out, inBuf)
				return out
			case strings.Contains(algo, "cfb"):
				out := make([]byte, len(inBuf))
				if decrypt {
					cipher.NewCFBDecrypter(block, ivOrZero(iv, block.BlockSize())).XORKeyStream(out, inBuf)
				} else {
					cipher.NewCFBEncrypter(block, ivOrZero(iv, block.BlockSize())).XORKeyStream(out, inBuf)
				}
				return out
			default: // cbc (and ecb-ish fallback)
				bs := block.BlockSize()
				data := inBuf
				if !decrypt && final && strings.Contains(algo, "cbc") {
					// PKCS7-pad on the finalizing encrypt call (Node default padding).
					pad := bs - len(data)%bs
					data = append(append([]byte{}, data...), bytes.Repeat([]byte{byte(pad)}, pad)...)
				}
				if len(data) == 0 || len(data)%bs != 0 {
					return nil
				}
				out := make([]byte, len(data))
				if decrypt {
					cipher.NewCBCDecrypter(block, ivOrZero(iv, bs)).CryptBlocks(out, data)
					if !strings.Contains(algo, "cbc") {
						return out
					}
					return pkcs7Strip(out)
				}
				cipher.NewCBCEncrypter(block, ivOrZero(iv, bs)).CryptBlocks(out, data)
				return out
			}
		}
		emit := func(outEnc string, final bool) goja.Value {
			pt := transform(final)
			if pt == nil || len(pt) <= returned {
				return r.encodeOut(nil, outEnc)
			}
			chunk := pt[returned:]
			returned = len(pt)
			if decrypt && len(chunk) >= 4 {
				// Surface the recovered plaintext: file it as a decoded blob (which
				// rescans for embedded URLs/commands) and record it so it shows in
				// the trace and feeds the verdict's deobfuscation signal.
				r.tr.AddDecoded(string(chunk))
				r.tr.Record(trace.CatEval, "decipher-output", string(chunk))
				// Remember the plaintext so the eval hook can flag a decrypt-then-
				// execute loader structurally, independent of the cipher algorithm.
				r.noteDecipherOutput(string(chunk))
			}
			return r.encodeOut(chunk, outEnc)
		}

		c := r.obj()
		set(c, "update", r.fn(func(call goja.FunctionCall) goja.Value {
			inEnc := ""
			if a := call.Argument(1); !goja.IsUndefined(a) {
				inEnc = a.String()
			}
			outEnc := ""
			if a := call.Argument(2); !goja.IsUndefined(a) {
				outEnc = a.String()
			}
			inBuf = append(inBuf, r.valueBytes(call.Argument(0), inEnc)...)
			return emit(outEnc, false)
		}))
		set(c, "final", r.fn(func(call goja.FunctionCall) goja.Value {
			outEnc := ""
			if a := call.Argument(0); !goja.IsUndefined(a) {
				outEnc = a.String()
			}
			return emit(outEnc, true)
		}))
		set(c, "setAutoPadding", r.fn(func(goja.FunctionCall) goja.Value { return c }))
		set(c, "getAuthTag", r.fn(func(goja.FunctionCall) goja.Value { return r.makeBuffer(make([]byte, 16)) }))
		set(c, "setAuthTag", r.fn(func(call goja.FunctionCall) goja.Value {
			authTag = r.valueBytes(call.Argument(0), "utf8")
			return c
		}))
		set(c, "setAAD", r.fn(func(goja.FunctionCall) goja.Value { return c }))
		return c
	})
}

// normalizeKey sizes a key to the AES variant the algorithm names (128/192/256),
// truncating or zero-padding - real malware keys are usually already correct, but
// this keeps aes.NewCipher from erroring on an off-by-bytes key.
// newBlockCipher builds the block cipher named by a Node algorithm string. AES
// is the default; DES / Triple-DES are recognised so `eval(des_decrypt(blob))`
// recovers real plaintext rather than AES garbage. Stream ciphers (RC4) and the
// non-stdlib ciphers (blowfish/CAST/SM4) are handled elsewhere or fall through.
func newBlockCipher(algo string, key []byte) (cipher.Block, error) {
	switch {
	case strings.Contains(algo, "des-ede3") || strings.Contains(algo, "des3") || strings.Contains(algo, "3des"):
		return des.NewTripleDESCipher(normalizeKey(key, algo))
	case strings.Contains(algo, "des"):
		return des.NewCipher(normalizeKey(key, algo))
	default:
		return aes.NewCipher(normalizeKey(key, algo))
	}
}

func normalizeKey(key []byte, algo string) []byte {
	want := 32
	switch {
	// DES family first: "des-ede3"/"3des" need 24 bytes, single DES needs 8.
	// Checked before the bit-width cases so "des-ede3-cbc" isn't misread.
	case strings.Contains(algo, "des-ede3") || strings.Contains(algo, "des3") || strings.Contains(algo, "3des"):
		want = 24
	case strings.Contains(algo, "des"):
		want = 8
	case strings.Contains(algo, "128"):
		want = 16
	case strings.Contains(algo, "192"):
		want = 24
	}
	if len(key) == want {
		return key
	}
	out := make([]byte, want)
	copy(out, key)
	return out
}

func ivOrZero(iv []byte, n int) []byte {
	if len(iv) == n {
		return iv
	}
	out := make([]byte, n)
	copy(out, iv)
	return out
}

// pkcs7Strip removes PKCS#7 padding from a decrypted CBC plaintext, tolerating
// invalid padding (returns the input unchanged) since we analyze hostile data.
func pkcs7Strip(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > len(b) || pad > aes.BlockSize {
		return b
	}
	for _, c := range b[len(b)-pad:] {
		if int(c) != pad {
			return b
		}
	}
	return b[:len(b)-pad]
}

func (r *Runtime) newHash(algo string) goja.Value {
	var acc []byte
	h := r.obj()
	set(h, "update", r.fn(func(call goja.FunctionCall) goja.Value {
		acc = append(acc, []byte(argStr(call.Argument(0)))...)
		return h
	}))
	set(h, "digest", r.fn(func(call goja.FunctionCall) goja.Value {
		var sum []byte
		switch strings.ToLower(algo) {
		case "md5":
			s := md5.Sum(acc)
			sum = s[:]
		case "sha1":
			s := sha1.Sum(acc)
			sum = s[:]
		default:
			s := sha256.Sum256(acc)
			sum = s[:]
		}
		if argStr(call.Argument(0)) == "hex" {
			return r.vm.ToValue(hex.EncodeToString(sum))
		}
		return r.makeBuffer(sum)
	}))
	return h
}

// ---- util / events / stream / vm / url / misc ----

func (r *Runtime) modUtil() goja.Value {
	m := r.obj()
	set(m, "promisify", r.fn(func(call goja.FunctionCall) goja.Value {
		inner, _ := goja.AssertFunction(call.Argument(0))
		return r.fn(func(c2 goja.FunctionCall) goja.Value {
			if inner != nil {
				r.safeCall("promisified", inner, goja.Undefined(), c2.Arguments...)
			}
			return r.resolvedPromise(goja.Undefined())
		})
	}))
	set(m, "inherits", r.fn(func(call goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(m, "format", r.fn(func(call goja.FunctionCall) goja.Value {
		return r.vm.ToValue(strings.Join(r.stringifyArgs(call.Arguments), " "))
	}))
	set(m, "inspect", r.fn(func(call goja.FunctionCall) goja.Value { return r.vm.ToValue(r.stringifyValue(call.Argument(0))) }))
	set(m, "types", r.obj())
	set(m, "deprecate", r.fn(func(call goja.FunctionCall) goja.Value { return call.Argument(0) }))
	return m
}

const eventsSource = `(function(){
  function EventEmitter(){ this._ev = {}; }
  EventEmitter.prototype.on = function(e,f){ (this._ev[e]=this._ev[e]||[]).push(f); return this; };
  EventEmitter.prototype.addListener = EventEmitter.prototype.on;
  EventEmitter.prototype.prependListener = EventEmitter.prototype.on;
  EventEmitter.prototype.once = function(e,f){ var s=this; function g(){ s.removeListener(e,g); return f.apply(this,arguments); } return this.on(e,g); };
  EventEmitter.prototype.removeListener = function(e,f){ var a=this._ev[e]; if(a){ this._ev[e]=a.filter(function(x){return x!==f;}); } return this; };
  EventEmitter.prototype.off = EventEmitter.prototype.removeListener;
  EventEmitter.prototype.removeAllListeners = function(e){ if(e){ delete this._ev[e]; } else { this._ev={}; } return this; };
  EventEmitter.prototype.emit = function(e){ var a=(this._ev[e]||[]).slice(); var args=[].slice.call(arguments,1); for(var i=0;i<a.length;i++){ a[i].apply(this,args); } return a.length>0; };
  EventEmitter.prototype.listeners = function(e){ return (this._ev[e]||[]).slice(); };
  EventEmitter.prototype.setMaxListeners = function(){ return this; };
  EventEmitter.defaultMaxListeners = 10;
  EventEmitter.EventEmitter = EventEmitter;
  return EventEmitter;
})()`

func (r *Runtime) modEvents() goja.Value {
	v, err := r.vm.RunString(eventsSource)
	if err != nil {
		return r.obj()
	}
	return v
}

// newEmitter instantiates a fresh EventEmitter instance.
func (r *Runtime) newEmitter() goja.Value {
	ee := r.modEvents()
	ctor, ok := goja.AssertFunction(ee)
	if !ok {
		return r.obj()
	}
	// Use the constructor via reflection-free path: call as function on a fresh
	// object isn't constructor semantics, so build via `new` in JS instead.
	inst, err := r.construct(ee)
	if err != nil || inst == nil {
		_ = ctor
		return r.obj()
	}
	return inst
}

// construct news up a JS constructor value.
func (r *Runtime) construct(ctor goja.Value) (goja.Value, error) {
	c, ok := goja.AssertConstructor(ctor)
	if !ok {
		return r.obj(), nil
	}
	o, err := c(nil)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (r *Runtime) modStream() goja.Value {
	m := r.obj()
	ee := r.modEvents()
	for _, k := range []string{"Readable", "Writable", "Duplex", "Transform", "PassThrough", "Stream"} {
		set(m, k, ee)
	}
	set(m, "pipeline", r.fn(func(call goja.FunctionCall) goja.Value {
		if cb, ok := r.lastCallback(call); ok {
			r.invoke(cb, goja.Null())
		}
		return goja.Undefined()
	}))
	return m
}

func (r *Runtime) modVM() goja.Value {
	m := r.obj()
	withSandbox := func(sandbox goja.Value, fn func() goja.Value) goja.Value {
		obj := sandbox.ToObject(r.vm)
		if obj == nil {
			return fn()
		}
		global := r.vm.GlobalObject()
		type savedVal struct {
			existed bool
			value   goja.Value
		}
		saved := map[string]savedVal{}
		for _, k := range obj.Keys() {
			prev := global.Get(k)
			saved[k] = savedVal{existed: !goja.IsUndefined(prev), value: prev}
			must(global.Set(k, obj.Get(k)))
		}
		out := fn()
		for k, prev := range saved {
			if prev.existed {
				must(global.Set(k, prev.value))
			} else {
				_ = global.Delete(k)
			}
		}
		return out
	}
	run := func(op string) goja.Value {
		return r.fn(func(call goja.FunctionCall) goja.Value {
			code := argStr(call.Argument(0))
			r.tr.Record(trace.CatEval, "vm."+op, code)
			return withSandbox(call.Argument(1), func() goja.Value {
				v, _ := r.RunString("vm:"+op, code)
				if v == nil {
					return goja.Undefined()
				}
				return v
			})
		})
	}
	set(m, "runInThisContext", run("runInThisContext"))
	set(m, "runInNewContext", run("runInNewContext"))
	set(m, "runInContext", run("runInContext"))
	set(m, "compileFunction", r.fn(func(call goja.FunctionCall) goja.Value {
		code := argStr(call.Argument(0))
		params := []string{}
		if a1 := call.Argument(1); !goja.IsUndefined(a1) {
			if arr := a1.ToObject(r.vm); arr != nil {
				for _, k := range arr.Keys() {
					params = append(params, arr.Get(k).String())
				}
			}
		}
		src := "(function(" + strings.Join(params, ",") + "){\n" + code + "\n})"
		r.tr.Record(trace.CatEval, "vm.compileFunction", code)
		return withSandbox(call.Argument(2), func() goja.Value {
			v, _ := r.RunString("vm:compileFunction", src)
			if v == nil {
				return r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() })
			}
			return v
		})
	}))
	set(m, "createContext", r.fn(func(call goja.FunctionCall) goja.Value {
		if o := call.Argument(0); !goja.IsUndefined(o) {
			obj := o.ToObject(r.vm)
			if obj != nil {
				if goja.IsUndefined(obj.Get("global")) {
					set(obj, "global", obj)
				}
				if goja.IsUndefined(obj.Get("globalThis")) {
					set(obj, "globalThis", obj)
				}
				return obj
			}
		}
		ctx := r.obj()
		set(ctx, "global", ctx)
		set(ctx, "globalThis", ctx)
		return ctx
	}))
	set(m, "Script", r.fn(func(call goja.FunctionCall) goja.Value {
		code := argStr(call.Argument(0))
		script := r.obj()
		set(script, "code", code)
		set(script, "runInThisContext", r.fn(func(goja.FunctionCall) goja.Value {
			return withSandbox(goja.Undefined(), func() goja.Value {
				v, _ := r.RunString("vm:Script.runInThisContext", code)
				if v == nil {
					return goja.Undefined()
				}
				return v
			})
		}))
		set(script, "runInContext", r.fn(func(c goja.FunctionCall) goja.Value {
			return withSandbox(c.Argument(0), func() goja.Value {
				v, _ := r.RunString("vm:Script.runInContext", code)
				if v == nil {
					return goja.Undefined()
				}
				return v
			})
		}))
		set(script, "runInNewContext", r.fn(func(c goja.FunctionCall) goja.Value {
			return withSandbox(c.Argument(0), func() goja.Value {
				v, _ := r.RunString("vm:Script.runInNewContext", code)
				if v == nil {
					return goja.Undefined()
				}
				return v
			})
		}))
		return script
	}))
	return m
}

func (r *Runtime) modURL() goja.Value {
	m := r.obj()
	set(m, "parse", r.fn(func(call goja.FunctionCall) goja.Value {
		u, err := url.Parse(call.Argument(0).String())
		if err != nil {
			return r.obj()
		}
		o := r.obj()
		set(o, "href", u.String())
		set(o, "protocol", u.Scheme+":")
		set(o, "host", u.Host)
		set(o, "hostname", u.Hostname())
		set(o, "port", u.Port())
		set(o, "pathname", u.Path)
		set(o, "search", "")
		set(o, "query", u.RawQuery)
		return o
	}))
	set(m, "fileURLToPath", r.fn(func(call goja.FunctionCall) goja.Value {
		s := strings.TrimPrefix(call.Argument(0).String(), "file://")
		return r.vm.ToValue(s)
	}))
	return m
}

func (r *Runtime) modModule() goja.Value {
	m := r.obj()
	set(m, "createRequire", r.fn(func(call goja.FunctionCall) goja.Value {
		return r.ld.requireFn(r.cfg.BaseDir)
	}))
	// module._load is the low-level loader some packages call to bypass require.
	set(m, "_load", r.fn(func(call goja.FunctionCall) goja.Value {
		return r.ld.require(argStr(call.Argument(0)), r.cfg.BaseDir)
	}))
	set(m, "_resolveFilename", r.fn(func(call goja.FunctionCall) goja.Value {
		return r.vm.ToValue(argStr(call.Argument(0)))
	}))
	set(m, "_cache", r.obj())
	set(m, "globalPaths", r.vm.NewArray())
	set(m, "builtinModules", r.vm.NewArray())
	return m
}

func (r *Runtime) modQuerystring() goja.Value {
	m := r.obj()
	set(m, "parse", r.fn(func(call goja.FunctionCall) goja.Value {
		v, _ := url.ParseQuery(call.Argument(0).String())
		o := r.obj()
		for k := range v {
			set(o, k, v.Get(k))
		}
		return o
	}))
	set(m, "stringify", r.fn(func(call goja.FunctionCall) goja.Value { return r.vm.ToValue("") }))
	return m
}

func (r *Runtime) modAssert() goja.Value {
	noop := r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() })
	a := r.vm.ToValue(noop).ToObject(r.vm)
	for _, k := range []string{"ok", "equal", "strictEqual", "deepEqual", "deepStrictEqual", "notEqual", "throws", "fail"} {
		set(a, k, noop)
	}
	return a
}

func (r *Runtime) modPerfHooks() goja.Value {
	m := r.obj()
	perf := r.obj()
	set(perf, "now", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(0) }))
	set(m, "performance", perf)
	return m
}

// resolvedPromise wraps a value in a resolved Promise via JS.
func (r *Runtime) resolvedPromise(v goja.Value) goja.Value {
	pv := r.vm.GlobalObject().Get("Promise")
	if pv == nil || goja.IsUndefined(pv) || goja.IsNull(pv) {
		return v
	}
	p := pv.ToObject(r.vm)
	resolve, ok := goja.AssertFunction(p.Get("resolve"))
	if !ok {
		return v
	}
	out, err := resolve(p, v)
	if err != nil {
		return v
	}
	return out
}

// rejectedPromise wraps a value in a rejected Promise via JS.
func (r *Runtime) rejectedPromise(v goja.Value) goja.Value {
	pv := r.vm.GlobalObject().Get("Promise")
	if pv == nil || goja.IsUndefined(pv) || goja.IsNull(pv) {
		return v
	}
	p := pv.ToObject(r.vm)
	reject, ok := goja.AssertFunction(p.Get("reject"))
	if !ok {
		return v
	}
	out, err := reject(p, v)
	if err != nil {
		return v
	}
	return out
}

// getStr reads a string property from an object, "" if absent.
func getStr(o *goja.Object, key string) string {
	v := o.Get(key)
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return ""
	}
	return v.String()
}
