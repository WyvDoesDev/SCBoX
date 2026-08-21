package sandbox

import (
	cryptorand "crypto/rand"
	"encoding/hex"

	"scbox/internal/third_party/goja"

	"scbox/internal/rules"
	"scbox/internal/trace"
)

// baitEnv seeds the fake process.env with realistic-looking values, including
// decoy secrets. Reads are logged, so if a sample scrapes these, we both see
// the access and capture the (fake) value it would exfiltrate.
func (r *Runtime) baitEnv() map[string]string {
	prof := r.profile
	return map[string]string{
		"PATH":    "/home/" + prof.Username + "/.nvm/versions/node/v20.11.0/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME":    prof.Homedir,
		"USER":    prof.Username,
		"LOGNAME": prof.Username,
		"SHELL":   "/bin/bash",
		"PWD":     r.cfg.VirtualBase,
		// A real desktop workstation locale (not the bare C.UTF-8 of a container),
		// consistent with the X/plasma session below - this also defeats locale-gated
		// payloads (`if (process.env.LANG.includes('en_US')) …`).
		"LANG":              "en_US.UTF-8",
		"LC_ALL":            "en_US.UTF-8",
		"TERM":              "xterm-256color",
		"HOSTNAME":          prof.Hostname,
		"NODE_ENV":          "development",
		"npm_config_global": "false",
		"npm_config_cache":  prof.Homedir + "/.npm",
		"DISPLAY":           ":0", // a desktop session - not a headless CI runner
		// Padding with the env vars a real interactive Arch/X session carries,
		// so the count and contents look like a workstation, not a sparse sandbox.
		"XDG_RUNTIME_DIR":          "/run/user/1000",
		"XDG_SESSION_TYPE":         "x11",
		"XDG_SESSION_CLASS":        "user",
		"XDG_SEAT":                 "seat0",
		"XDG_DATA_DIRS":            "/usr/local/share:/usr/share",
		"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
		"SSH_AUTH_SOCK":            "/run/user/1000/keyring/ssh",
		"DESKTOP_SESSION":          "plasma",
		"GDMSESSION":               "plasma",
		"COLORTERM":                "truecolor",
		"EDITOR":                   "nvim",
		"PAGER":                    "less",
		"MOZ_ENABLE_WAYLAND":       "0",
		"GTK_THEME":                "Breeze-Dark",
		"MAIL":                     "/var/spool/mail/" + prof.Username,
		// Bait credentials with realistic formats - a read is the signal, and the
		// (fake) value the malware exfiltrates is captured in the trace. The values
		// are randomized per run (see baitCreds) so they can't be recognized as a
		// known SCBoX constant, while their shapes still match the secret regexes.
		"NPM_TOKEN":             prof.Bait.NPMToken,
		"AWS_ACCESS_KEY_ID":     prof.Bait.AWSKeyID,
		"AWS_SECRET_ACCESS_KEY": prof.Bait.AWSSecret,
		"GITHUB_TOKEN":          prof.Bait.GitHubToken,
		// Crypto wallet bait - same values served in ~/.env, so exfil from either the
		// env or the file is taint-tracked (both match IsSensitiveEnv).
		"WALLET_PRIVATE_KEY": "0x" + prof.Bait.WalletKey,
		"MNEMONIC":           prof.Bait.Mnemonic,
		// Timezone + X authority so geo/timezone-gated and X-session-gated payloads
		// fire. (CI vars are deliberately NOT set - see the anti-evasion note: their
		// absence defeats the more common `if (process.env.CI) return` self-suppression.)
		"TZ":         "America/New_York",
		"XAUTHORITY": prof.Homedir + "/.Xauthority",
	}
}

// randomBait returns a shape-neutral decoy value for a user-defined env taint
// source that carries no explicit bait. It is long enough to clear the taint
// minimum length and random per run so it can't be recognized as a constant.
func randomBait() string {
	var b [24]byte
	_, _ = cryptorand.Read(b[:])
	return "scbx_" + hex.EncodeToString(b[:])
}

// installProcess installs the global `process` object. It must run after the
// bootstrap (it relies on __mkEnvProxy) and seeds a logged, bait-filled env.
func (r *Runtime) installProcess() {
	g := r.vm.GlobalObject()
	p := r.obj()

	// env as a logging Proxy.
	envTarget := r.obj()
	env := r.baitEnv()
	taintRules := r.tr.TaintRules()
	// Custom taint rules: a literal env source not present in the fake env is
	// seeded (with the rule's bait, or a generated decoy) so a read returns a
	// watchable value. Wildcard sources only tag variables that already exist.
	for _, rl := range taintRules {
		for _, s := range rl.Sources {
			if s.Env == "" {
				continue
			}
			if name, ok := rules.LiteralEnvName(s.Env); ok {
				if _, exists := env[name]; !exists {
					bait := s.Bait
					if bait == "" {
						bait = randomBait()
					}
					env[name] = bait
				}
			}
		}
	}
	for k, v := range env {
		set(envTarget, k, v)
		// Taint: watch the bait value of every credential-shaped env var, so if the
		// sample reads it and ships it out (in any encoding) the verdict sees the
		// value land at a network sink. A value that exists only inside our fake env
		// can't reach an external endpoint by any benign route.
		if trace.IsSensitiveEnv(k) {
			r.tr.WatchSecret(v)
		}
		for _, rl := range taintRules {
			if rl.MatchesEnv(k) {
				r.tr.WatchTaint(rl.Name, v)
			}
		}
	}
	mkEnv, ok := goja.AssertFunction(r.mkEnvProxy)
	if ok {
		if proxy, err := mkEnv(goja.Undefined(), envTarget); err == nil {
			set(p, "env", proxy)
		} else {
			set(p, "env", envTarget)
		}
	} else {
		set(p, "env", envTarget)
	}

	// argv[0] is the resolved Node binary and must equal execPath (and what
	// `which node` returns) - a mismatch there is a cross-checkable sandbox tell.
	// argv0 stays the bare "node" the user typed, as real Node reports it.
	execPath := r.profile.Homedir + "/.nvm/versions/node/v20.11.0/bin/node"
	set(p, "argv", r.vm.NewArray(execPath, r.cfg.VirtualBase+"/index.js"))
	set(p, "argv0", "node")
	set(p, "execArgv", r.vm.NewArray()) // no --inspect/--debug → not under a debugger
	set(p, "execPath", execPath)
	set(p, "debugPort", 0)
	set(p, "platform", r.cfg.Platform)
	set(p, "arch", r.profile.Arch)
	set(p, "pid", r.profile.PID)
	set(p, "ppid", r.profile.PPID) // a shell, as for a real `npm install` - not init (1)
	set(p, "version", "v20.11.0")
	versions := r.obj()
	set(versions, "node", "20.11.0")
	set(versions, "v8", "11.3.244.8")
	set(versions, "uv", "1.46.0")
	set(versions, "openssl", "3.0.12")
	set(versions, "modules", "115")
	set(versions, "zlib", "1.2.13")
	set(versions, "brotli", "1.0.9")
	set(versions, "napi", "9")
	set(versions, "icu", "73.2")
	set(versions, "cldr", "43.1")
	set(versions, "unicode", "15.0")
	set(p, "versions", versions)

	set(p, "cwd", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(r.cfg.VirtualBase) }))
	set(p, "chdir", r.fn(func(goja.FunctionCall) goja.Value { return goja.Undefined() }))
	set(p, "exit", r.fn(func(call goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatProcess, "process.exit", argStr(call.Argument(0)))
		panic(r.vm.ToValue("__scbox_process_exit__"))
	}))
	set(p, "nextTick", r.fn(func(call goja.FunctionCall) goja.Value {
		if cb, ok := goja.AssertFunction(call.Argument(0)); ok {
			r.queueCallback(cb)
		}
		return goja.Undefined()
	}))
	onFn := r.fn(func(call goja.FunctionCall) goja.Value {
		ev := argStr(call.Argument(0))
		r.tr.Record(trace.CatProcess, "process.on", ev)
		// Capture exit/signal listeners so a payload deferred to process teardown
		// (`process.on('exit', () => exec(...))`) is fired at end of analysis instead
		// of silently dropped.
		switch ev {
		case "exit", "beforeExit", "SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT":
			if cb, ok := goja.AssertFunction(call.Argument(1)); ok {
				r.exitHandlers = append(r.exitHandlers, cb)
			}
		}
		return p
	})
	set(p, "on", onFn)
	set(p, "once", onFn)
	set(p, "addListener", onFn)
	set(p, "prependListener", onFn)
	set(p, "binding", r.fn(func(call goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatProcess, "process.binding", argStr(call.Argument(0)))
		return r.callMkFake("process.binding(" + argStr(call.Argument(0)) + ")")
	}))
	set(p, "kill", r.logged(trace.CatProcess, "process.kill", nil))
	// dlopen would load a native .node addon = real host code; never permit it.
	set(p, "dlopen", r.fn(func(call goja.FunctionCall) goja.Value {
		r.tr.Record(trace.CatProcess, "process.dlopen", argStr(call.Argument(1)))
		return goja.Undefined()
	}))
	set(p, "report", func() *goja.Object {
		rep := r.obj()
		set(rep, "getReport", r.fn(func(goja.FunctionCall) goja.Value {
			o := r.obj()
			set(o, "header", r.obj())
			return o
		}))
		set(rep, "directory", "")
		set(rep, "filename", "")
		return rep
	}())
	hr := r.fn(func(call goja.FunctionCall) goja.Value { return r.vm.NewArray(12345, 678900000) })
	set(p, "hrtime", hr)
	set(p, "memoryUsage", r.fn(func(goja.FunctionCall) goja.Value {
		o := r.obj()
		set(o, "rss", 1024)
		set(o, "heapTotal", 1024)
		set(o, "heapUsed", 512)
		return o
	}))
	set(p, "umask", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(0) }))
	set(p, "getuid", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(1000) }))
	set(p, "getgid", r.fn(func(goja.FunctionCall) goja.Value { return r.vm.ToValue(1000) }))

	// stdout/stderr write → console category.
	mkStream := func(name string) *goja.Object {
		s := r.obj()
		set(s, "write", r.fn(func(call goja.FunctionCall) goja.Value {
			r.tr.Record(trace.CatConsole, name, argStr(call.Argument(0)))
			return r.vm.ToValue(true)
		}))
		set(s, "on", r.fn(func(goja.FunctionCall) goja.Value { return s }))
		set(s, "isTTY", false)
		return s
	}
	set(p, "stdout", mkStream("stdout"))
	set(p, "stderr", mkStream("stderr"))
	set(p, "stdin", r.newEmitter())

	set(g, "process", p)
}
