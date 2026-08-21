package sandbox

import (
	"fmt"
	"strings"

	"scbox/internal/third_party/goja"

	"scbox/internal/trace"
)

// installEval instruments every route to dynamic code execution and the common
// string-deobfuscation primitives, then lets the real implementation run so the
// payload still detonates. The hooks are installed in JS because the dangerous
// constructors are reachable through several prototype chains
// (e.g. `[]["constructor"]["constructor"]("code")()`, the classic sandbox-escape
// gadget) that a Go-side global override would miss.
//
// On goja the escape gadget is not actually dangerous - `Function("return this")`
// returns *our* fake global, never a real Node `process` - but capturing the
// code body is still high-value for analysis, so we hook it anyway.
func (r *Runtime) installEval() {
	must(r.vm.Set("__trace_eval", r.fn(func(call goja.FunctionCall) goja.Value {
		body := argStr(call.Argument(0))
		// Decrypt-then-execute loader: the eval/Function body is the very plaintext
		// a createDecipheriv just produced (`eval(decrypt(blob))`). This is the
		// sample's own behavior and intrinsically malicious, so record it through
		// the mute (force-execution surfaces these payloads) - the intrinsic verdict
		// view scores it. Cipher-agnostic: the match holds even when our decryption
		// is wrong (unsupported algo) because the sample evals whatever we returned.
		if r.evalBodyFromDecipher(body) {
			r.tr.Record(trace.CatEval, "decrypt-then-eval", body)
		}
		// Dynamic code triggered BY our own ForceExecute fuzzing is a sandbox
		// artifact, not the sample's behavior: invoking a validation library's
		// schema compiler / regex builder with synthetic args drives hundreds of
		// new Function() calls (e.g. zod emitted 628), which falsely read as "heavy
		// dynamic-code / packed payload". Skip those while fuzzing - BUT still record
		// when the eval body is high-signal: a download-and-execute loader fetches
		// its stage and evals it (`Function(res.data.cookie)()`), so the body carries
		// the fake-fetch marker; that path only fires under force-execution and
		// dropping it would be a false negative.
		if r.exploreQuiet && !strings.Contains(body, "/* fetched */") && !highSignalDecoded(body) {
			return goja.Undefined()
		}
		// Record the dynamic-code execution (Record auto-scans the body for any
		// embedded URLs/commands). We deliberately do NOT file the body as a
		// "decoded blob": generated code is routine in benign libraries (zod
		// schema codegen, bundler chunk loaders, template compilers). Conflating
		// it with base64/hex deobfuscation produced false "packed payload"
		// signals. Genuine deobfuscation primitives (atob/Buffer.from/charcode)
		// still populate the Decoded set below.
		r.tr.Record(trace.CatEval, "dynamic-code", body)
		// EXCEPTION to the above: an eval body that is itself a download-and-execute
		// loader (process exec + network, e.g. require('child_process').spawn after
		// https.get(C2)) is the recovered final stage of a packed/multi-layer payload,
		// not benign codegen. The staged DPRK obfuscator loaders (bn-math/ultra/…)
		// XOR-decode several layers and surface their C2 ONLY in this eval body - the
		// raw base64 decode is intermediate ciphertext - and they run under the muted
		// file-load, so only an intrinsic decoded-loader signal can score them. File
		// just these into the Decoded set; the exec+net shape keeps codegen out.
		if looksLikeLoaderEval(body) {
			r.tr.AddDecoded(body)
		}
		return goja.Undefined()
	})))
	must(r.vm.Set("__trace_decode", r.fn(func(call goja.FunctionCall) goja.Value {
		// Same as eval/atob: deobfuscation primitives exercised by the fuzz sweep
		// are artifacts of our synthetic inputs, not the sample's own behavior.
		if r.exploreQuiet {
			return goja.Undefined()
		}
		s := argStr(call.Argument(0))
		r.tr.Record(trace.CatEval, "deobfuscate", s)
		r.tr.AddDecoded(s)
		return goja.Undefined()
	})))

	if _, err := r.vm.RunString(evalHookSource); err != nil {
		panic(fmt.Errorf("sandbox: eval hooks failed: %w", err))
	}
}

// looksLikeLoaderEval reports whether an eval/Function body is itself a
// download-and-execute loader: it spawns a process AND reaches the network. This
// is the high-confidence conjunction (mirrors the decoded-loader detector) - a
// benign template/codegen body has neither child_process nor an http endpoint, so
// filing only these into the decoded set scores real staged loaders without the
// codegen false positives that filing ALL dynamic code would cause.
func looksLikeLoaderEval(body string) bool {
	if len(body) < 16 {
		return false
	}
	low := strings.ToLower(body)
	exec := strings.Contains(low, "child_process") || strings.Contains(low, "spawn(") ||
		strings.Contains(low, "spawnsync") || strings.Contains(low, "execsync") ||
		strings.Contains(low, "exec(") || strings.Contains(low, "/bin/sh") ||
		strings.Contains(low, "/bin/bash") || strings.Contains(low, "node -e") ||
		strings.Contains(low, "powershell") || strings.Contains(low, "cmd.exe")
	net := strings.Contains(low, "http://") || strings.Contains(low, "https://") ||
		strings.Contains(low, "fetch(") || strings.Contains(low, "websocket") ||
		strings.Contains(low, "\"net\"") || strings.Contains(low, "'net'") ||
		strings.Contains(low, "import(\"https\")") || strings.Contains(low, "require('https')") ||
		strings.Contains(low, "require(\"https\")") || strings.Contains(low, "require('http')")
	return exec && net
}

const evalHookSource = `(function(){
  var _eval = globalThis.__trace_eval;       // captured before the global is deleted
  var _decode = globalThis.__trace_decode;
  var realEval = globalThis.eval;
  var realFunction = globalThis.Function;    // captured before wrapCtor replaces it
  function log(c){ try {
    if (typeof c === 'string') { if (c.length) _eval(c); return; }
    // Some droppers eval a parsed value: eval(JSON.parse(body)). When the C2
    // body deserializes to an object/array, the executed payload still carries
    // our fetched-payload marker in its fields - stringify so the marker reaches
    // the analyzer (a bare object would otherwise log as "[object Object]").
    if (c && typeof c === 'object') { var s = JSON.stringify(c); if (s && s.indexOf('/* fetched */') >= 0) _eval(s); }
  } catch (e) {} }

  // Run an eval payload inside a synthetic CommonJS scope. Replacing eval with a
  // wrapper makes the call INDIRECT (global scope), so a payload that references
  // module/exports/__dirname/__filename - which a real DIRECT eval inside a module
  // would see - throws "module is not defined" and the loader dies before its next
  // stage. This is the staged-obfuscator idiom: eval(decodeSource(blob)) where the
  // decoded layer opens with module.exports={...} then eval()s the layer below it.
  // We re-run such a payload with the CommonJS bindings as function parameters (the
  // way Node's module loader does), WITHOUT leaking module/exports onto globalThis
  // (a sandbox tell). require is already global. Used only on the ReferenceError
  // retry, so plain expression eval (eval("1+1")) keeps its value via realEval.
  function runCJS(c){
    var m = { exports: {} };
    return realFunction('module','exports','require','__filename','__dirname', c)
             .call(globalThis, m, m.exports, globalThis.require, '', '');
  }

  // Wrap eval (indirect - runs in global scope). Two scope problems make a real
  // DIRECT eval inside a module behave differently from our indirect one, and both
  // surface as a ReferenceError "<id> is not defined":
  //   1. CommonJS bindings: the payload reads module/exports/__dirname/__filename.
  //   2. const/let + hoisted function: indirect eval puts a function declaration in
  //      the GLOBAL scope but keeps a sibling const x = require(...) in the eval's
  //      own lexical scope, so the function can't see x and throws when called. The
  //      staged DPRK loaders end with exactly this shape (a const os=require('os')
  //      next to a function run(){ os.platform() } then run()), so the final stage
  //      silently never fired.
  // Re-running the whole payload inside one CommonJS function scope (runCJS) puts the
  // consts and the functions in the SAME scope and supplies module/exports/require,
  // fixing both. Only taken on the ReferenceError path, so plain expression eval
  // keeps its value via realEval. (realEval may have produced side effects before
  // throwing; for these loaders that prefix is idempotent require/decode work.)
  globalThis.eval = function(c){
    log(c);
    try { return realEval(c); }
    catch (e) {
      if (typeof c === 'string' && (e instanceof ReferenceError || /\bis not defined\b/.test(String(e)))) {
        return runCJS(c);
      }
      throw e;
    }
  };

  // Wrap a Function-family constructor via its prototype so every path that
  // reaches it (Function, ({}).constructor.constructor, [].constructor.constructor,
  // async/generator variants) is logged.
  function wrapCtor(proto){
    if (!proto) return null;
    var real = proto.constructor;
    if (typeof real !== 'function') return null;
    function Wrapped(){
      var a = arguments;
      if (a.length) log(a[a.length - 1]);
      return real.apply(this, a); // Function ctor ignores |this|, returns a fn
    }
    Wrapped.prototype = real.prototype;
    try { proto.constructor = Wrapped; } catch (e) {}
    return Wrapped;
  }
  var WFunction = wrapCtor(Function.prototype);
  if (WFunction) { try { globalThis.Function = WFunction; } catch (e) {} }
  try { wrapCtor(Object.getPrototypeOf(function*(){})); } catch (e) {}
  try { wrapCtor(Object.getPrototypeOf(async function(){})); } catch (e) {}
  // (async generators aren't supported by the interpreter; nothing to wrap.)

  // Capture string-deobfuscation primitives: their *output* is frequently the
  // real payload (URLs, commands, more code), and feeding it to __trace_decode
  // re-scans it for nested IOCs.
  var fcc = String.fromCharCode;
  if (fcc) String.fromCharCode = function(){ var s = fcc.apply(String, arguments); try { if (s.length >= 6) _decode(s); } catch (e) {} return s; };
  var fcp = String.fromCodePoint;
  if (fcp) String.fromCodePoint = function(){ var s = fcp.apply(String, arguments); try { if (s.length >= 6) _decode(s); } catch (e) {} return s; };

  ['unescape','decodeURIComponent','decodeURI'].forEach(function(n){
    var f = globalThis[n];
    if (typeof f === 'function') {
      globalThis[n] = function(x){ var r = f(x); try { if (typeof r === 'string' && r.length >= 6 && r !== x) _decode(r); } catch (e) {} return r; };
    }
  });
})();`
