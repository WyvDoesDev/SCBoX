package sandbox

import (
	"time"

	"scbox/internal/third_party/goja"
)

// This file implements a webcrack-style recovery of javascript-obfuscator
// string-array loaders. Rather than reimplementing the tool's base64/RC4/rotation
// decoder in Go, it runs the sample's OWN code inside a throwaway goja VM and
// harvests the plaintext at the SINKS - the decoded values necessarily arrive as
// arguments to fetch / Function / eval / require / WebSocket once the loader has
// run its decoder, regardless of where (often nested inside an exported function)
// the decoder is defined. The file's top-level code plus a permissive synthetic
// call of the module exports drive the decoder, so the recovered set includes the
// C2 URL and the executed payload body even when the live payload is gated behind
// a runtime argument and never fires under normal detonation. The recovered
// strings are fed back to the tracer as decoded payload + IOCs, so the verdict
// scores the sample on its real behavior instead of an obfuscation fingerprint.

// deobfBootstrap stands up a permissive, inert environment whose capability sinks
// harvest every string argument into __deobf. A self-returning Proxy backs
// require()/fetch() so deep property/call chains (`require('https').request(...)`,
// `options.a.b.c`) never throw and the loader proceeds to its decode-and-call
// path. No sink performs real I/O.
const deobfBootstrap = `
function __harvestArgs(a){ for (var i=0;i<a.length;i++){ try{ var v=a[i]; if (typeof v==='string') __deobf(v); } catch(e){} } }
// Self-returning proxy backing every faked capability. Its apply trap harvests
// string args, so a decoded value reaching ANY chained sink - require('https').
// get(url), spawn(cmd), ws.send(data) - is captured even though no concrete stub
// exists for it.
var __P = new Proxy(function(){return __P;}, {
  get:function(){return __P;},
  apply:function(t,th,a){ __harvestArgs(a); return __P; },
  construct:function(t,a){ __harvestArgs(a); return __P; }
});
var module={exports:{}}, exports=module.exports;
function require(){ __harvestArgs(arguments); return __P; }
var fetch=function(){ __harvestArgs(arguments); return {then:function(){return this;},catch:function(){return this;},finally:function(){return this;}}; };
var __RealFunction = Function;
Function = function(){ __harvestArgs(arguments); try { return __RealFunction.apply(this, arguments); } catch(e){ return function(){}; } };
Function.prototype = __RealFunction.prototype;
eval = function(c){ try{ if(typeof c==='string') __deobf(c); }catch(e){} return undefined; };
var atob = function(s){ try{ __deobf(String(s)); }catch(e){} return ""; };
var btoa = function(s){ return ""; };
function WebSocket(){ __harvestArgs(arguments); return __P; }
function XMLHttpRequest(){ return { open:function(){ __harvestArgs(arguments); }, send:function(){ __harvestArgs(arguments); }, setRequestHeader:function(){} }; }
function AbortController(){ this.signal={aborted:false,addEventListener:function(){}}; this.abort=function(){}; }
function importScripts(){ __harvestArgs(arguments); }
// Inert timers: run callbacks synchronously so deferred decode paths still fire,
// but never schedule real work.
function setTimeout(f){ try{ if(typeof f==='function') f(); }catch(e){} return 0; }
function setInterval(){ return 0; }
function clearTimeout(){} function clearInterval(){} function queueMicrotask(f){ try{ if(typeof f==='function') f(); }catch(e){} }
function setImmediate(f){ try{ if(typeof f==='function') f(); }catch(e){} return 0; }
function __b64dec(s){ var t='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'; s=String(s).replace(/[^A-Za-z0-9+/]/g,''); var o=''; for(var i=0;i<s.length;i+=4){ var a=t.indexOf(s.charAt(i)),b=t.indexOf(s.charAt(i+1)),c=t.indexOf(s.charAt(i+2)),d=t.indexOf(s.charAt(i+3)); o+=String.fromCharCode((a<<2)|(b>>4)); if(c>=0)o+=String.fromCharCode(((b&15)<<4)|(c>>2)); if(d>=0)o+=String.fromCharCode(((c&3)<<6)|d); } return o; }
function __hexdec(s){ s=String(s); var o=''; for(var i=0;i+1<s.length;i+=2){ var n=parseInt(s.substr(i,2),16); if(n>=0) o+=String.fromCharCode(n); } return o; }
// Buffer.from actually decodes base64/hex so a Buffer.from(x,'base64').toString()
// loader yields its real plaintext URL/command, which then reaches a harvesting sink.
var Buffer={ from:function(x,enc){ var d=String(x); try{ if(enc==='base64') d=__b64dec(x); else if(enc==='hex') d=__hexdec(x); }catch(e){} try{ __deobf(d); }catch(e){} return { toString:function(){ return d; }, slice:function(){return this;}, length:d.length }; }, alloc:function(){return Buffer.from("");}, isBuffer:function(){return false;} };
function TextEncoder(){ this.encode=function(s){ try{__deobf(String(s));}catch(e){} return []; }; }
function TextDecoder(){ this.decode=function(){ return ""; }; }
var URL=function(u){ try{__deobf(String(u));}catch(e){} this.href=String(u); this.searchParams={get:function(){return null;},set:function(){}}; };
var console={log:function(){},error:function(){},warn:function(){},info:function(){},debug:function(){}};
var process={env:{},argv:[],platform:'linux',version:'v20.11.0',versions:{node:'20.11.0'},cwd:function(){return '/';},nextTick:function(f){try{if(typeof f==='function')f();}catch(e){}},on:function(){},exit:function(){}};
var global=this, globalThis=this, window=undefined, self=this, navigator={userAgent:'node'}, document=undefined, location=undefined;
`

// deobfDriver runs after the loader source: it calls every exported function with
// a self-returning Proxy so a gated payload (e.g. a postcss plugin that builds its
// C2 URL only from its `options` argument) executes its decode path and the URL
// reaches the harvesting fetch/require. All failures are expected and ignored.
const deobfDriver = `;(function(){try{
  var t=[];
  try{ if(module&&module.exports){ var m=module.exports;
    if(typeof m==='function') t.push(m);
    if(m&&typeof m==='object') for(var k in m){ try{ if(typeof m[k]==='function') t.push(m[k]); }catch(e){} } } }catch(e){}
  for(var i=0;i<t.length;i++){ try{ t[i](__P,__P,__P); }catch(e){} }
}catch(e){}})();`

// RecoverObfuscatedStrings runs src in an isolated goja VM and returns the
// de-duplicated plaintext strings that reach its capability sinks. It performs NO
// host I/O - every sink is inert - and is bounded by budget via the VM interrupt.
func RecoverObfuscatedStrings(src string, budget time.Duration) []string {
	vm := goja.New()
	seen := map[string]struct{}{}
	var out []string
	must(vm.Set("__deobf", func(call goja.FunctionCall) goja.Value {
		s := call.Argument(0).String()
		if len(s) == 0 || len(s) > 1<<16 {
			return goja.Undefined()
		}
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
		return goja.Undefined()
	}))
	if _, err := vm.RunString(deobfBootstrap); err != nil {
		return nil
	}
	prog, cerr := goja.Compile("deobf", src+deobfDriver, false)
	if cerr != nil {
		return nil
	}
	if budget <= 0 {
		budget = 2 * time.Second
	}
	timer := time.AfterFunc(budget, func() { vm.Interrupt("deobf budget") })
	defer timer.Stop()
	func() {
		defer func() { _ = recover() }()
		_, _ = vm.RunProgram(prog)
	}()
	return out
}
