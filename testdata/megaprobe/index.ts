// EXHAUSTIVE, benign sandbox probe. Throws every detection / evasion / escape
// technique I can think of at the sandbox and prints what it observed. Nothing
// here is harmful — it only reports, so we can see what a real evasive sample
// would learn about the environment.

type Out = (label: string, value: unknown) => void;
const lines: string[] = [];
const out: Out = (label, value) => lines.push(`${label} = ${String(value)}`);
const tryOut = (label: string, fn: () => unknown): void => {
  try {
    out(label, fn());
  } catch (e) {
    out(label, "THREW:" + (e as Error).message);
  }
};

const G = globalThis as any;

// ============ 0. instrumentation-global leak detection ============
tryOut("leak:suspicious-globals", () => {
  const names = Object.getOwnPropertyNames(globalThis);
  const bad = names.filter((n) => /__|trace|mkfake|clock|scbox|goja|hook|inject|sandbox|coverage/i.test(n));
  return bad.length ? bad.join(",") : "(none)";
});
tryOut("leak:__mkFake", () => typeof G.__mkFake);
tryOut("leak:__trace_eval", () => typeof G.__trace_eval);
tryOut("leak:__clock_offset", () => typeof G.__clock_offset);
tryOut("leak:globalThis-key-count", () => Object.keys(globalThis).length);

// ============ 1. escape gadgets ============
tryOut("escape:Function-return-this", () => {
  const g = Function("return this")();
  return typeof g + " hasProcess=" + (typeof g?.process);
});
tryOut("escape:ctor.ctor-return-process", () => {
  const p = ([] as any).constructor.constructor("return process")();
  return typeof p + " platform=" + p?.platform;
});
tryOut("escape:AsyncFunction-ctor", () => {
  const AF = Object.getPrototypeOf(async function () {}).constructor;
  return typeof AF;
});
tryOut("escape:GeneratorFunction-ctor", () => {
  const GF = Object.getPrototypeOf(function* () {}).constructor;
  return typeof GF;
});
tryOut("escape:vm.runInNewContext", () => {
  const vm = require("vm");
  return String(vm.runInNewContext("1+1"));
});
tryOut("escape:vm.runInThisContext-process", () => {
  const vm = require("vm");
  const p = vm.runInThisContext("typeof process");
  return String(p);
});
tryOut("escape:process.binding-spawn_sync", () => typeof (process as any).binding?.("spawn_sync"));
tryOut("escape:process.dlopen", () => typeof (process as any).dlopen);
tryOut("escape:process.mainModule", () => typeof (process as any).mainModule);
tryOut("escape:module._load-fs", () => {
  const m: any = require("module");
  return typeof m?._load?.("fs")?.readFileSync;
});
tryOut("escape:read-/etc/passwd", () => {
  const fs = require("fs");
  const d: string = fs.readFileSync("/etc/passwd", "utf8");
  return "len=" + d.length + " first=" + JSON.stringify(d.slice(0, 14));
});
tryOut("escape:read-/proc/self/environ", () => {
  const fs = require("fs");
  return "len=" + fs.readFileSync("/proc/self/environ", "utf8").length;
});
tryOut("escape:write-readback-consistency", () => {
  const fs = require("fs");
  const p = "/tmp/__mega_probe_" + Date.now();
  fs.writeFileSync(p, "CANARY-1234");
  return fs.readFileSync(p, "utf8");
});
tryOut("escape:execSync-id", () => {
  const cp = require("child_process");
  return cp.execSync("id").toString().trim();
});
tryOut("escape:execSync-uname", () => {
  const cp = require("child_process");
  return cp.execSync("uname -a").toString().trim();
});
tryOut("escape:worker_threads", () => typeof require("worker_threads")?.Worker);
tryOut("escape:Buffer.allocUnsafe-zeroed", () => {
  const b = Buffer.allocUnsafe(32);
  let nonZero = 0;
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) nonZero++;
  return "nonzero-bytes=" + nonZero;
});
tryOut("escape:error-stack-leaks-path", () => {
  const s = new Error("x").stack || "";
  return /\/tmp|scbox|goja|\.go:/i.test(s) ? "LEAK:" + s.split("\n")[1] : "clean";
});

// ============ 2. host fingerprint / detection ============
const os = require("os");
const fs = require("fs");
tryOut("detect:hostname", () => os.hostname());
tryOut("detect:username", () => os.userInfo().username);
tryOut("detect:cpu-count", () => os.cpus().length);
tryOut("detect:total-GB", () => Math.round(os.totalmem() / 1e9));
tryOut("detect:uptime-hours", () => Math.round(os.uptime() / 3600));
tryOut("detect:eth0-mac", () => os.networkInterfaces()?.eth0?.[0]?.mac);
tryOut("detect:mac-is-vm", () => {
  const m: string = (os.networkInterfaces()?.eth0?.[0]?.mac || "").toLowerCase();
  return /^(08:00:27|00:0c:29|00:05:69|00:1c:14|00:50:56|00:16:3e|00:15:5d|52:54:00)/.test(m);
});
tryOut("detect:dockerenv", () => fs.existsSync("/.dockerenv"));
tryOut("detect:proc-vz", () => fs.existsSync("/proc/vz"));
tryOut("detect:dmi-vendor", () => {
  try {
    return fs.readFileSync("/sys/class/dmi/id/sys_vendor", "utf8").trim();
  } catch {
    return "(enoent)";
  }
});
tryOut("detect:cpuinfo-hypervisor-flag", () => {
  const c: string = fs.readFileSync("/proc/cpuinfo", "utf8");
  return /hypervisor/.test(c) ? "PRESENT(vm)" : "absent";
});
tryOut("detect:os-release", () => {
  const c: string = fs.readFileSync("/etc/os-release", "utf8");
  return (c.match(/^ID=(\S+)/m) || [])[1];
});
tryOut("detect:env-var-count", () => Object.keys(process.env).length);
tryOut("detect:env.CI", () => process.env.CI ?? "(unset)");
tryOut("detect:env.GITHUB_ACTIONS", () => process.env.GITHUB_ACTIONS ?? "(unset)");
tryOut("detect:env.container", () => process.env.container ?? "(unset)");
tryOut("detect:pid", () => process.pid);
tryOut("detect:cwd-suspicious", () => /tmp|sandbox|sample|malware|virus|scbox/i.test(process.cwd()));
tryOut("detect:dirname-suspicious", () => /tmp|sandbox|sample|malware|virus|scbox/i.test(__dirname));

// ============ 3. API-hooking / native-code detection ============
const isNative = (f: unknown) => Function.prototype.toString.call(f).includes("[native code]");
tryOut("hook:fs.readFileSync-native", () => isNative(fs.readFileSync));
tryOut("hook:console.log-native", () => isNative(console.log));
tryOut("hook:fetch-native", () => isNative(G.fetch));
tryOut("hook:child_process.exec-native", () => isNative(require("child_process").exec));
tryOut("hook:eval-native", () => isNative(G.eval));

// ============ 4. node/runtime-shape detection ============
tryOut("shape:setTimeout-return-type", () => {
  const t: any = setTimeout(() => {}, 0);
  const r = typeof t + " hasUnref=" + (typeof t?.unref === "function");
  clearTimeout(t);
  return r;
});
tryOut("shape:Error.captureStackTrace", () => typeof (Error as any).captureStackTrace);
tryOut("shape:process.hrtime.bigint", () => typeof (process as any).hrtime?.bigint);
tryOut("shape:process.versions.node", () => process.versions?.node);
tryOut("shape:WebAssembly", () => typeof G.WebAssembly);
tryOut("shape:crypto.getRandomValues", () => typeof G.crypto?.getRandomValues);
tryOut("shape:structuredClone", () => typeof G.structuredClone);
tryOut("shape:BigInt", () => typeof G.BigInt);
tryOut("shape:queueMicrotask", () => typeof G.queueMicrotask);
tryOut("shape:navigator-cores-vs-cpus", () => {
  return `${G.navigator?.hardwareConcurrency} vs ${os.cpus().length}`;
});

// ============ 5b. additional evasion / fidelity ============
tryOut("evade:busy-wait-sleep-escapes", () => {
  // Long busy-wait used to outlast analysis. Should terminate quickly because
  // the clock races forward as we poll it; if we reach here, evasion failed.
  const s = Date.now();
  let spins = 0;
  while (Date.now() - s < 600000) spins++;
  return "completed after " + spins + " spins, virtual-elapsed=" + (Date.now() - s);
});
tryOut("detect:home-file-count", () => require("fs").readdirSync(os.homedir()).length);
tryOut("fidelity:buffer-roundtrip", () => {
  const b = Buffer.from("hello");
  return b.toString() + " b[0]=" + b[0] + " len=" + b.length;
});
tryOut("fidelity:buffer-base64-index", () => {
  const b = Buffer.from("aGVsbG8=", "base64");
  return b.toString() + " b[0]=" + b[0];
});
tryOut("detect:ppid", () => process.ppid);

// ============ 5. timing-based detection ============
const tStart = Date.now();
let busy = 0;
for (let i = 0; i < 2_000_000; i++) busy += i;
tryOut("timing:busyloop-advanced-ms", () => Date.now() - tStart);

const tBefore = Date.now();
setTimeout(() => {
  out("timing:settimeout-5s-elapsed-ms", String(Date.now() - tBefore));
  // Final report.
  console.log("===== MEGAPROBE FINDINGS =====");
  for (const l of lines) console.log(l);
  console.log("===== END (" + lines.length + " checks) =====");
}, 5000);

export {};
