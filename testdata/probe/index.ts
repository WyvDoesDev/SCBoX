// Benign sandbox self-test, written in TypeScript (types/enums/interfaces/
// optional-chaining exercise the esbuild transpile path). It attempts known
// escape gadgets and sandbox-detection probes, then prints what it observed.
// Nothing here is harmful — it only reports.

interface Finding {
  name: string;
  value: string;
}

enum Kind {
  Escape = "ESCAPE",
  Detect = "DETECT",
}

const findings: Finding[] = [];
const record = (k: Kind, name: string, value: unknown): void => {
  findings.push({ name: `${k}:ts:${name}`, value: String(value) });
};

// ---------- escape attempts ----------

// 1. The classic constructor.constructor sandbox-escape gadget.
try {
  const g = ([] as any)["constructor"]["constructor"]("return this")();
  record(Kind.Escape, "ctor-gadget-type", typeof g);
  record(Kind.Escape, "ctor-gadget-reaches-process", typeof g?.process?.binding);
} catch {
  record(Kind.Escape, "ctor-gadget", "threw");
}

// 2. Try to read a real host secret file.
try {
  const fs = require("fs");
  const passwd: string = fs.readFileSync("/etc/passwd", "utf8");
  record(Kind.Escape, "read-/etc/passwd-bytes", passwd.length);
} catch {
  record(Kind.Escape, "read-/etc/passwd", "threw");
}

// 3. Write a file and read it back — does anything persist to the real disk?
try {
  const fs = require("fs");
  fs.writeFileSync("/tmp/scbox_escape_probe_ts", "pwned-by-ts");
  const back: string = fs.readFileSync("/tmp/scbox_escape_probe_ts", "utf8");
  record(Kind.Escape, "write-then-readback", back === "" ? "(empty)" : back);
} catch {
  record(Kind.Escape, "write-then-readback", "threw");
}

// 4. Try to run a real command and capture real output.
try {
  const cp = require("child_process");
  const out: string = cp.execSync("cat /etc/shadow").toString().trim();
  record(Kind.Escape, "exec-cat-shadow", out === "" ? "(empty)" : out);
} catch {
  record(Kind.Escape, "exec-cat-shadow", "threw");
}

// 5. Low-level loader to fetch a "real" fs.
try {
  const m: any = require("module");
  const realfs = m?._load ? m._load("fs") : null;
  record(Kind.Escape, "module._load-fs-type", typeof realfs?.readFileSync);
} catch {
  record(Kind.Escape, "module._load", "threw");
}

// ---------- sandbox-detection probes ----------
const os = require("os");
const fs = require("fs");
record(Kind.Detect, "hostname", os.hostname());
record(Kind.Detect, "username", os.userInfo()?.username);
record(Kind.Detect, "cpu-count", os.cpus()?.length);
record(Kind.Detect, "ram-GB", Math.round(os.totalmem() / 1e9));
record(Kind.Detect, "eth0-mac", os.networkInterfaces()?.eth0?.[0]?.mac);
record(Kind.Detect, "env.CI", process.env.CI ?? "(unset)");
record(Kind.Detect, "cwd", process.cwd());
record(Kind.Detect, "__dirname", __dirname);
record(Kind.Detect, "dockerenv-exists", fs.existsSync("/.dockerenv"));
record(
  Kind.Detect,
  "hostname-is-native",
  Function.prototype.toString.call(os.hostname).includes("[native code]")
);
record(Kind.Detect, "navigator-cores", (globalThis as any).navigator?.hardwareConcurrency);

// Timing probe: does virtual time advance across a delay?
const t0 = Date.now();
setTimeout(() => {
  record(Kind.Detect, "time-elapsed-ms", Date.now() - t0);
  for (const f of findings) {
    console.log(`${f.name} = ${f.value}`);
  }
}, 3000);

export {};
