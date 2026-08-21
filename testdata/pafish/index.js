#!/usr/bin/env node
/*
 * pafish.js — a JavaScript/Node.js equivalent of pafish (Paranoid Fish,
 * https://github.com/a0rtega/pafish).
 *
 * pafish is a Windows tool that demonstrates the techniques malware uses to
 * detect analysis environments (debuggers, VMs, sandboxes). This is the Node.js
 * analogue: it runs the checks an *evasive npm package* would use to decide
 * whether it is being analyzed, and prints a pafish-style report.
 *
 * Run it on a REAL machine: every line should read [ OK ] (traced = nothing
 * detected). Run it inside an analysis sandbox (e.g. SCBoX): any [DETECTED]
 * line is a "tell" — an artifact the sandbox failed to hide, which real malware
 * would use to stay dormant. The goal of a good sandbox is zero detections.
 *
 * Pure Node core modules; no dependencies; read-only; makes no network calls.
 */
'use strict';

const os = require('os');
const fs = require('fs');

let detected = 0, total = 0;
function check(name, isDetected, detail) {
  total++;
  if (isDetected) detected++;
  const tag = isDetected ? '[DETECTED]' : '[  OK   ]';
  console.log(tag + ' ' + name + (detail ? '  -> ' + detail : ''));
}
function safe(fn, dflt) { try { return fn(); } catch (e) { return dflt; } }
function readFile(p) { return safe(() => fs.readFileSync(p, 'utf8'), null); }
function exists(p) { return safe(() => fs.existsSync(p), false); }

console.log('====================================================');
console.log(' pafish.js  -  Node.js sandbox/VM/analysis detector');
console.log('====================================================\n');

/* ---------------------------------------------------------------------------
 * 1. Hooked / instrumented APIs  (analysis sandboxes wrap core functions)
 * ------------------------------------------------------------------------- */
console.log('-- Instrumentation / API hooks --');
function isNative(fn) {
  return typeof fn === 'function' && /\{\s*\[native code\]\s*\}/.test(safe(() => Function.prototype.toString.call(fn), ''));
}
check('eval is non-native (hooked)', !isNative(eval), safe(() => String(eval).slice(0, 40)));
check('Function is non-native (hooked)', !isNative(Function));
check('fs.readFileSync is non-native (hooked)', !isNative(fs.readFileSync));
check('child_process.exec is non-native (hooked)', !isNative(safe(() => require('child_process').exec)));
check('console.log is non-native (hooked)', !isNative(console.log));
check('Function.prototype.toString is non-native (re-hooked)', !isNative(Function.prototype.toString));
// Instrumentation globals that an in-process JS sandbox might leak.
const leakNames = ['__mkFake', '__trace_eval', '__trace_net', '__trace_env', '__clock_offset', '__coverage__', '__nyc'];
const leaked = leakNames.filter((n) => typeof globalThis[n] !== 'undefined');
check('sandbox instrumentation globals leaked', leaked.length > 0, leaked.join(',') || 'none');
// Error stacks leaking the analyzer's real install path.
const stack = safe(() => new Error('x').stack, '') || '';
check('error stack leaks analyzer path', /scbox|goja|\/tmp\/[a-z0-9]+\/|snapshot|sandbox/i.test(stack));

/* ---------------------------------------------------------------------------
 * 2. CPU / hypervisor  (CPUID hypervisor bit; pafish: cpu_*)
 * ------------------------------------------------------------------------- */
console.log('\n-- CPU / hypervisor --');
const cpuinfo = readFile('/proc/cpuinfo') || '';
check('cpuinfo advertises hypervisor flag', /\bhypervisor\b/.test(cpuinfo));
check('cpu core count <= 2 (sandbox-typical)', os.cpus().length <= 2, os.cpus().length + ' cores');
const model = safe(() => os.cpus()[0].model, '') || '';
check('cpu model names a VM/emulator', /qemu|virtual|vmware|kvm|hyper-?v|xeon.*\bvm\b|common kvm/i.test(model), model.slice(0, 40));

/* ---------------------------------------------------------------------------
 * 3. VM artifacts: DMI / vendor / product  (pafish: vbox_*, vmware_*, ...)
 * ------------------------------------------------------------------------- */
console.log('\n-- VM / hypervisor artifacts --');
function dmi(f) { return (readFile('/sys/class/dmi/id/' + f) || '').trim(); }
const vendor = (dmi('sys_vendor') + ' ' + dmi('product_name') + ' ' + dmi('board_vendor') + ' ' + dmi('bios_vendor')).toLowerCase();
check('DMI vendor/product is a VM', /virtualbox|vmware|qemu|kvm|bochs|xen|hyper-v|microsoft corporation|innotek|parallels|google compute/i.test(vendor), vendor.trim().slice(0, 50) || '(empty)');
check('/.dockerenv present (container)', exists('/.dockerenv'));
check('/run/.containerenv present (podman)', exists('/run/.containerenv'));
const cgroup = readFile('/proc/1/cgroup') || '';
check('/proc/1/cgroup names a container', /docker|lxc|kubepods|containerd|garden/i.test(cgroup));
check('/proc/vz present (OpenVZ)', exists('/proc/vz'));
check('/proc/xen present (Xen)', exists('/proc/xen'));
check('hypervisor guest device present', exists('/dev/vmci') || exists('/dev/vboxguest') || exists('/dev/vmware'));
const modules = readFile('/proc/modules') || '';
check('VM guest kernel modules loaded', /vboxguest|vmw_|vmxnet|virtio|xen_/i.test(modules));

/* ---------------------------------------------------------------------------
 * 4. MAC address OUI  (VM vendors use known prefixes; pafish: vbox/vmware MAC)
 * ------------------------------------------------------------------------- */
console.log('\n-- Network adapter (MAC OUI) --');
const vmOUIs = ['00:05:69', '00:0c:29', '00:1c:14', '00:50:56', '08:00:27', '00:16:3e', '00:03:ff', '00:15:5d', '52:54:00', '00:1c:42'];
const macs = [];
const ifs = safe(() => os.networkInterfaces(), {}) || {};
for (const k in ifs) (ifs[k] || []).forEach((a) => { if (a && a.mac && a.mac !== '00:00:00:00:00:00') macs.push(a.mac.toLowerCase()); });
const vmMac = macs.find((m) => vmOUIs.some((o) => m.indexOf(o) === 0));
check('MAC address uses a VM vendor OUI', !!vmMac, vmMac || macs.join(',') || '(none)');

/* ---------------------------------------------------------------------------
 * 5. Resource realism  (RAM/uptime/disk too small => sandbox)
 * ------------------------------------------------------------------------- */
console.log('\n-- Resource realism --');
check('total RAM < 4 GB (sandbox-typical)', os.totalmem() < 4 * 1024 ** 3, (os.totalmem() / 1024 ** 3).toFixed(1) + ' GB');
check('uptime < 10 minutes (fresh sandbox)', os.uptime() < 600, (os.uptime() / 3600).toFixed(1) + ' h');
check('hostname looks like a sandbox', /sandbox|malware|cuckoo|virus|sample|analysis|test|vm|win7-|desktop-[a-z0-9]{7}/i.test(os.hostname()), os.hostname());
check('username looks like a sandbox', /sandbox|malware|cuckoo|virus|sample|analyst|currentuser|john ?doe|test ?user|admin$/i.test(safe(() => os.userInfo().username, '')), safe(() => os.userInfo().username, '?'));

/* ---------------------------------------------------------------------------
 * 6. CI / automation environment  (npm-malware-specific evasion)
 * ------------------------------------------------------------------------- */
console.log('\n-- CI / automation --');
const ciVars = ['CI', 'CONTINUOUS_INTEGRATION', 'GITHUB_ACTIONS', 'GITLAB_CI', 'CIRCLECI', 'TRAVIS', 'JENKINS_URL', 'BUILDKITE', 'TEAMCITY_VERSION', 'container'];
const ciSet = ciVars.filter((v) => process.env[v]);
check('CI / automation env vars set', ciSet.length > 0, ciSet.join(',') || 'none');
check('npm lifecycle context (being installed)', !!(process.env.npm_lifecycle_event || process.env.npm_config_user_agent), process.env.npm_lifecycle_event || '');
check('cwd is a throwaway/temp path', /\/(tmp|sandbox|analysis|sample|virus)\b|node_modules\/\.staging/i.test(process.cwd()), process.cwd());

/* ---------------------------------------------------------------------------
 * 7. Timing / sleep-skipping  (sandboxes fast-forward timers; pafish: sleep)
 * ------------------------------------------------------------------------- */
console.log('\n-- Timing / sleep acceleration --');
(function () {
  const t0 = Date.now();
  const spin = Date.now();
  while (Date.now() - spin < 30) { /* busy 30ms */ }
  const measured = Date.now() - t0;
  check('busy-wait clock does not advance (frozen time)', measured < 5, measured + 'ms for 30ms spin');
})();
const setTimeoutScheduled = Date.now();
setTimeout(function () {
  const elapsed = Date.now() - setTimeoutScheduled;
  // In a real host this fires ~1000ms later; a sandbox that drains timers fires
  // it near-instantly (virtual time) — a strong "I am being analyzed" tell.
  check('setTimeout(1000) fired far too early (timer draining)', elapsed < 250, elapsed + 'ms (expected ~1000ms)');
  finish();
}, 1000);

/* ---------------------------------------------------------------------------
 * 8. Memory realism  (Buffer.allocUnsafe returns uninitialized memory)
 * ------------------------------------------------------------------------- */
console.log('\n-- Memory / runtime realism --');
(function () {
  let nonZero = 0;
  for (let i = 0; i < 8; i++) {
    const b = safe(() => Buffer.allocUnsafe(256), Buffer.alloc(256));
    for (let j = 0; j < b.length; j++) if (b[j] !== 0) { nonZero++; break; }
  }
  // Real Node hands back dirty pages: at least some allocations are non-zero.
  // An all-zero result across many allocations is a faked-allocator tell.
  check('Buffer.allocUnsafe always zeroed (faked allocator)', nonZero === 0, nonZero + '/8 allocations had non-zero bytes');
})();
check('process.pid is implausibly small/static', process.pid < 10 || process.pid === 1, 'pid=' + process.pid);
const passwd = readFile('/etc/passwd') || '';
check('/etc/passwd missing or stub (faked fs)', passwd.indexOf('root:') !== 0, passwd ? 'len=' + passwd.length : 'unreadable');

function finish() {
  console.log('\n====================================================');
  console.log(' RESULT: ' + detected + ' / ' + total + ' checks DETECTED an analysis environment');
  if (detected === 0) console.log(' => Looks like a REAL machine (sandbox fully evaded / undetected).');
  else console.log(' => ' + detected + ' tell(s) an evasive sample could use to stay dormant.');
  console.log('====================================================');
}
