package sandbox

import (
	"path/filepath"
	"strings"

	"scbox/internal/third_party/goja"

	"scbox/internal/rules"
	"scbox/internal/trace"
)

// This file makes the fake environment look like an ordinary developer/CI Linux
// box so that evasive malware - which fingerprints its surroundings and refuses
// to run inside analysis sandboxes - detonates anyway. It is the inverse of the
// techniques catalogued at https://evasions.checkpoint.com/: every classic
// "am I in a sandbox?" probe is answered the way a real machine would answer.

// The host identity (hostProfile / defaultProfile) is defined in profile.go,
// where it is randomized per run so the analyzer can't be fingerprinted by
// constant values. This file consumes r.profile to render believable file
// contents and directory listings.

// sandboxArtifactTokens are path fragments whose mere existence would betray an
// analysis VM/container. existsSync returns false for any of these.
var sandboxArtifactTokens = []string{
	"/.dockerenv", "/.dockerinit", "/run/.containerenv", "/proc/vz", "/proc/xen",
	"/proc/scsi/scsi", "vboxguest", "vboxsf", "vmci", "vmmemctl", "vmxnet", "virtio",
	"qemu", "virtualbox", "xen_", "parallels", "vmware", "/dev/vmware",
	"/sys/class/dmi/id/product_uuid", "cuckoo", "sandbox", "/usr/bin/wireshark",
	"/usr/bin/qemu-ga", "/dev/vboxguest", "frida", "/tmp/analysis",
}

// DefaultVirtualRoot is the believable on-disk path the analyzed package is
// presented as living at (its __dirname, process.cwd, lifecycle cwd, …). The
// in-memory FS is rooted here so the path the sample observes matches the host
// profile; kept in lockstep with Config.VirtualBase's default.
func DefaultVirtualRoot() string {
	return defaultProfile().Homedir + "/projects/web-app"
}

// looksLikeSandboxArtifact reports whether a path is a known VM/sandbox tell.
func looksLikeSandboxArtifact(p string) bool {
	lp := strings.ToLower(p)
	for _, t := range sandboxArtifactTokens {
		if strings.Contains(lp, t) {
			return true
		}
	}
	return false
}

// dropTargetDirs are the world-writable staging locations a download-and-execute
// dropper writes its fetched stage into. On a fresh victim these files do NOT yet
// exist, so an existence probe of the dropper's own target must read false - else
// a guard like `if (fs.existsSync('/var/tmp/launcher.sh')) return;` makes the
// payload conclude it already ran and skip the download (a false negative). We
// only deny existence for the dropper's OWN unwritten target here; real system
// binaries the malware legitimately uses (node, /bin/sh) keep reading as present.
var dropTargetDirs = []string{
	"/tmp/", "/var/tmp/", "/dev/shm/", "/private/var/folders/", "/private/tmp/",
	"\\temp\\", "\\tmp\\", "/appdata/local/temp/", "\\appdata\\local\\temp\\",
	"/library/caches/", "/.cache/", "/users/public/", "\\users\\public\\",
}

// looksLikeDropTarget reports whether p is under a temp/staging directory where a
// dropper stages its downloaded payload. Used (only for paths NOT in the vfs) to
// answer an existence probe the way a clean machine would: the file isn't there
// yet, so the download proceeds and detonates.
func looksLikeDropTarget(p string) bool {
	lp := strings.ToLower(filepath.ToSlash(p))
	for _, d := range dropTargetDirs {
		if strings.Contains(lp, strings.ReplaceAll(d, "\\", "/")) {
			return true
		}
	}
	return false
}

// readFake decides what a file read should return. Sandbox/VM artifacts report
// as non-existent (like a real machine); everything else returns believable,
// non-empty content - because malware that reads a file and finds it empty or
// missing concludes it's in a sandbox and bails.
func (r *Runtime) readFake(path string) (content string, notExist bool) {
	// Custom taint rules may override the served content with their own bait, so a
	// rule author controls exactly what value to track flowing out.
	if bait, ok := rules.FileBait(r.tr.TaintRules(), path); ok {
		r.vfsWrite(path, bait, false) // read-back consistency for any later read of the same path
		content = bait
	} else {
		content, notExist = r.readFakeContent(path)
	}
	// Taint: if this is a credential/secret file, watch the content we just handed
	// back so the verdict can tell whether it actually reached a network sink (real
	// exfil) rather than being read and dropped. Keyed on the value, this catches
	// base64/hex-disguised egress and never fires on an incidental read.
	if !notExist && (trace.IsSensitivePath(path) || trace.IsInfostealerPath(path)) {
		r.tr.WatchSecret(content)
	}
	// User-defined file taint sources: watch the served content under each
	// matching rule so the verdict can check it against that rule's sinks.
	if !notExist {
		for _, rl := range r.tr.TaintRules() {
			if rl.MatchesFile(path) {
				r.tr.WatchTaint(rl.Name, content)
			}
		}
	}
	return content, notExist
}

func (r *Runtime) readFakeContent(path string) (content string, notExist bool) {
	// Anything the sample wrote this run reads back exactly (consistency check).
	if c, ok := r.vfsRead(path); ok {
		return c, false
	}
	if looksLikeSandboxArtifact(path) {
		return "", true
	}
	if c, ok := r.fakeFileContent(path); ok {
		return c, false
	}
	return r.genericFileContent(path), false
}

// hasSuf is true if path ends with any of the given suffixes.
func hasSuf(path string, suffixes ...string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(path, s) {
			return true
		}
	}
	return false
}

// fakeFileContent returns believable Arch Linux contents for the system files,
// dotfiles, and credential files malware reads to fingerprint the host or steal
// secrets. Credential files return realistic *bait* so the sample proceeds and
// exfiltrates values we then capture. Returns ("", false) if uncurated.
func (r *Runtime) fakeFileContent(p string) (string, bool) {
	prof := r.profile
	u := prof.Username
	switch {
	// ---- OS / hardware fingerprint ----
	case hasSuf(p, "/etc/os-release", "/usr/lib/os-release"):
		return "NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\nANSI_COLOR=\"38;2;23;147;209\"\nHOME_URL=\"https://archlinux.org/\"\nDOCUMENTATION_URL=\"https://wiki.archlinux.org/\"\nSUPPORT_URL=\"https://bbs.archlinux.org/\"\nBUG_REPORT_URL=\"https://gitlab.archlinux.org/groups/archlinux/-/issues\"\nLOGO=archlinux-logo\n", true
	case hasSuf(p, "/etc/lsb-release"):
		return "LSB_VERSION=1.4\nDISTRIB_ID=Arch\nDISTRIB_RELEASE=rolling\nDISTRIB_DESCRIPTION=\"Arch Linux\"\n", true
	case hasSuf(p, "/etc/arch-release"):
		return "", true // genuinely empty on Arch; existence is the point
	case hasSuf(p, "/proc/version"):
		return "Linux version 6.12.8-arch1-1 (linux@archlinux) (gcc (GCC) 14.2.1 20240910, GNU ld (GNU Binutils) 2.43.0) #1 SMP PREEMPT_DYNAMIC Fri, 17 Jan 2025 18:01:36 +0000\n", true
	case hasSuf(p, "/proc/cpuinfo"):
		c := prof.CPU
		var b strings.Builder
		for i := 0; i < c.Threads; i++ {
			b.WriteString("processor\t: " + itoa(i))
			b.WriteString("\nvendor_id\t: " + c.VendorID +
				"\ncpu family\t: " + itoa(c.Family) +
				"\nmodel\t\t: " + itoa(c.ModelNum) +
				"\nmodel name\t: " + c.Model +
				"\nstepping\t: 0\ncpu MHz\t\t: " + c.MHz +
				"\ncache size\t: " + itoa(c.CacheKB) + " KB\nphysical id\t: 0\nsiblings\t: " + itoa(c.Threads) +
				"\ncore id\t\t: " + itoa(i/2) + "\ncpu cores\t: " + itoa(c.Cores) +
				"\nflags\t\t: " + c.Flags +
				"\nbogomips\t: " + c.Bogo + "\n\n")
		}
		return b.String(), true
	case hasSuf(p, "/proc/meminfo"):
		totalKB := prof.TotalMem / 1024
		free := totalKB * 56 / 100
		avail := totalKB * 76 / 100
		return "MemTotal:       " + itoa(int(totalKB)) + " kB\nMemFree:        " + itoa(int(free)) +
			" kB\nMemAvailable:   " + itoa(int(avail)) + " kB\nBuffers:          512440 kB\nCached:          6021884 kB\nSwapTotal:       8388604 kB\nSwapFree:        8388604 kB\n", true
	case hasSuf(p, "/proc/uptime"):
		return "862344.21 13284551.77\n", true
	case hasSuf(p, "/proc/loadavg"):
		return "0.42 0.31 0.28 2/812 14233\n", true
	case hasSuf(p, "/proc/self/cgroup"):
		return "0::/user.slice/user-1000.slice/session-2.scope\n", true
	case hasSuf(p, "/proc/self/environ"):
		// NUL-separated, like the real file.
		var b strings.Builder
		for k, v := range r.baitEnv() {
			b.WriteString(k + "=" + v)
			b.WriteByte(0)
		}
		return b.String(), true
	case hasSuf(p, "/proc/self/cmdline"):
		return "node\x00" + r.cfg.VirtualBase + "/index.js\x00", true
	case hasSuf(p, "/proc/self/status"):
		return "Name:\tnode\nState:\tR (running)\nPid:\t" + itoa(prof.PID) + "\nPPid:\t" + itoa(prof.PPID) + "\nVmRSS:\t  124800 kB\nThreads:\t11\n", true
	case hasSuf(p, "/proc/mounts", "/proc/self/mounts", "/etc/mtab"):
		return "/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n/dev/nvme0n1p1 /boot vfat rw,relatime 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n", true
	case hasSuf(p, "/etc/hostname"):
		return prof.Hostname + "\n", true
	case hasSuf(p, "/etc/hosts"):
		return "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 " + prof.Hostname + "\n", true
	case hasSuf(p, "/etc/resolv.conf"):
		return "# Generated by NetworkManager\nnameserver " + prof.Gateway + "\nnameserver 1.1.1.1\n", true
	case hasSuf(p, "/etc/machine-id", "/var/lib/dbus/machine-id"):
		return prof.MachineID + "\n", true
	case hasSuf(p, "/sys/class/dmi/id/product_name"):
		return prof.ProductName + "\n", true
	case hasSuf(p, "/sys/class/dmi/id/sys_vendor"):
		return prof.SysVendor + "\n", true
	case hasSuf(p, "/sys/class/dmi/id/board_name"):
		return prof.BoardName + "\n", true
	case hasSuf(p, "/sys/class/dmi/id/product_uuid"):
		return prof.ProductUUID + "\n", true
	case hasSuf(p, "/sys/class/dmi/id/bios_vendor"):
		return prof.BiosVendor + "\n", true

	// ---- /etc/passwd : realistic Arch user table ----
	case hasSuf(p, "/etc/passwd"):
		return "root:x:0:0::/root:/usr/bin/bash\nbin:x:1:1::/:/usr/bin/nologin\ndaemon:x:2:2::/:/usr/bin/nologin\nmail:x:8:12::/var/spool/mail:/usr/bin/nologin\nftp:x:14:11::/srv/ftp:/usr/bin/nologin\nhttp:x:33:33::/srv/http:/usr/bin/nologin\nnobody:x:65534:65534:Nobody:/:/usr/bin/nologin\ndbus:x:81:81:System Message Bus:/:/usr/bin/nologin\nsystemd-network:x:998:998:systemd Network Management:/:/usr/bin/nologin\npolkitd:x:102:102:PolicyKit daemon:/:/usr/bin/nologin\n" + u + ":x:1000:1000:" + u + ":/home/" + u + ":/usr/bin/zsh\n", true
	case hasSuf(p, "/etc/shadow"):
		// Readable only by root; return a believable line so length checks pass.
		return "root:!*:19000::::::\n" + u + ":$6$" + "Qx7kP2mN$" + "9fABCdef0123456789abcdefGHIJKLmnopqrstuvwxyz0123456789ABCDEF.:19876:0:99999:7:::\n", true

	// ---- shell / dev dotfiles ----
	case hasSuf(p, "/.bashrc", "/.zshrc", "/.profile", "/.bash_profile"):
		return "# ~/." + "rc\n[[ $- != *i* ]] && return\nalias ls='ls --color=auto'\nalias grep='grep --color=auto'\nexport EDITOR=nvim\nexport PATH=\"$HOME/.local/bin:$HOME/.npm-global/bin:$PATH\"\neval \"$(starship init bash)\"\n", true
	case hasSuf(p, "/.bash_history", "/.zsh_history", "/.history"):
		return "cd ~/projects/web-app\nnpm install\ngit status\nnpm run dev\nsudo pacman -Syu\ngit commit -m \"fix auth\"\nssh deploy@prod\ndocker compose up -d\nnpm publish\nkubectl get pods\n", true
	case hasSuf(p, "/.python_history"):
		return "import os\nos.getcwd()\nimport requests\nrequests.get('https://api.internal')\nexit()\n", true
	case hasSuf(p, "/.node_repl_history"):
		return "const fs = require('fs')\nprocess.env.HOME\n.exit\n", true
	case hasSuf(p, "/.viminfo"):
		return "# This viminfo file was generated by Vim 9.1.\n*encoding=utf-8\n", true
	case hasSuf(p, "/.gitconfig"):
		return "[user]\n\tname = " + u + "\n\temail = " + u + "@gmail.com\n[init]\n\tdefaultBranch = main\n[pull]\n\trebase = true\n[credential]\n\thelper = store\n", true
	case hasSuf(p, "/.git-credentials"):
		return "https://" + u + ":" + prof.Bait.GitHubToken + "@github.com\n", true

	// ---- credential files (realistic, randomized bait) ----
	case hasSuf(p, "/.npmrc"):
		return "//registry.npmjs.org/:_authToken=" + prof.Bait.NPMToken + "\nregistry=https://registry.npmjs.org/\n", true
	case hasSuf(p, "/.aws/credentials"):
		return "[default]\naws_access_key_id = " + prof.Bait.AWSKeyID + "\naws_secret_access_key = " + prof.Bait.AWSSecret + "\n", true
	case hasSuf(p, "/.aws/config"):
		return "[default]\nregion = us-east-1\noutput = json\n[profile prod]\nregion = us-west-2\n", true
	case hasSuf(p, "/.ssh/id_rsa", "/.ssh/id_dsa"):
		return prof.Bait.SSHRSA, true
	case hasSuf(p, "/.ssh/id_ed25519"):
		return prof.Bait.SSHED25519, true
	case hasSuf(p, "/.ssh/id_rsa.pub", "/.ssh/id_ed25519.pub"):
		return prof.Bait.SSHPub + " " + u + "@" + prof.Hostname + "\n", true
	case hasSuf(p, "/.ssh/config"):
		return "Host github.com\n\tUser git\n\tIdentityFile ~/.ssh/id_ed25519\nHost prod\n\tHostName 203.0.113.27\n\tUser deploy\n", true
	case hasSuf(p, "/.ssh/known_hosts"):
		return "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n", true
	case hasSuf(p, "/.netrc"):
		return "machine github.com login " + u + " password " + prof.Bait.GitHubToken + "\n", true
	case hasSuf(p, "/.docker/config.json"):
		return "{\n  \"auths\": {\n    \"https://index.docker.io/v1/\": {\n      \"auth\": \"" + prof.Bait.DockerAuth + "\"\n    }\n  }\n}\n", true
	case hasSuf(p, "/.kube/config"):
		return "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n  name: prod\nusers:\n- name: " + u + "\n  user:\n    token: " + prof.Bait.KubeToken + "\n", true
	case hasSuf(p, "/.env", "/.env.local", "/.env.production"):
		return "NODE_ENV=production\nDATABASE_URL=postgres://app:" + prof.Bait.DBPass + "@db.internal:5432/app\nSTRIPE_SECRET_KEY=" + prof.Bait.StripeKey + "\nJWT_SECRET=" + prof.Bait.JWTSecret + "\nWALLET_PRIVATE_KEY=0x" + prof.Bait.WalletKey + "\nMNEMONIC=\"" + prof.Bait.Mnemonic + "\"\n", true
	case hasSuf(p, "/.gnupg/secring.gpg", "/.pgpass"):
		return "db.internal:5432:app:app:" + prof.Bait.DBPass + "\n", true
	}
	return "", false
}

// fakeDirListing returns a believable directory listing - an empty readdir (our
// old behavior) on a home or project dir is a strong sandbox tell. Paths here
// are the believable virtual paths the sample sees.
func (r *Runtime) fakeDirListing(p string) []interface{} {
	p = strings.TrimRight(p, "/")
	strs := func(names ...string) []interface{} {
		out := make([]interface{}, len(names))
		for i, n := range names {
			out[i] = n
		}
		return out
	}
	switch {
	case p == r.profile.Homedir:
		return strs(".bashrc", ".bash_history", ".bash_profile", ".zshrc", ".zsh_history", ".profile",
			".config", ".cache", ".local", ".ssh", ".gnupg", ".npmrc", ".npm", ".gitconfig", ".git-credentials",
			".aws", ".docker", ".kube", ".mozilla", ".pki", ".vscode", "projects", "Downloads", "Documents", "Desktop", "Pictures", ".Xauthority")
	case hasSuf(p, "/.ssh"):
		return strs("id_rsa", "id_rsa.pub", "id_ed25519", "id_ed25519.pub", "known_hosts", "config", "authorized_keys")
	case hasSuf(p, "/.aws"):
		return strs("credentials", "config")
	case hasSuf(p, "/.config"):
		return strs("gcloud", "gh", "nvim", "systemd", "Code", "discord")
	case r.cfg.VirtualBase != "" && strings.HasPrefix(p, r.cfg.VirtualBase):
		return strs("package.json", "package-lock.json", "index.js", "README.md", "tsconfig.json",
			".gitignore", ".git", "node_modules", "src", "dist", "test")
	case p == "/tmp":
		return strs(".X11-unix", ".ICE-unix", "systemd-private-8f3c2a1b", "ssh-XnQ2k9")
	case p == "/":
		return strs("bin", "boot", "dev", "etc", "home", "lib", "lib64", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var")
	case p == "/etc":
		return strs("passwd", "group", "hosts", "hostname", "os-release", "resolv.conf", "fstab", "ssh", "pacman.conf", "systemd")
	default:
		return strs("data", "config.json", "index.js")
	}
}

// genericFileContent returns plausible, non-empty content for an uncurated path
// so length/emptiness checks (a common sandbox tell) pass.
func (r *Runtime) genericFileContent(p string) string {
	switch {
	case hasSuf(p, ".json"):
		return "{\n  \"name\": \"app\",\n  \"version\": \"1.0.0\"\n}\n"
	case hasSuf(p, ".yaml", ".yml"):
		return "version: \"3\"\nservices: {}\n"
	case hasSuf(p, ".ini", ".conf", ".cfg", ".toml"):
		return "# configuration\n[default]\nenabled = true\n"
	case hasSuf(p, ".log"):
		return "[2025-05-29T16:30:01Z] INFO startup complete\n"
	default:
		return "# " + r.profile.Username + "\n"
	}
}

// itoa is a tiny base-10 int formatter avoiding an strconv import here.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// installAntiEvasion wires the virtual clock and native-code masking that defeat
// timing- and hook-detection probes. The believable identity is applied in the
// os/process/fs builtins via r.profile.
func (r *Runtime) installAntiEvasion() {
	// Virtual clock: Date.now()/performance.now() return real time plus an
	// offset that advances as timers "elapse" (see DrainTimers). This defeats
	// "did N ms actually pass?" sandbox checks even though we don't really wait.
	// Each observation of the clock advances virtual time by a small tick. This
	// defeats busy-wait sleeps (`while (Date.now() - t < 600000) {}`) used to
	// outlast analysis: the loop's own polling races the clock forward, so it
	// exits in a few thousand iterations instead of spinning past our timeout.
	const clockTickMs = 5
	must(r.vm.Set("__clock_offset", r.fn(func(call goja.FunctionCall) goja.Value {
		r.clockOffsetMs += clockTickMs
		return r.vm.ToValue(r.clockOffsetMs)
	})))

	const js = `(function(){
    var _off = globalThis.__clock_offset;  // captured before the global is deleted
    // Virtual clock.
    var realNow = Date.now;
    Date.now = function(){ return realNow() + _off(); };
    if (typeof performance === 'undefined') { globalThis.performance = {}; }
    var perfStart = realNow();
    globalThis.performance.now = function(){ return (realNow() - perfStart) + _off(); };

    // Native-code masking: many packers call fn.toString() and bail if a core
    // API is not "[native code]" (i.e. has been hooked). Make our stubs report
    // native source. Real JS functions keep their true source.
    var realToString = Function.prototype.toString;
    var nativeRe = /\{\s*\[native code\]\s*\}/;
    var identRe = /^[A-Za-z_$][\w$]*$/;
    // Core globals we wrap in JS (eval, the Function constructor, …) keep their
    // JS source unless we force them: a packer doing /\[native code\]/.test(
    // eval.toString()) would otherwise see our wrapper body and know it's hooked.
    // Match by identity so the genuine builtins always render as native.
    var forceNative = [];
    try { forceNative.push(globalThis.eval); } catch (e) {}
    try { forceNative.push(globalThis.Function); } catch (e) {}
    try { forceNative.push(globalThis.Function.prototype.constructor); } catch (e) {}
    var nativeName = function(self){
      for (var i = 0; i < forceNative.length; i++) {
        if (self === forceNative[i]) {
          return (self === globalThis.Function) ? 'Function' : (self === globalThis.eval ? 'eval' : '');
        }
      }
      return null;
    };
    Function.prototype.toString = function(){
      try {
        var forced = nativeName(this);
        if (forced !== null) return 'function ' + forced + '() { [native code] }';
        var s = realToString.call(this);
        // goja renders a Go-backed native func as
        //   "function scbox/internal/sandbox.(*Runtime).fuzzArgs.func1() { [native code] }"
        // i.e. it already contains "[native code]" but leaks the Go symbol path.
        // So we can't trust the rendering when it's native: ALWAYS rebuild it
        // from a sanitized, identifier-only name. A real JS function (with a
        // genuine "{ ... }" body and no native marker) is returned untouched -
        // unless it somehow carries the sandbox path, in which case we scrub it.
        var isNative = nativeRe.test(s) || s.indexOf('{') === -1;
        var leaksPath = s.indexOf('scbox') !== -1 || s.indexOf('goja') !== -1 || s.indexOf('(*') !== -1;
        if (isNative || leaksPath) {
          var nm = (this && typeof this.name === 'string') ? this.name : '';
          if (!identRe.test(nm)) nm = '';
          return 'function ' + nm + '() { [native code] }';
        }
        return s;
      } catch (e) {
        return 'function () { [native code] }';
      }
    };

    // Virtual-clock Date: new Date() with no args must observe the same advancing
    // virtual time as Date.now(). Otherwise a sample cross-checks (Date.now()
    // advances under the virtual clock while new Date().getTime() reads real,
    // frozen-looking time) or busy-waits on "new Date() - t0 < N" to outlast
    // analysis - the array clocks below have the same requirement. Wrap the
    // constructor so the zero-arg form is offset by the virtual clock (and its
    // _off() call races the busy-wait forward); every other form passes through.
    (function(){
      var RealDate = Date;
      function FakeDate(a, b, c, d, e, f, g){
        if (!(this instanceof FakeDate)) return RealDate();
        switch (arguments.length) {
          case 0:  return new RealDate(realNow() + _off());
          case 1:  return new RealDate(a);
          case 2:  return new RealDate(a, b);
          case 3:  return new RealDate(a, b, c);
          case 4:  return new RealDate(a, b, c, d);
          case 5:  return new RealDate(a, b, c, d, e);
          case 6:  return new RealDate(a, b, c, d, e, f);
          default: return new RealDate(a, b, c, d, e, f, g);
        }
      }
      FakeDate.prototype = RealDate.prototype;
      FakeDate.now = RealDate.now;       // already virtual (patched above)
      FakeDate.parse = RealDate.parse;
      FakeDate.UTC = RealDate.UTC;
      try { globalThis.Date = FakeDate; } catch (e) {}
    })();

    // Virtual-clock process.hrtime(): the array form must advance like Date.now,
    // or it is both a constant-value sandbox tell (two calls return the identical
    // [12345, 678900000]) and a busy-wait that never exits ("while
    // (process.hrtime(t)[0] < N){}" spins to the per-call timeout). Base it on the
    // same virtual clock; _off() ticks it forward on every read so a hrtime
    // busy-wait races to its deadline in a few thousand iterations. The diff form
    // process.hrtime(prev) returns elapsed since prev, as Node does.
    try {
      if (globalThis.process && typeof process.hrtime === 'function') {
        var hrNowNs = function(){ return Math.floor((realNow() + _off()) * 1e6); };
        var prevBigint = process.hrtime.bigint;
        var hrtime = function(prev){
          var ns = hrNowNs();
          var sec = Math.floor(ns / 1e9), nano = ns % 1e9;
          if (prev && prev.length === 2) {
            var ds = sec - prev[0], dn = nano - prev[1];
            if (dn < 0) { ds -= 1; dn += 1e9; }
            return [ds, dn];
          }
          return [sec, nano];
        };
        if (typeof prevBigint === 'function') hrtime.bigint = prevBigint;
        process.hrtime = hrtime;
      }
    } catch (e) {}
  })();`
	if _, err := r.vm.RunString(js); err != nil {
		panic("sandbox: anti-evasion failed: " + err.Error())
	}
}
