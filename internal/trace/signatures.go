package trace

import (
	"regexp"
	"sort"
	"strings"
)

// reObfHexIdent matches javascript-obfuscator's generated `_0x`-hex identifiers.
// reObfArrayRotate matches its string-array rotation cradle - the self-decoding
// loop `arr['push'](arr['shift']())` / `arr.push(arr.shift())` that aligns the
// encrypted string table before first use. reObfTrueIdiom matches the `!![]`
// boolean-coercion idiom the tool emits as the rotation-loop guard `while(!![])`;
// it survives even when the 'push'/'shift' member names are themselves split
// ('p'+'u'+'s'+'h') or bracket-index-encoded to dodge a literal match. Normal
// minifiers emit `!0`/`!1`, never `!![]`, so paired with hex-ident density it is
// highly specific.
var (
	reObfHexIdent    = regexp.MustCompile(`_0x[0-9a-fA-F]{4,8}`)
	reObfArrayRotate = regexp.MustCompile(`\[\s*['"]push['"]\s*\][^;{}]*\[\s*['"]shift['"]\s*\]|\.push\(\s*[\w$]+\.shift\(\)\s*\)`)
	reObfTrueIdiom   = regexp.MustCompile(`!!\[\]`)
	// The base64 alphabet literal embedded in the string-array decoder (either
	// case-order javascript-obfuscator emits).
	reObfB64Alphabet = regexp.MustCompile(`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789|abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`)
	// The RC4 key-schedule the decoder runs: the three-way array-element swap
	// `…[…]=…[…],…[…]=…` (state[i],state[j] exchange) that is the heart of RC4 /
	// Fisher-Yates. Requiring the swap - not merely `%256`+charCodeAt, which any
	// text codec or CSV parser has - keeps this specific to the obfuscator's cipher
	// and off legitimate parsers (csv-parse, papaparse).
	reObfRC4KSA = regexp.MustCompile(`[\w$]+\[[\w$]+\]\s*=\s*[\w$]+\[[\w$]+\]\s*,\s*[\w$]+\[[\w$]+\]\s*=`)
)

// IsObfuscatorLoader reports whether src is `javascript-obfuscator` output. In
// PUBLISHED npm package source that structure is an almost-exclusive marker of a
// skimmer / DPRK second-stage loader - legitimate packages ship readable or
// merely-minified code, not RC4 string-array-obfuscated code. Detecting it from
// the inert source catches DORMANT loaders whose payload is gated behind a
// runtime argument or environment condition and so never fires under detonation
// (animatecss-postcss-plugin's plugin body, a loader parked in a non-executed
// test.js), which a behavior-only verdict misses entirely.
//
// Detection anchors on the `_0x`-hex identifier density (the default
// identifierNamesGenerator), tiered so it resists member-name splitting:
//   - a very high density is conclusive on its own (the rotation cradle may be
//     fully string-split, but thousands of `_0x` names cannot be hidden); and
//   - a moderate density plus a structural marker that survives string-splitting
//     - the `!![]` loop guard or the push/shift shuffle in any spacing.
func IsObfuscatorLoader(src string) bool {
	seen := map[string]struct{}{}
	for _, m := range reObfHexIdent.FindAllString(src, -1) {
		seen[m] = struct{}{}
		if len(seen) >= 24 {
			break // conclusive density reached; stop counting
		}
	}
	hex := len(seen)
	if hex >= 24 { // unmistakable `_0x`-name density (ultra-base64-math profile)
		return true
	}
	// The string-array ROTATION CRADLE is the required anchor: the self-decoding
	// `arr.push(arr.shift())` shuffle that aligns the encrypted table. It is the one
	// structure benign code essentially never contains - unlike RC4 or a base64
	// alphabet, which real crypto/codec libraries (node-forge, crypto-js, csv-parse)
	// legitimately ship and which therefore must NOT flag on their own. The cradle
	// plus any obfuscation corroborator (a few `_0x` names, the `!![]` guard, the
	// base64 alphabet, or the RC4 element-swap) is the animatecss-postcss-plugin
	// profile: only a handful of `_0x` names but the full rotate-and-decode machinery.
	if reObfArrayRotate.MatchString(src) &&
		(hex >= 3 || reObfTrueIdiom.MatchString(src) ||
			reObfB64Alphabet.MatchString(src) || reObfRC4KSA.MatchString(src)) {
		return true
	}
	return false
}

// sensitiveEnv and sensitivePath are tokens whose access by an install-time
// script is a strong signal of credential/secret theft.
var sensitiveEnv = []string{
	"NPM_TOKEN", "AWS_", "GITHUB_TOKEN", "GH_TOKEN", "SSH", "SECRET",
	"PASSWORD", "PRIVATE_KEY", "API_KEY", "ACCESS_KEY", "DOCKER", "GCP", "AZURE",
	// crypto wallet seed/key material - the primary target of wallet drainers.
	"MNEMONIC", "SEED_PHRASE", "SEEDPHRASE", "RECOVERY_PHRASE", "PRIVATE_KEYS",
}
var sensitivePath = []string{
	"/etc/passwd", "/etc/shadow", ".ssh", ".npmrc", ".aws", ".docker",
	"id_rsa", ".bash_history", "credentials", "wallet", "keychain", // .env handled by reDotenv (boundary-aware)
	// Cloud / CI / VCS credential files. Unlike the browser/wallet stores below,
	// these DO have a legitimate reader - the matching cloud SDK or CLI loads them
	// as a matter of course (e.g. google-auth-library reads
	// ~/.config/gcloud/application_default_credentials.json). So reading one is only
	// the SENSITIVE tier (scored when correlated with egress), not the uncorrelated
	// infostealer tier; their actual theft is caught by value-taint when the content
	// reaches an external sink.
	".config/gcloud", ".kube/config", ".git-credentials", "/.netrc", ".config/gh/hosts",
	".azure/", ".config/doctl", ".terraform.d", ".pgpass", ".my.cnf",
}

// infostealerPaths are credential/secret stores that a published npm package has
// essentially NO legitimate reason to read at runtime: browser login/cookie
// databases, crypto-wallet (browser-extension and desktop) storage, and password
// managers. Reading any of these is a near-certain infostealer (ATT&CK T1555
// Credentials from Password Stores, T1539 Steal Web Session Cookie), so it scores
// UNCORRELATED - these strings are specific enough (full app/browser-profile paths
// and wallet extension IDs) that benign packages don't match them. (Cloud/CI
// credential files live in sensitivePath instead: those have legitimate SDK
// readers, so they are scored correlated, not uncorrelated.)
var infostealerPaths = []string{
	// browser credential / cookie / autofill stores
	"/google/chrome/", "/chromium/", "/microsoft/edge/", "/bravesoftware/", "/brave-browser/",
	"/mozilla/firefox/", "/.mozilla/", "/opera software/", "/vivaldi/", "/yandex/",
	"login data", "cookies.sqlite", "/cookies", "web data", "logins.json", "key4.db", "key3.db",
	"signons.sqlite", "local state", "formhistory.sqlite",
	// crypto-wallet browser extensions (MetaMask, Phantom, Coinbase, Binance, TronLink, …)
	"nkbihfbeogaeaoehlefnkodbefgpgknn", "ejbalbakoplchlghecdalmeeeajnimhm", // MetaMask
	"bfnaelmomeimhlpmgjnjophhpkkoljpa", "fhbohimaelbohpjbbldcngcnapndodjp", // Phantom, Binance
	"hnfanknocfeofbddgcijnmhnfnkdnaad", "ibnejdfjmmkpcnlpebklmnkoeoihofec", // Coinbase, TronLink
	"acmacodkjbdgmoleebolmdjonilkdbch", "mcohilncbfahbmgdjkbpemcciiolgcge", // Rabby, OKX
	"dmkamcknogkgcdfhhbddcghachkejeap", "egjidjbpglichdcondbcbdnbeeppgdph", // Keplr, Trust
	"aholpfdialjgjfhomihkjbmgjidlcdno", "bhhhlbepdkbapadjdnnojkbgioiodbic", // Exodus ext, Solflare
	"aflkmfhebedbjioipglgcbcmnbpgliof", "mfgccjchihfkkindfppnaooecgfneiii", // Backpack, TokenPocket
	"hmeobnfnfcmdkdcmlblgagmfpfboieaf", "aeachknmefphepccionboohckonoeemg", // XDEFI, Coin98
	"ejjladinnckdgjemekebdpeokbikhfci", "efbglgofoippbgcjepnhiblaibcnclgk", // Petra, Martian (Aptos)
	"local extension settings", "indexeddb",
	// desktop & developer crypto wallets / keystores
	"wallet.dat", "/exodus/", "/electrum/", "/atomic/", "/ledger live/", "/coinomi/",
	"/monero/", "/bitcoin/wallets", "/.ethereum/keystore", "keystore/utc--",
	"/.config/solana/", "/solana/id.json", "/.foundry/keystore", "/.wasabiwallet/",
	"/.config/sparrow/", "/trezor suite/", "/@trezor/", "/daedalus mainnet/",
	// password managers / keychains
	"login.keychain", "keychain-db", "/keyrings/",
	// raw input devices (keylogging): reading these captures keystrokes - no
	// legitimate published-package use (ATT&CK T1056.001).
	"/dev/input/event", "/dev/input/by-", "/dev/hidraw",
	// messaging-app session stores (Telegram/Signal/Discord token theft)
	"/telegram desktop/", "/discord/local storage/", "/signal/sql/", "/tdata/",
	// cloud-native / orchestrator credentials with no benign package-read use:
	// the Kubernetes service-account token and the Docker daemon socket (container
	// escape / lateral movement), and cloud SA key material.
	"/var/run/secrets/kubernetes.io", "/run/secrets/kubernetes.io",
	"/var/run/docker.sock", "/run/docker.sock",
}

// systemTamperPaths are critical system/auth/name-resolution config files. A
// published npm package writing to one is tampering (traffic redirection via
// /etc/hosts or resolv.conf, an auth backdoor via sudoers/pam, DNS hijack), with
// no benign install use. (Persistence/autostart writes live in persistencePaths.)
var systemTamperPaths = []string{
	"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/sudoers",
	"/etc/pam.d", "/etc/environment", "/etc/ssh/sshd_config", "/etc/ld.so.conf",
	"/etc/security/", "/etc/sysctl", "/etc/sudoers.d",
}

// IsSystemTamperPath reports whether a write targets a critical system/auth/DNS
// config file (no benign package use).
func IsSystemTamperPath(p string) bool { return containsAnyFold(p, systemTamperPaths) }

// IsInfostealerPath reports whether a read targets a browser/wallet/credential
// store with no legitimate package use (scored uncorrelated).
func IsInfostealerPath(p string) bool {
	return containsAnyFold(p, infostealerPaths)
}

// officialRegistryHosts are the package-registry hosts a legitimate .npmrc/.yarnrc
// points at; a registry directive to anything else (esp. a raw IP / http://) that a
// package writes at runtime is a registry hijack.
var officialRegistryHosts = []string{
	"registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com",
	"registry.npmmirror.com", ".jfrog.io", ".pkg.dev", ".visualstudio.com",
	"npm.fontawesome.com", "registry.bower.io",
}

// IsRegistryHijack reports whether an .npmrc/.yarnrc content sets the package
// registry to a non-official host (all future installs would flow through it).
func IsRegistryHijack(content string) (string, bool) {
	for _, m := range reRegistryDirective.FindAllStringSubmatch(content, -1) {
		host := strings.ToLower(hostFromURL(m[1]))
		official := false
		for _, h := range officialRegistryHosts {
			if host == h || strings.HasSuffix(host, h) {
				official = true
				break
			}
		}
		if !official {
			return m[1], true
		}
	}
	return "", false
}

// reGithubPayloadFetch matches GitHub URLs used to HOST or FETCH a payload - raw
// file content, or a repo's file contents / git blobs / source archive. That is
// the actual abuse pattern (a stager pulling its next stage from a repo). A
// GENERIC GitHub API call - e.g. api.github.com/repos/{n}/{n}, /user, release
// metadata - is deliberately NOT matched, so legitimate API use (or a fuzzer that
// synthesizes such URLs during force-execution) isn't flagged. This keys on the
// behavior, not the host: a compromised package fetching a stage from GitHub is
// still caught no matter which package it is.
var reGithubPayloadFetch = regexp.MustCompile(`(?i)(?:raw\.githubusercontent\.com/|api\.github\.com/repos/[^/]+/[^/]+/(?:contents|git/blobs|tarball|zipball))`)

// isAbusedEndpoint reports whether a URL on an otherwise-benign host is a known
// exfil/C2 drop-site or webhook (gist raw, discord/telegram/slack webhooks, paste
// raw, GitHub payload fetch, …). Used so the IOC scanner keeps these instead of
// dropping them with the rest of the host's (legitimate) CDN traffic.
func isAbusedEndpoint(u string) bool {
	return containsAnyFold(u, oobC2Markers) || reGithubPayloadFetch.MatchString(u)
}

// IsSensitiveEnv reports whether an environment variable name is
// credential/secret-shaped - i.e. accessing it is a theft signal, not the
// benign HOME/PATH/cwd reads the anti-evasion layer triggers.
func IsSensitiveEnv(name string) bool {
	up := strings.ToUpper(name)
	for _, s := range sensitiveEnv {
		if strings.Contains(up, s) {
			return true
		}
	}
	return false
}

// reDotenv matches a dotenv credential file (.env, .env.local, .env.production,
// …) as a path COMPONENT - but not files that merely end in ".env" such as React
// Native's build config .xcode.env / .xcode.env.local, which are not secrets.
var reDotenv = regexp.MustCompile(`(?i)(^|/)\.env($|\.)`)

// IsSensitivePath reports whether a filesystem path points at credentials,
// keys, or other secrets worth flagging (vs. the package's own files).
func IsSensitivePath(p string) bool {
	return containsAnyFold(p, sensitivePath) || reDotenv.MatchString(strings.ReplaceAll(p, `\`, "/"))
}

// containsAnyFold reports whether the lower-cased s contains any of subs (which
// must already be lower-case).
func containsAnyFold(s string, subs []string) bool {
	ls := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(ls, sub) {
			return true
		}
	}
	return false
}

// decodedLoaderEvidence inspects decoded/decrypted blobs for embedded malware
// loaders. When a sample decrypts or base64-decodes a payload whose CONTENT is
// itself executable malware - process spawning, network exfil, or further dynamic
// eval - that recovered plaintext is intrinsic proof of malice: the package
// shipped this payload obfuscated and unwraps it at runtime. It scores on the
// plaintext alone, independent of whether the payload then ran (it commonly fires
// behind a magic-argument gate or a deferred timer the analyzer mutes). Requiring
// process-exec or eval combined with a network/exec tell keeps benign decoded data
// (images, JSON, configs) from matching.
// decodedHiddenEndpointEv returns evidence when a base64/obfuscated blob decodes
// to an http(s) URL pointing at a non-benign host. Packages base64-encode their
// URL specifically to keep the C2/staging endpoint out of static scanners, so a
// *decoded* hidden endpoint is a strong concealed-loader signal - and unlike a
// hardcoded host list it is host-INDEPENDENT, catching freshly-registered dropper
// domains (tiiny.site/vercel.app/new TLDs) the moment a campaign rotates.
func decodedHiddenEndpointEv(decoded map[string]struct{}) []string {
	seen := map[string]bool{}
	var out []string
	consider := func(disp, host string) {
		host = strings.ToLower(host)
		if host == "" || isBenignHost(host) || seen[host] {
			return
		}
		seen[host] = true
		out = append(out, disp)
	}
	for blob := range decoded {
		// Full scheme URLs (https://host/…), bare hosts (www.host.com/…, no scheme -
		// loaders often store just the host), and raw-IP endpoints all count: the
		// tell is concealing ANY network endpoint inside an encoded blob.
		for _, m := range reURL.FindAllString(blob, -1) {
			consider(strings.TrimRight(m, "/.,)\"'"), hostFromURL(m))
		}
		for _, d := range reDomain.FindAllString(blob, -1) {
			consider(d, d)
		}
		for _, ip := range reIP.FindAllString(blob, -1) {
			consider(ip, ip)
		}
	}
	return clipList(out)
}

func decodedLoaderEvidence(decoded map[string]struct{}) []string {
	has := func(s string, subs ...string) bool {
		for _, sub := range subs {
			if strings.Contains(s, sub) {
				return true
			}
		}
		return false
	}
	var out []string
	for blob := range decoded {
		// Defeat string-obfuscation (concat, fromCharCode, \x/\u escapes, array
		// join, reverse) so a split token like `'child_'+'process'` or
		// `String.fromCharCode(115,104)` still matches - see deobfuscateViews.
		low := deobfuscateViews(blob)
		exec := has(low, "child_process", "spawn(", "spawnsync", "execsync", "exec(",
			"/bin/sh", "/bin/bash", "bash -c", "sh -c", "node -e", "powershell", "cmd.exe",
			// download-and-execute one-liners: a decoded `curl … | sh` / `wget … | bash`
			// is itself the loader, even without a child_process token.
			"| sh", "|sh", "| bash", "|bash", "curl ", "wget ", "iwr ", "invoke-expression", "iex ")
		net := has(low, "http://", "https://", "fetch(", "xmlhttprequest", "websocket",
			"\"net\"", "'net'", "dns.", "curl ", "wget ", "exfil", "webhook")
		dyn := has(low, "eval(", "new function", "import(", "require(", "function(",
			"=>", "atob(", "frombase64", "createdecipher")
		// Strongest: a decoded payload that spawns processes AND reaches the network
		// (classic dropper). Also flag exec+further-eval, or network+eval staging.
		if (exec && (net || dyn)) || (net && dyn) {
			out = append(out, truncField(blob, 200))
		}
	}
	return clipList(out)
}

// dnsLabelLooksEncoded reports whether a DNS name carries a long, high-entropy
// hex/base32 label in a subdomain position - the hallmark of DNS data smuggling,
// where stolen data is encoded into the query name (e.g.
// `774a39...80hexchars.exfil.attacker.example`). The final two labels (domain +
// TLD) are exempt so an ordinary registrable name never matches; only an
// over-long encoded child label trips it, keeping integrity-hash subdomains
// (which are short) clear.
func dnsLabelLooksEncoded(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	// Strip scheme/path if a URL slipped in.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	labels := strings.Split(s, ".")
	if len(labels) < 3 {
		return false
	}
	isHex := func(r byte) bool { return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') }
	isB32 := func(r byte) bool { return (r >= 'a' && r <= 'z') || (r >= '2' && r <= '7') }
	allOf := func(lab string, pred func(byte) bool) bool {
		for i := 0; i < len(lab); i++ {
			if !pred(lab[i]) {
				return false
			}
		}
		return lab != ""
	}
	for _, lab := range labels[:len(labels)-2] { // skip registrable domain + TLD
		// A pure-hex/base32 subdomain label this long is an encoded data chunk, not a
		// hostname. Hex >=20 (>=10 bytes) catches short-secret exfil while staying
		// clear of integrity-hash/cache-key labels, which are alphanumeric, not pure
		// hex/base32.
		if len(lab) >= 20 && allOf(lab, isHex) {
			return true
		}
		if len(lab) >= 32 && allOf(lab, isB32) {
			return true
		}
	}
	return false
}

// sandboxProbePaths are filesystem artifacts a sample reads specifically to tell
// whether it is inside a container / VM / analysis sandbox. Reading these is an
// evasion tell that is almost never legitimate in an installed npm package - a
// VM-guest device or the container init's cgroup has no benign use at runtime.
var sandboxProbePaths = []string{
	"/.dockerenv", "/run/.containerenv", // container marker files
	"/proc/1/cgroup", "/proc/self/cgroup", "/proc/1/sched", // container/init inspection
	"/sys/hypervisor", "/proc/scsi/scsi", // hypervisor presence
	"/proc/vz", "/proc/xen", // OpenVZ / Xen
	"/proc/modules", "/dev/vmci", "/dev/vboxguest", // VM guest kernel modules/devices
}

// ambientProbePaths are host facts that LEGITIMATE tooling reads - build tools
// size their thread pools from CPU/memory and select prebuilt native binaries
// from DMI/arch. On their own these are not evasion (next, sharp, esbuild, etc.
// all read them), so they only count when they CORROBORATE a genuinely
// suspicious signal, never standalone.
var ambientProbePaths = []string{
	"/proc/cpuinfo", "/proc/meminfo", "/sys/class/dmi",
}

// sandboxProbeEnv are the CI/analysis environment variables a sample may
// enumerate. Build tools (next, ci-info, etc.) legitimately read these to adjust
// telemetry and output, so the CI cluster is treated as ambient, not as a
// standalone evasion tell.
var sandboxProbeEnv = []string{
	"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "TRAVIS", "APPVEYOR",
	"JENKINS_URL", "BUILDKITE", "TEAMCITY_VERSION", "BITBUCKET_BUILD_NUMBER",
	"DRONE", "SEMAPHORE", "CODEBUILD_BUILD_ID",
}

// detectSandboxProbes scans events and returns two sets of tells: evasion-grade
// tells (container/VM-guest probes that almost never have a benign purpose) and
// whether any ambient host-probing occurred (CPU/mem/DMI/CI - legitimate for
// build tooling). The caller scores evasion tells standalone but ambient ones
// only when correlated with another suspicious signal, so a normal build tool
// like next isn't flagged for reading /proc/cpuinfo or process.env.CI.
func detectSandboxProbes(events []Event) (evasion []string, ambient bool) {
	tells := map[string]bool{}
	ciHits := map[string]bool{}
	for _, e := range events {
		if e.Cat == CatFS {
			for _, a := range e.Args {
				lp := strings.ToLower(a)
				for _, probe := range sandboxProbePaths {
					if strings.Contains(lp, probe) {
						tells["reads "+probe] = true
					}
				}
				for _, probe := range ambientProbePaths {
					if strings.Contains(lp, probe) {
						ambient = true
					}
				}
			}
		}
		if e.Cat == CatEnv {
			for _, a := range e.Args {
				for _, k := range sandboxProbeEnv {
					if strings.EqualFold(a, k) {
						ciHits[strings.ToUpper(k)] = true
					}
				}
			}
		}
	}
	if len(ciHits) >= 3 {
		ambient = true // enumerating the CI cluster is host-probing, but benign for build tools
	}
	out := make([]string, 0, len(tells))
	for k := range tells {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, ambient
}

// High-fidelity command signatures (from dynamic-analysis threat research). These
// are scored heavily because, unlike a bare child_process spawn, they have
// almost no benign use at npm install/import time.
var (
	// Reverse shells: bash /dev/tcp, `nc -e`, mkfifo+sh pipes, python pty, etc.
	reReverseShell = regexp.MustCompile(`(?i)(/dev/tcp/|/dev/udp/|\bnc(?:at)?\b[^|;&]*\s-[a-z]*e|\bbash\s+-i\b|mkfifo\b[^|]*\|[^|]*\b(?:sh|bash)\b|socket\.socket\([^)]*\)[^;]*?\.connect|python[0-9.]*\s+-c\s+['"][^'"]*pty\.spawn)`)
	// Interactive OS shell spawned with NO command of its own (no -c/-e//c/-Command,
	// only an optional -i/-l). Such a shell is useless unless its stdio is wired to
	// something else - a backdoor pipes a network socket into it. Benign build code
	// always spawns a shell WITH a command (`sh -c "tsc"`), which this won't match.
	reInteractiveShell = regexp.MustCompile(`(?i)^\s*(?:/[\w./-]*/)?(?:sh|bash|zsh|dash|ash|ksh|busybox|cmd|powershell|pwsh)(?:\.exe)?(?:\s+-[il]+)*\s*$`)
	// Downloader piped straight into an interpreter: curl|bash, wget -O- | sh, …
	reDownloaderPipe = regexp.MustCompile(`(?i)\b(?:curl|wget|fetch)\b[^|;]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python[0-9.]*|node|perl|ruby)\b`)
	// Decode transform piped straight into an interpreter: `echo <b64> | base64 -d |
	// sh`, `curl url | openssl enc -d | bash`, `... | xxd -r -p | sh`, rot13 via
	// `tr`/`rev`. This is the obfuscated twin of the curl|bash loader - the payload
	// is decoded in-line and executed - and has no benign install-time use.
	reDecodePipe = regexp.MustCompile(`(?i)\b(?:base64\s+(?:-d\b|-D\b|--decode\b)|openssl\s+enc\b[^|]*\b-d\b|xxd\s+-r\b|uudecode\b|gunzip\b|gzip\s+-d\b|zcat\b|bunzip2\b|\brev\b|\btr\b[^|]*['"]?[a-z])[^|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ash|ksh|python[0-9.]*|node|perl|ruby|php)\b`)
	// Downloader binaries - used by stagedDownloadExecEv, which flags the file-staged
	// download-and-execute cradle (`wget URL -O /tmp/x && chmod +x /tmp/x && /tmp/x`):
	// a download written to a file that is then RUN. The download alone, or even a
	// download + chmod +x without execution (the legitimate prebuilt-CLI install),
	// does not match - only fetch-then-execute of the same path does.
	reDownloader = regexp.MustCompile(`(?i)\b(?:curl|wget|aria2c|axel|lwp-download)\b`)
	// Privilege escalation / system tampering.
	rePrivEsc = regexp.MustCompile(`(?i)(\bsudo\s|\bchmod\s+(?:[+]s|[0-7]*[4-7][0-7]{3}|u\+s)|\bchown\s+root|/etc/sudoers|/etc/shadow|\bsetcap\b|\bvisudo\b)`)
	// Runtime package-manager install verb with an explicit package argument: a
	// package whose own code spawns `npm install <pkg>` / `yarn add <pkg>` /
	// `pnpm add <pkg>` / `npx <pkg>` to fetch and run a SECOND-STAGE payload (a
	// dropper / dependency-confusion stager - e.g. DPRK
	// `try{require('x')}catch{execSync('npm install x')}`).
	reRuntimeInstall = regexp.MustCompile(`(?i)\b(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install|i)|npx)\s+(?:--?\S+\s+)*[@a-z0-9][@a-z0-9._/-]+`)
	// Stealth flags that hide a runtime install (no lockfile/package.json change,
	// no output) - near-exclusive to droppers that don't want to leave a trace.
	reInstallStealth = regexp.MustCompile(`(?i)(--no-save|--no-progress|--no-audit|--no-fund|--silent|--loglevel[ =]+silent|--prefer-offline|--ignore-scripts\b.*--)`)
	// Cryptominer / resource hijacking (ATT&CK T1496): mining-pool protocol URLs
	// and well-known miner binaries/pools. No benign install-time use.
	reCryptominer = regexp.MustCompile(`(?i)(stratum\+(?:tcp|ssl|tcps)://|\bxmrig\b|\bminergate\b|\bcoinhive\b|\bcryptonight\b|\bnanopool\.org\b|\bsupportxmr\.com\b|\bminexmr\b|\bnicehash\b|\bethermine\.org\b|\bf2pool\.com\b|\b2miners\.com\b|--cpu-priority|--donate-level)`)
	// Scheduled-task persistence (ATT&CK T1053): a package's code installing a
	// cron job (T1053.003) / scheduled task (T1053.005) / launchd / service at
	// runtime via a spawned command.
	reScheduledTask = regexp.MustCompile(`(?i)(\bcrontab\s+-|\bschtasks\s+/create|\bat\s+now\b|systemctl\s+enable|launchctl\s+(?:load|bootstrap)|\bcrontab\s+/)`)
	// PowerShell abuse (ATT&CK T1059.001): encoded/hidden command, in-memory
	// download-and-exec (IEX + DownloadString), or base64 blob. Near-zero benign
	// use from an npm package.
	rePowerShell = regexp.MustCompile(`(?i)(powershell|pwsh)(\.exe)?\b[^|;&]*(-enc(?:odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{20,}|-w(?:indowstyle)?\s+hidden|-nop\b|-noni\b|iex\b|invoke-expression|downloadstring|frombase64string|-executionpolicy\s+bypass)`)
	// Windows Command Shell obfuscation (T1059.003): cmd /c with a download or
	// piped exec - usually paired with certutil/bitsadmin staging.
	reWinShell = regexp.MustCompile(`(?i)(cmd(\.exe)?\s+/c\s+.*\b(certutil|bitsadmin|mshta|regsvr32|rundll32)\b|\bcertutil\b.*-urlcache|\bbitsadmin\b.*\/transfer|\bmshta\b\s+https?://)`)
	// Cloud instance metadata theft (ATT&CK T1552.005): reading the link-local
	// metadata endpoint to steal cloud IAM/role credentials. Highly specific.
	reCloudMetadata = regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data/|/computeMetadata/v1/|/metadata/instance\?api-version)`)
	// OS credential-store dumping via command (ATT&CK T1555.001 macOS Keychain,
	// T1555.004 Windows Credential Manager): the CLI tools that export them.
	reCredDump = regexp.MustCompile(`(?i)(security\s+(?:dump-keychain|find-(?:generic|internet)-password)|\bvaultcmd\b|\bcmdkey\s+/list|\bmimikatz\b|reg\s+(?:save|export)\s+hk(?:lm|cu)\\\\?sam)`)
	// DNS exfiltration / tunneling (ATT&CK T1048.003 / T1071.004): a named DNS
	// tunnel tool, or known DNS-logging callback hosts, or an explicit exfil label.
	// (A generic long-hex label is matched separately by dnsLabelLooksEncoded, which
	// requires correlation with the encode call to avoid integrity-hash false hits.)
	reDNSExfil = regexp.MustCompile(`(?i)(\biodine\b|\bdnscat2?\b|\bdns2tcp\b|\.dnslog\.|\.requestrepo\.com\b|\.oast\.|\.dns\.outlook\.exfil|\bexfil\b|\.tunnel\.)`)
	// Impair defenses (ATT&CK T1562): disabling or killing endpoint security, AV,
	// SELinux/AppArmor, or the host firewall. An npm package has no benign reason to
	// stop falcon/osquery/auditd, run `setenforce 0`, flush iptables, or disable the
	// firewall, so this is high-fidelity.
	reDefenseEvasion = regexp.MustCompile(`(?i)(` +
		`\bsetenforce\s+0\b|\baa-(?:disable|teardown|complain)\b|` +
		`\bsystemctl\s+(?:stop|disable|mask)\s+[^;&|]*\b(?:falcon[\w-]*|crowdstrike|cbagentd|carbonblack|cb-response|osqueryd?|auditd|wazuh[\w-]*|ossec[\w-]*|clamav|clamd|freshclam|sentinel\w*|sysmon|td-agent|splunkd?|filebeat|firewalld|apparmor|snort|suricata)\b|` +
		`\b(?:pkill|killall|kill)\b[^;&|]*\b(?:falcon[\w-]*|crowdstrike|osquery\w*|auditd|wazuh\w*|ossec\w*|clamd?|sentinel\w*|sysmon|splunkd?|carbonblack|msmpeng|defender)\b|` +
		`\biptables\s+(?:-F|--flush)\b|\bufw\s+disable\b|\bnetsh\s+advfirewall\b[^;&|]*\b(?:off|disable)\b|` +
		`\bset-mppreference\b[^;&|]*\bdisable\w*|\badd-mppreference\b[^;&|]*\bexclusion|\bsc\b\s+(?:stop|delete|config)\s+(?:windefend|sense|sysmon)\b|` +
		`\bspctl\s+--master-disable\b|\bcsrutil\s+disable\b` +
		`)`)
	// Anti-forensics / indicator removal (ATT&CK T1070): clearing shell history,
	// wiping system logs, or shredding the dropper. Routine for malware covering its
	// tracks, never for a package install.
	reAntiForensics = regexp.MustCompile(`(?i)(` +
		`\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bHISTFILE=(?:/dev/null|["']{2}|\s|;|$)|\bHISTSIZE=0\b|\bset\s+\+o\s+history\b|` +
		`\brm\b[^;&|]*\.(?:bash|zsh|sh|ash|python)_history\b|` +
		`\bshred\b\s+-?[a-z]*u|` +
		`(?:\btruncate\s+-s\s*0|\brm\s+-rf|:\s*>|>)\s*/var/log/|\bjournalctl\b[^;&|]*--vacuum|` +
		`\bwevtutil\s+cl\b|\bclear-eventlog\b|\bremove-eventlog\b` +
		`)`)
	// Clipboard write tools - a crypto-clipper swaps a copied wallet address for the
	// attacker's by writing the clipboard. Scored only together with a wallet address
	// (see detectCommandSignatures), since clipboard access alone is benign.
	reClipboardWrite = regexp.MustCompile(`(?i)(\bxclip\b[^;&|]*(?:-i\b|-in\b|-selection\s+clip)|\bxsel\b[^;&|]*(?:-i\b|-b\b|--input)|\bpbcopy\b|\bwl-copy\b|\bclip(?:\.exe)?\b|\bset-clipboard\b)`)
	// Crypto wallet address (BTC/ETH-shaped), reused to qualify a clipboard write as
	// a clipper.
	reWalletAddr = regexp.MustCompile(`(?i)(\b(?:bc1|tb1)[a-z0-9]{20,}\b|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b|\bT[1-9A-HJ-NP-Za-km-z]{33}\b|\b(?:cosmos|osmo|juno|terra)1[a-z0-9]{38,}\b)`)
	// Self-propagation (worm): a package's own code republishing to the registry at
	// runtime - the spreading step of a self-replicating supply-chain worm. A normal
	// package never runs `npm publish` from its install/import code.
	reSelfPropagate = regexp.MustCompile(`(?i)\b(?:npm|yarn|pnpm|bun)\s+publish\b`)
	// A package.json lifecycle-script key - used to detect a manifest being rewritten
	// to inject an install/publish hook.
	reLifecycleKey = regexp.MustCompile(`(?i)"(?:pre|post)?(?:install|publish|pack|prepare|prepublishonly)"\s*:`)
	// A shell/exec payload - a command or code-exec primitive that has no business
	// inside a freshly-written lifecycle script.
	reShellPayload = regexp.MustCompile(`(?i)(\bcurl\s|\bwget\s|\bnode\s+-e\b|child_process|\beval\(|\bbase64\s+-d|\bsh\s+-c\b|\|\s*(?:sudo\s+)?(?:ba)?sh\b|\bpowershell\b|\bexecsync?\b|\bexec\()`)
	// Archive extractors (7z/zip/rar/xz/zstd/tar/…). Extracting is benign on its own
	// (build tools unpack prebuilt assets), so this is paired with execution from a
	// world-writable staging dir (reExecFromStage) to flag the extract-and-run
	// dropper - the archive equivalent of the download cradle, format-agnostic even
	// when the format itself (7z/xz/rar) can't be unpacked in-process.
	reArchiveExtract = regexp.MustCompile(`(?i)(\b7za?r?\b\s+[xe]\b|\bunzip\b|\bunrar\b|\brar\s+[xe]\b|\btar\b[^|;&]*(?:-{1,2}?x|--extract)|\bxz\b\s+-?-?d|\bunxz\b|\bbunzip2\b|\bbzip2\s+-d|\bunlzma\b|\bunzstd\b|\bzstd\s+-d|\bcabextract\b|\bgunzip\b|\b7zr\b)`)
	// Execution of a file straight out of a world-writable staging dir.
	reExecFromStage = regexp.MustCompile(`(?i)(?:^|[|;&]|\bthen\b|\bsudo\s)\s*/(?:tmp|var/tmp|dev/shm|run/shm)/\S`)
	// A command that launches a script interpreter on a file argument. Paired with
	// the runtime-written-file set (dropAndExecEv) to flag drop-and-execute: the
	// sample writes a script then spawns an interpreter on that exact file.
	reInterpreterExec = regexp.MustCompile(`(?i)(?:^|[\s|;&/])(?:node(?:js)?|bun|deno|ts-node|tsx|python[0-9.]*|sh|bash|zsh|dash|ksh|perl|ruby|php|osascript|wscript|cscript)(?:\.exe)?\s`)
	// ICMP / covert-channel tunneling (T1095): ping with a long hex payload pattern
	// (`ping -p <hex>`), or the dedicated tunneling tools. No benign install use.
	reICMPExfil = regexp.MustCompile(`(?i)(\bping\b[^|;&]*\s-p\s*[0-9a-f]{8,}|\bhping3?\b|\bnping\b|\bicmptunnel\b|\bptunnel\b)`)
	// Container escape (T1611): entering PID 1's namespaces (nsenter -t 1), chroot /
	// mount of the host root via /proc/1/root, or privileged unshare. No benign npm
	// install/import use.
	reContainerEscape = regexp.MustCompile(`(?i)(\bnsenter\b[^|;&]*(?:-t\s*1\b|--target\s*1\b)|chroot\s+/proc/1/root|\bmount\b[^|;&]*/proc/1/root|/proc/1/root/|\bunshare\b[^|;&]*(?:--mount|-m\b|--map-root-user|-r\b))`)
	// Lateral movement over SSH (T1021.004): automated/non-interactive SSH/SCP/rsync
	// - password automation (sshpass) or host-key verification disabled
	// (StrictHostKeyChecking=no / UserKnownHostsFile=/dev/null) - which a package has
	// no benign reason to run at install/import time.
	reLateralSSH = regexp.MustCompile(`(?i)(\bsshpass\b|\b(?:ssh|scp|sftp|rsync)\b[^|;&]*(?:stricthostkeychecking\s*=\s*no|userknownhostsfile\s*=\s*/dev/null|\bbatchmode\s*=\s*yes\b))`)
	// Fork bomb (T1499 resource exhaustion / DoS): the classic `:(){ :|:& };:` and
	// the general self-piping backgrounded-function form (RE2 has no backreferences,
	// so the named variant is matched structurally: a function body that pipes into
	// itself and backgrounds, `f(){ … | … & }`).
	reForkBomb = regexp.MustCompile(`(?i)(:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\b\w+\s*\(\)\s*\{[^}]*\|[^}]*&\s*\}\s*;|\bwhile\s*\(\s*(?:true|1)\s*\)[^}]*\bfork\s*\()`)
	// A package-manager registry directive in an .npmrc/.yarnrc, capturing the URL -
	// used to flag a registry hijack (repointing installs to an attacker host).
	reRegistryDirective = regexp.MustCompile(`(?i)\bregistry\s*[=:]\s*["']?(https?://[^\s"'\n]+)`)
	// A native addon (.node) dropped into a WORLD-WRITABLE staging dir (/tmp,
	// /var/tmp, /dev/shm, /run/shm). Loading native code is arbitrary RCE, but legit
	// prebuilt-binary installers (prebuild-install/node-pre-gyp) write the .node into
	// the package's own build/Release|prebuilds dir - so only a drop to a transient
	// world-writable path, where droppers stage payloads, is the tell.
	reNativeAddonDrop = regexp.MustCompile(`(?i)(?:^|/)(?:tmp|var/tmp|dev/shm|run/shm)/[^\s'"]*\.node(?:["'\s]|$)`)
)

// downloadInterpreters are the interpreters a dropper invokes on a file it just
// fetched (`bash /tmp/x`, `node ./payload`), used to recognize execution of a
// staged download even when the file itself carries no execute bit.
var downloadInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true, "ksh": true,
	"busybox": true, "node": true, "nodejs": true, "perl": true, "ruby": true,
	"php": true, "python": true, "python2": true, "python3": true,
}

// pathBase returns the final path element of a (possibly quoted) token.
func pathBase(p string) string {
	p = strings.Trim(p, `"'`)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return p
}

// downloadTargets returns the output file paths a downloader command writes to
// (-o/-O/--output[-document]/`>` redirect). Empty unless the command actually
// invokes a downloader, so a bare `> file` redirect doesn't count.
func downloadTargets(cmd string) []string {
	if !reDownloader.MatchString(cmd) {
		return nil
	}
	var out []string
	toks := strings.Fields(cmd)
	for i, t := range toks {
		switch {
		case t == "-o" || t == "-O" || t == "--output" || t == "--output-document":
			if i+1 < len(toks) {
				out = append(out, strings.Trim(toks[i+1], `"'`))
			}
		case strings.HasPrefix(t, "--output="):
			out = append(out, strings.Trim(strings.TrimPrefix(t, "--output="), `"'`))
		case strings.HasPrefix(t, "--output-document="):
			out = append(out, strings.Trim(strings.TrimPrefix(t, "--output-document="), `"'`))
		case t == ">" || t == ">>":
			if i+1 < len(toks) {
				out = append(out, strings.Trim(toks[i+1], `"'`))
			}
		case strings.HasPrefix(t, ">") && len(t) > 1:
			out = append(out, strings.Trim(strings.TrimLeft(t, ">"), `"'`))
		}
	}
	return out
}

// shellSegmentRe splits a command line into the sub-commands the shell runs in
// sequence (&&, ||, ;, |, newline), so execution of a staged file can be found
// inside a compound one-liner like `wget -O /tmp/x && chmod +x /tmp/x && /tmp/x`.
var shellSegmentRe = regexp.MustCompile(`&&|\|\||;|\n|\|`)

// commandExecutesFile reports whether cmd RUNS the file at path (matched by full
// path or basename): in any of its &&/;-separated segments the file is the command
// head (`/tmp/x`, `./x`) or an interpreter is invoked on it (`bash /tmp/x`). A bare
// `chmod +x` is deliberately NOT execution - downloading a binary and marking it
// executable (without running it) is the legitimate prebuilt-CLI install pattern.
func commandExecutesFile(cmd, path, base string) bool {
	if base == "" {
		return false
	}
	for _, seg := range shellSegmentRe.Split(cmd, -1) {
		first := strings.Trim(firstArg(seg), `"'`)
		if first == path || pathBase(first) == base {
			return true
		}
		if downloadInterpreters[leadingBinary(seg)] {
			for _, t := range strings.Fields(seg) {
				tt := strings.Trim(t, `"'`)
				if tt == path || pathBase(tt) == base {
					return true
				}
			}
		}
	}
	return false
}

// stagedDownloadExecEv detects a staged download-and-execute dropper across the
// whole command set: a remote download written to a file path that is then RUN
// (directly or via an interpreter). It correlates on the target PATH and requires
// actual execution - downloading an asset, or even downloading a binary and
// chmod +x'ing it without running it (the legitimate prebuilt-CLI install pattern),
// does NOT match; only fetch-then-execute of the SAME file does. This is the
// file-staged equivalent of the curl|bash pipe and survives the shell splitting
// `&&` chains into separate commands.
// dropAndExecEv flags a drop-and-execute dropper: an interpreter command whose
// script argument is a file the sample WROTE at runtime (a path in `written`).
// Writing a script to disk and immediately spawning an interpreter on it - often
// detached and staged under a temp dir - has no benign install-time use; build
// tools run their OWN shipped files, not freshly written ones. Correlating
// against the runtime-written set (never the package's own source tree, which is
// not in FilesWritten) is what keeps this precise. This is the in-JS twin of the
// shell `curl|bash` / extract-and-run cradles, e.g. webpack-cache-clean's
// `writeFileSync(tmp/dropper.js); spawn(node,[tmp/dropper.js],{detached})`.
func dropAndExecEv(cmds, written map[string]struct{}) []string {
	if len(written) == 0 {
		return nil
	}
	var ev []string
	for c := range cmds {
		if !reInterpreterExec.MatchString(c) {
			continue
		}
		for w := range written {
			if w == "" || !strings.Contains(c, w) {
				continue
			}
			ev = append(ev, truncField(c, 200))
			break
		}
	}
	return clipList(ev)
}

func stagedDownloadExecEv(cmds map[string]struct{}) []string {
	type tgt struct{ path, src string }
	targets := map[string]tgt{}
	// Operate on the RAW commands: shell-level obfuscation (${IFS}, quote/backslash
	// insertion) and JS-built command strings are already resolved by the time the
	// shell/goja record the exec, so the recorded text is structurally clean. Running
	// the token/segment logic over the lossy deobfuscated multi-view would corrupt it
	// (e.g. whitespace-stripping `chmod +x ./bin/tool` to `chmod+x./bin/tool`, whose
	// basename looks like the executed file).
	for c := range cmds {
		for _, p := range downloadTargets(c) {
			if p != "" {
				targets[p] = tgt{path: p, src: c}
			}
		}
	}
	if len(targets) == 0 {
		return nil
	}
	var ev []string
	seen := map[string]bool{}
	for c := range cmds {
		for _, t := range targets {
			base := pathBase(t.path)
			if !strings.Contains(c, t.path) && (base == "" || !strings.Contains(c, base)) {
				continue
			}
			if !commandExecutesFile(c, t.path, base) {
				continue
			}
			key := t.src + "\x00" + c
			if seen[key] {
				continue
			}
			seen[key] = true
			if c == t.src {
				ev = append(ev, truncField(c, 200))
			} else {
				ev = append(ev, truncField(t.src, 100)+" => "+truncField(c, 100))
			}
		}
	}
	return clipList(ev)
}

// persistencePaths are write targets that survive the process - adding one is a
// near-certain persistence attempt for an npm package.
var persistencePaths = []string{
	"/etc/cron", "/var/spool/cron", "crontab", "/etc/init.d", "/etc/rc.local",
	"/etc/systemd/", "/lib/systemd/", ".config/systemd", "/etc/profile",
	".bashrc", ".bash_profile", ".zshrc", ".profile", "/etc/ld.so.preload",
	"authorized_keys", ".ssh/config", "/library/launchagents", "/library/launchdaemons",
	"\\currentversion\\run", "/etc/xdg/autostart", ".config/autostart",
}

// gitHookPaths are git-hook locations. A dropped hook is code execution on every
// commit/checkout - a real persistence vector - BUT legitimate, extremely common
// tools (husky, lefthook, simple-git-hooks, pre-commit, yorkie) write here as
// their normal function. So a write alone is only weakly suspicious: it is scored
// low (those tools pass on their own) yet still adds to the total alongside real
// malware signals (taint, exfil, obfuscation), where a genuine hook-dropper still
// trips the malicious band.
var gitHookPaths = []string{
	".git/hooks/", "/hooks/pre-commit", "/hooks/post-checkout", "/hooks/post-merge",
	"/hooks/pre-push", ".husky/",
}

// oobC2Markers are interaction/collaborator/tunneling service hosts: standard
// infrastructure for exfil and out-of-band callbacks, rare in benign packages.
var oobC2Markers = []string{
	".onion", "oast.site", "oast.pro", "oast.live", "oast.fun", "oast.me",
	"interact.sh", "interactsh", "burpcollaborator", "oastify.com", "requestbin",
	"requestcatcher", "pipedream.net", "webhook.site", "dnslog.cn", "ngrok.io",
	"ngrok-free.app", "trycloudflare.com", "termbin.com", "transfer.sh",
	"0x0.st", "tmpfiles.org", "anonfiles", "controlc.com", "paste.ee",
	// Web-service exfil channels (ATT&CK T1567.002) - bot/webhook/paste endpoints
	// that supply-chain stealers use as drop sites. The full API paths keep these
	// specific (a package merely linking to telegram.org isn't matched).
	"api.telegram.org/bot", "discord.com/api/webhooks", "discordapp.com/api/webhooks",
	"hooks.slack.com/services", "pastebin.com/raw", "gist.githubusercontent.com",
	"hastebin.com/raw", "ptb.discord.com/api/webhooks", "canary.discord.com/api/webhooks",
	"glot.io", "ix.io", "paste.rs", "filebin.net", "file.io",
	// Abused exfil/C2 drop sites on otherwise-benign hosts: notification relays,
	// no-auth/low-friction data stores, serverless function/webhook relays, paste
	// sites, file hosts, chat/mail webhook endpoints, and Telegram file/bot APIs.
	// Full hosts/paths keep these low-collision so a package merely depending on
	// the legitimate service isn't flagged (these score AND un-suppress via
	// isAbusedEndpoint).
	"ntfy.sh", "api.notion.com", "api.airtable.com", "jsonbin.io", "api.pinata.cloud",
	"supabase.co", "firebaseio.com", "firebasedatabase.app", "val.town", "smee.io",
	"rentry.co", "catbox.moe", "api.github.com/gists",
	"outlook.office.com/webhook", "chat.googleapis.com/v1/spaces", "api.sendgrid.com",
	"api.mailgun.net", "api.telegram.org/file/bot",
}

// spawnOps are the CatProc operations that represent an actual process spawn (as
// opposed to bookkeeping events like stdin.write or a shell parse error).
var spawnOps = map[string]bool{
	"exec": true, "execFile": true, "execSync": true, "execFileSync": true,
	"spawn": true, "fork": true, "spawnSync": true, "shell-exec": true,
}
