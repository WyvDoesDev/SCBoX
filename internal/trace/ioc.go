package trace

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

// IOCSet holds deduplicated indicators of compromise, grouped by type. All
// access goes through the Tracer's helpers, which hold its lock; the embedded
// mutex guards direct scan() calls from auto-scanning.
type IOCSet struct {
	mu sync.Mutex

	URLs         map[string]struct{}
	Domains      map[string]struct{}
	IPs          map[string]struct{}
	Paths        map[string]struct{} // files read / accessed
	FilesWritten map[string]struct{} // files written (dropped payloads)
	FilesDeleted map[string]struct{} // files deleted/removed (destructive)
	Commands     map[string]struct{} // shell/process commands
	EnvAccessed  map[string]struct{} // env vars the sample read
	Dependencies map[string]struct{} // declared/required external packages
	Decoded      map[string]struct{} // base64/hex-decoded blobs

	// Broadened indicator surface.
	Secrets   map[string]struct{} // credential-shaped tokens seen anywhere (AWS/GitHub/npm/JWT/PEM…)
	Wallets   map[string]struct{} // crypto wallet addresses (clipboard hijack / theft)
	Emails    map[string]struct{} // email addresses (exfil targets)
	Onion     map[string]struct{} // Tor .onion C2 addresses
	Headers   map[string]struct{} // HTTP headers set (auth/cookies/beacon)
	Payloads  map[string]struct{} // data sent over the network (exfil bodies)
	CryptoOps map[string]struct{} // crypto algorithms / ciphers used
}

func newIOCSet() *IOCSet {
	return &IOCSet{
		URLs:         map[string]struct{}{},
		Domains:      map[string]struct{}{},
		IPs:          map[string]struct{}{},
		Paths:        map[string]struct{}{},
		FilesWritten: map[string]struct{}{},
		FilesDeleted: map[string]struct{}{},
		Commands:     map[string]struct{}{},
		EnvAccessed:  map[string]struct{}{},
		Dependencies: map[string]struct{}{},
		Decoded:      map[string]struct{}{},
		Secrets:      map[string]struct{}{},
		Wallets:      map[string]struct{}{},
		Emails:       map[string]struct{}{},
		Onion:        map[string]struct{}{},
		Headers:      map[string]struct{}{},
		Payloads:     map[string]struct{}{},
		CryptoOps:    map[string]struct{}{},
	}
}

// IOC sets are bounded so a hostile package cannot exhaust memory or stall the
// verdict scoring - which runs AFTER detonation, outside the goja interrupt
// budget, and applies deobfuscateViews (~13 string transforms) to every command
// and payload. A package flooding Commands/Payloads/etc. with millions of unique
// entries within the execution budget would otherwise hang verdict generation or
// blow up memory. Real samples need only a handful of entries to fire every
// signature, so a generous cap costs no detection fidelity; per-entry length is
// capped for the same reason (bounds per-item transform cost).
const (
	maxIOCEntries = 4096
	maxIOCItemLen = 8192
)

func (s *IOCSet) add(m *map[string]struct{}, v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	if len(v) > maxIOCItemLen {
		v = v[:maxIOCItemLen]
	}
	s.mu.Lock()
	if _, exists := (*m)[v]; !exists && len(*m) >= maxIOCEntries {
		s.mu.Unlock()
		return
	}
	(*m)[v] = struct{}{}
	s.mu.Unlock()
}

var (
	reURL    = regexp.MustCompile(`\b(?:https?|ftp|wss?)://[^\s'"` + "`" + `)\]<>]+`)
	reIP     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reDomain = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|ru|cn|info|xyz|top|tk|pw|app|dev|sh|me|biz|online|site|club|live|gift|link|click|host|fun|icu|cc|gg|to|ws)\b`)
	reOnion  = regexp.MustCompile(`\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b`)
	reEmail  = regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)
	reBTC    = regexp.MustCompile(`\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{20,80})\b`)
	reETH    = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	// Tron (T + 33 base58, 34 chars) and Monero (4/8 prefix + 95 base58) - distinctive
	// prefix+length keeps false positives near zero. Both are common crypto-clipper
	// swap targets that the BTC/ETH patterns miss.
	reTRX = regexp.MustCompile(`\bT[1-9A-HJ-NP-Za-km-z]{33}\b`)
	reXMR = regexp.MustCompile(`\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`)

	// Credential-shaped tokens. These fire on the bait values too, so an exfil
	// attempt lights them up.
	secretREs = []*regexp.Regexp{
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                                              // AWS access key
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),                                    // GitHub token
		regexp.MustCompile(`\bnpm_[A-Za-z0-9]{20,}\b`),                                          // npm token
		regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),                                  // Slack token
		regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),                                        // Google API key
		regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{16,}\b`),                                   // Stripe key
		regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+\b`), // JWT
		regexp.MustCompile(`-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`),                          // PEM private key
		regexp.MustCompile(`\bAQ[A-Za-z0-9+/=]{20,}\b`),                                         // Discord token-ish / base64 secret
	}
)

// commonTLDFalsePositives filters package/file names that look like domains.
var notReallyDomains = map[string]bool{
	"index.js": true, "package.json": true, "index.json": true,
}

// benignHostSuffixes are well-known developer registries, CDNs, source hosts and
// documentation sites. Network references to these are normal for build tooling
// and package metadata, so they are excluded from the URL/domain IOC sets (and
// therefore from scoring) - otherwise hundreds of github.com doc links and the
// like drown out the rare genuine C2 endpoint. This is the network allow-list
// from the FP-reduction research: trust major registries/CDNs/git hosts, and
// scrutinize everything else.
var benignHostSuffixes = []string{
	"github.com", "github.io", "githubusercontent.com", "githubassets.com",
	"npm.pkg.github.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
	"npmjs.org", "npmjs.com", "npmjs.help", "yarnpkg.com", "pnpm.io", "nodejs.org",
	"unpkg.com", "jsdelivr.net", "jsdelivr.com", "cdnjs.cloudflare.com",
	"skypack.dev", "esm.sh", "jspm.io", "deno.land",
	"reactjs.org", "react.dev", "vuejs.org", "angular.io", "svelte.dev",
	"jquery.com", "socket.io", "expressjs.com",
	"standardjs.com", "eslint.org", "prettier.io", "stylelint.io",
	"typescriptlang.org", "babeljs.io", "webpack.js.org", "rollupjs.org",
	"vitejs.dev", "parceljs.org", "gulpjs.com", "gruntjs.com",
	"jestjs.io", "mochajs.org", "vitest.dev",
	"developer.mozilla.org", "mozilla.org", "w3.org", "whatwg.org",
	"json-schema.org", "schema.org", "ecma-international.org", "tc39.es",
	"caniuse.com", "mathiasbynens.be",
	// funding / sponsorship links commonly printed by benign postinstall banners
	"opencollective.com", "patreon.com", "boosty.to", "ko-fi.com",
	"paypal.com", "paypal.me", "liberapay.com", "buymeacoffee.com",
	"tidelift.com", "thanks.dev", "github.com/sponsors",
}

// isBenignHost reports whether host is (a subdomain of) a well-known benign host.
func isBenignHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimPrefix(host, "www.")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	for _, s := range benignHostSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// hostFromURL extracts the bare host (no scheme/userinfo/port/path) from a URL.
func hostFromURL(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.Index(u, "@"); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.LastIndex(u, ":"); i >= 0 && !strings.Contains(u, "]") {
		u = u[:i] // strip :port (skip IPv6 literals)
	}
	return u
}

// codeIdentLabels are JavaScript object/member identifiers that the bare-domain
// regex misreads as hostnames when they precede a ccTLD-shaped property - e.g.
// `exports.core.locales.ru` or `module.exports.io`. A "domain" whose left-most
// label is one of these is source code, not a network destination.
var codeIdentLabels = map[string]bool{
	"exports": true, "module": true, "require": true, "process": true,
	"global": true, "globalthis": true, "window": true, "self": true,
	"document": true, "console": true, "default": true, "prototype": true,
	"constructor": true, "this": true, "undefined": true, "arguments": true,
	"locales": true, "core": true, "options": true, "config": true,
	// module-id namespaces (core-js exposes ids like es.array.from, web.url.to)
	"es": true, "esnext": true, "web": true,
}

// softTLDs are TLDs that double as ordinary English/code words (so the bare
// domain regex misfires on dotted identifiers like `es.array.to`). A real C2
// host on one of these is almost always 2 labels (`evil.to`); a 3+-label match
// ending in one is overwhelmingly source code, not a destination.
var softTLDs = map[string]bool{
	"to": true, "link": true, "sh": true, "me": true, "gg": true, "cc": true,
	"ws": true, "io": true, "app": true, "dev": true, "fun": true, "gift": true,
	"click": true, "host": true, "live": true, "top": true, "icu": true,
	"name": true, "site": true, "online": true, "club": true,
}

// looksLikeCodeIdent reports whether a regex "domain" match is really a dotted
// JavaScript member expression rather than a network destination - either its
// first label is a known code identifier, or it has 3+ labels ending in a TLD
// that collides with ordinary code words.
func looksLikeCodeIdent(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(labels) > 0 && codeIdentLabels[labels[0]] {
		return true
	}
	if len(labels) >= 3 && softTLDs[labels[len(labels)-1]] {
		return true
	}
	return false
}

// scan extracts network IOCs from an arbitrary string. Typed IOCs (paths,
// commands, env, decoded) are added explicitly by callers, not here.
func (s *IOCSet) scan(v string) {
	if v == "" {
		return
	}
	for _, m := range reURL.FindAllString(v, -1) {
		u := strings.TrimRight(m, ".,;")
		// Keep the URL if it's an abused drop-site/webhook endpoint, even when its
		// host suffix is otherwise benign: gist.githubusercontent.com/<id>/raw and
		// the discord/telegram/slack webhook paths live on "benign" CDNs but are
		// known exfil/C2 channels (see oobC2Markers). Without this they'd be filtered
		// before the out-of-band-C2 detector could ever match them.
		if isBenignHost(hostFromURL(u)) && !isAbusedEndpoint(u) {
			continue // well-known registry/CDN/docs host - not an IOC
		}
		s.add(&s.URLs, u)
	}
	for _, m := range reIP.FindAllString(v, -1) {
		if m == "0.0.0.0" || m == "127.0.0.1" {
			continue
		}
		s.add(&s.IPs, m)
	}
	for _, m := range reDomain.FindAllString(v, -1) {
		l := strings.ToLower(m)
		// Skip local script/asset filenames, dotted JS identifiers misread as
		// domains, and well-known benign hosts.
		if notReallyDomains[l] || hasScriptExt(l) || looksLikeCodeIdent(l) || isBenignHost(l) {
			continue
		}
		s.add(&s.Domains, m)
	}
	for _, m := range reOnion.FindAllString(v, -1) {
		s.add(&s.Onion, m)
	}
	for _, m := range reEmail.FindAllString(v, -1) {
		s.add(&s.Emails, m)
	}
	for _, m := range reBTC.FindAllString(v, -1) {
		s.add(&s.Wallets, m)
	}
	for _, m := range reETH.FindAllString(v, -1) {
		s.add(&s.Wallets, m)
	}
	for _, m := range reTRX.FindAllString(v, -1) {
		s.add(&s.Wallets, m)
	}
	for _, m := range reXMR.FindAllString(v, -1) {
		s.add(&s.Wallets, m)
	}
	for _, re := range secretREs {
		for _, m := range re.FindAllString(v, -1) {
			s.add(&s.Secrets, m)
		}
	}
}

// hasScriptExt reports whether s ends with a local file extension that the
// domain regex would otherwise misread as a TLD (e.g. "probe.sh", "index.ts").
func hasScriptExt(s string) bool {
	for _, ext := range []string{".js", ".json", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".sh", ".rb", ".pl", ".lock", ".md", ".yml", ".yaml", ".toml"} {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Snapshot returns the IOCs as sorted slices for stable output.
func (s *IOCSet) Snapshot() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string][]string{
		"urls":          sortedKeys(s.URLs),
		"domains":       sortedKeys(s.Domains),
		"ips":           sortedKeys(s.IPs),
		"paths":         sortedKeys(s.Paths),
		"files_written": sortedKeys(s.FilesWritten),
		"files_deleted": sortedKeys(s.FilesDeleted),
		"commands":      sortedKeys(s.Commands),
		"env_accessed":  sortedKeys(s.EnvAccessed),
		"dependencies":  sortedKeys(s.Dependencies),
		"decoded":       sortedKeys(s.Decoded),
		"secrets":       sortedKeys(s.Secrets),
		"wallets":       sortedKeys(s.Wallets),
		"emails":        sortedKeys(s.Emails),
		"onion":         sortedKeys(s.Onion),
		"headers":       sortedKeys(s.Headers),
		"payloads":      sortedKeys(s.Payloads),
		"crypto":        sortedKeys(s.CryptoOps),
	}
}

func (s *IOCSet) count(m map[string]struct{}) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(m)
}

// fields returns pointers to every indicator map. merge and any future
// all-fields operation goes through this so a newly added IOC category can't be
// silently forgotten in one place but not another.
func (s *IOCSet) fields() []*map[string]struct{} {
	return []*map[string]struct{}{
		&s.URLs, &s.Domains, &s.IPs, &s.Paths, &s.FilesWritten, &s.FilesDeleted,
		&s.Commands, &s.EnvAccessed, &s.Dependencies, &s.Decoded, &s.Secrets,
		&s.Wallets, &s.Emails, &s.Onion, &s.Headers, &s.Payloads, &s.CryptoOps,
	}
}

// merge unions every indicator from other into s. Used to fold a worker's IOCs
// back into the primary set after parallel analysis.
// clone returns a deep copy of the IOC set (used to build the merged "intrinsic"
// view for high-fidelity malice signals without mutating the scored set).
func (s *IOCSet) clone() *IOCSet {
	c := newIOCSet()
	c.merge(s)
	return c
}

func (s *IOCSet) merge(other *IOCSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	other.mu.Lock()
	defer other.mu.Unlock()
	sf, of := s.fields(), other.fields()
	for i := range sf {
		for k := range *of[i] {
			(*sf[i])[k] = struct{}{}
		}
	}
}
