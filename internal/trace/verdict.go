package trace

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"scbox/internal/rules"
)

// Verdict is the triage conclusion derived from observed behavior.
type Verdict struct {
	Score   int            `json:"score"`
	Level   string         `json:"level"` // clean | low | suspicious | malicious
	Reasons []string       `json:"reasons"`
	Details []ReasonDetail `json:"details"`
}

// ReasonDetail is a single weighted finding plus the concrete observations that
// triggered it (the eval'd snippets, spawned commands, decoded blobs, …) so a
// reason like "executes code dynamically (79 times)" can be drilled into.
type ReasonDetail struct {
	Text     string   `json:"text"`
	Weight   int      `json:"weight"`
	Evidence []string `json:"evidence,omitempty"`
}

// reason accumulates a weighted finding plus its supporting evidence.
type reason struct {
	text     string
	weight   int
	evidence []string
}

// reasonBuf collects the reasons emitted by a single detector. Each detector
// builds its own buffer, so detectors can run concurrently without sharing
// mutable state.
type reasonBuf struct{ rs []reason }

func (b *reasonBuf) add(w int, format string, a ...any) {
	b.rs = append(b.rs, reason{text: fmt.Sprintf(format, a...), weight: w})
}

// addEv records a finding with its supporting evidence attached.
func (b *reasonBuf) addEv(w int, ev []string, format string, a ...any) {
	b.rs = append(b.rs, reason{text: fmt.Sprintf(format, a...), weight: w, evidence: ev})
}

// verdictCtx is the precomputed, read-only view the detectors score against. It
// is built once per Verdict() call; every detector reads it concurrently and
// never mutates it, which is what makes the parallel fan-out safe.
type verdictCtx struct {
	// intrinsic - every non-dev event, INCLUDING muted (force-executed) ones.
	//             Used by signatures that are malicious by their nature regardless
	//             of how they were triggered (sandbox/VM detection, reverse-shell
	//             commands, hardcoded credential exfil). A payload hidden inside an
	//             exported function and surfaced by force-execution is still the
	//             sample's malware - muting it here would be a false negative.
	intrinsic []Event
	// events - non-dev AND non-muted. Used by generic capability COUNTS (N deletes,
	//          N evals, N network calls, generic env reads) so a benign library
	//          exercised with fuzz args can't inflate the score.
	events []Event

	ic  *IOCSet // scored IOC view (muted excluded) - used by generic COUNT signals
	mic *IOCSet // scored + muted view - used by high-fidelity intrinsic-malice signals

	seen          map[Category]int // category counts over events
	seenIntrinsic map[Category]int // category counts over intrinsic (force-exec included)

	netURLs      map[string]struct{} // non-benign URLs in scored network events
	netIPs       map[string]struct{} // non-loopback IPs in scored network events
	intrinsicNet map[string]struct{} // same, over force-executed behavior too
	hardNet      int                 // len(netURLs)+len(netIPs)

	suspiciousNet bool // a non-allow-listed endpoint, payload, or onion contact
	correlated    bool // suspiciousNet or captured secrets - gates common capabilities

	watched []string // sensitive source VALUES to taint-match against egress
	egress  string   // concatenation of all network-bound strings (taint search space)

	// User-defined taint rules (--rules): the rules, the per-rule source values
	// the sandbox served, and the command/file sink search spaces (the network
	// sink reuses egress). Built only when rules are loaded.
	taintRules []rules.Rule
	taintVals  map[string][]string
	cmdSpace   string // spawned command lines (command sink search space)
	fileSpace  string // file-write paths and content (file sink search space)
}

// Verdict computes a score from the event log and IOCs. The weights are tuned
// for npm install-time malware triage, not a formal classifier - treat the
// output as a prioritized lead, not proof.
//
// Scoring is split across independent detectors (one per behavior family) that
// run concurrently against an immutable verdictCtx; their reasons are collected
// in a fixed order so the report stays deterministic, then summed.
func (t *Tracer) Verdict() Verdict {
	c := t.buildVerdictCtx()

	// Each detector reads the shared ctx and returns its own reasons; ordering is
	// fixed by the slice so equal-weight findings stay deterministic across runs.
	detectors := []func() []reason{
		c.detectExfilAndProc,
		c.detectDynamicCode,
		c.detectSensitivePaths,
		c.detectCommandSignatures,
		c.detectEvasionAndEndpoints,
		c.detectCustomTaint,
		c.detectStaticObfuscation,
	}
	results := make([][]reason, len(detectors))
	var wg sync.WaitGroup
	for i, d := range detectors {
		wg.Add(1)
		go func(i int, d func() []reason) {
			defer wg.Done()
			results[i] = d()
		}(i, d)
	}
	wg.Wait()

	var reasons []reason
	for _, rs := range results {
		reasons = append(reasons, rs...)
	}
	return finalizeVerdict(reasons)
}

// buildVerdictCtx assembles the immutable scoring view: it filters dev-tree
// behavior, splits the muted/intrinsic event views, derives the network and
// process tallies, and computes the correlation gates the detectors share.
func (t *Tracer) buildVerdictCtx() *verdictCtx {
	allEvents := t.Events()
	ic := t.iocs // dev-tree indicators are routed to devIOCs, so this excludes them

	// devDependency-tree behavior is never scored at all - those packages are never
	// installed or run by a consumer of the analyzed package.
	t.mu.Lock()
	dev := t.devScopes
	t.mu.Unlock()

	intrinsic := make([]Event, 0, len(allEvents))
	events := make([]Event, 0, len(allEvents))
	for _, e := range allEvents {
		if dev[e.Source] {
			continue
		}
		intrinsic = append(intrinsic, e)
		if !e.Muted {
			events = append(events, e)
		}
	}

	// mic is the IOC view for high-fidelity, intrinsically-malicious signatures
	// (reverse shells, downloader pipes, runtime-install droppers, OOB C2, decoded
	// loaders, download-and-execute): the scored set PLUS the muted (force-executed)
	// set. Malware routinely hides its payload in a non-entry file that only runs
	// under force-execution - muting that would be a false negative - but these
	// signatures are specific enough that a fuzz artifact can't trip them. Generic
	// COUNT signals keep using ic (muted excluded) to stay false-positive-free.
	mic := ic.clone()
	mic.merge(t.mutedIOCs)

	c := &verdictCtx{
		intrinsic:     intrinsic,
		events:        events,
		ic:            ic,
		mic:           mic,
		seen:          map[Category]int{},
		seenIntrinsic: map[Category]int{},
		netURLs:       map[string]struct{}{},
		netIPs:        map[string]struct{}{},
		intrinsicNet:  map[string]struct{}{},
	}
	for _, e := range events {
		c.seen[e.Cat]++
	}
	for _, e := range intrinsic {
		c.seenIntrinsic[e.Cat]++
	}

	// hardNet counts high-confidence network endpoints observed in *network events*
	// (not just any string scan), after the benign-host allow-list has filtered
	// registries/CDNs. This avoids treating version-like strings as IPs.
	collectNet := func(src []Event, urls, ips map[string]struct{}) {
		for _, e := range src {
			if e.Cat != CatNet {
				continue
			}
			vals := append([]string{}, e.Args...)
			if e.Note != "" {
				vals = append(vals, e.Note)
			}
			for _, v := range vals {
				for _, m := range reURL.FindAllString(v, -1) {
					u := strings.TrimRight(m, ".,;")
					if isBenignHost(hostFromURL(u)) {
						continue
					}
					urls[u] = struct{}{}
				}
				for _, m := range reIP.FindAllString(v, -1) {
					if m == "0.0.0.0" || m == "127.0.0.1" {
						continue
					}
					ips[m] = struct{}{}
				}
			}
		}
	}
	collectNet(events, c.netURLs, c.netIPs)
	// intrinsicNet folds force-executed behavior into one set - used by the
	// exfiltration signal, since credential stealers commonly fire only when their
	// exported function is invoked (surfaced by force-execution).
	collectNet(intrinsic, c.intrinsicNet, c.intrinsicNet)
	c.hardNet = len(c.netURLs) + len(c.netIPs)

	// correlation gates: a lone powerful API is not malicious - only a CHAIN is, so
	// common-but-benign capabilities (dynamic code, base64 decode, host fingerprint)
	// score only when they co-occur with a genuinely suspicious signal.
	// NOTE: a bare wallet address is NOT a correlation trigger - benign packages
	// print donation addresses in postinstall banners (e.g. core-js). Tor .onion
	// contact, by contrast, has no benign install-time use, so it stays.
	c.suspiciousNet = c.hardNet > 0 || ic.count(ic.Payloads) > 0 || ic.count(ic.Onion) > 0
	c.correlated = c.suspiciousNet || ic.count(ic.Secrets) > 0

	// Taint search space: every network-bound string (payload bodies, request URLs
	// incl. query strings, contacted domains/headers, and the force-exec endpoints).
	// taintedExfilEv searches this for watched source values, raw or encoded.
	c.watched = t.watchedSecrets()
	var eg strings.Builder
	for _, set := range []map[string]struct{}{mic.Payloads, mic.URLs, mic.Domains, mic.Headers} {
		for v := range set {
			eg.WriteString(v)
			eg.WriteByte('\n')
		}
	}
	for v := range c.intrinsicNet {
		eg.WriteString(v)
		eg.WriteByte('\n')
	}
	c.egress = eg.String()

	// User-defined taint rules: snapshot the per-rule source values and build the
	// command/file sink search spaces. Like the egress space, these are built
	// from `mic`/intrinsic views - a tainted value smuggled out by a payload that
	// only fires under force-execution is still a real flow.
	c.taintRules = t.taintRules
	if len(c.taintRules) > 0 {
		c.taintVals = t.taintSnapshot()
		var cs, fs strings.Builder
		for v := range mic.Commands {
			cs.WriteString(v)
			cs.WriteByte('\n')
		}
		for v := range mic.FilesWritten {
			fs.WriteString(v)
			fs.WriteByte('\n')
		}
		for _, e := range intrinsic {
			var b *strings.Builder
			switch e.Cat {
			case CatProc:
				b = &cs
			case CatFS:
				b = &fs
			default:
				continue
			}
			for _, a := range e.Args {
				b.WriteString(a)
				b.WriteByte('\n')
			}
			if e.Note != "" {
				b.WriteString(e.Note)
				b.WriteByte('\n')
			}
		}
		c.cmdSpace, c.fileSpace = cs.String(), fs.String()
	}
	return c
}

// encodedForms returns the raw value plus the encodings a stealer routinely wraps
// exfil in (standard/url base64 with and without padding, lower-hex). Matching any
// of these at a sink proves the value flowed out even when it was "disguised" in
// transit - the case content inspection of the payload alone would miss.
func encodedForms(v string) []string {
	b := []byte(v)
	return []string{
		v,
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		hex.EncodeToString(b),
		// Percent-encoding: a secret shipped in a URL query/path
		// (`fetch(c2+'?d='+encodeURIComponent(secret))`) is escaped, so the raw
		// form misses any value with reserved chars (AWS secrets carry / and +).
		// PathEscape matches encodeURIComponent for those; QueryEscape covers form
		// bodies (space→+).
		url.PathEscape(v),
		url.QueryEscape(v),
	}
}

// taintedExfilEv reports watched source VALUES (bait env, secret-file content) that
// reached a network sink in raw/base64/hex form. A hit is direct proof a secret
// flowed out of the box - the causal link that a bare "read a secret AND made a
// request" correlation lacks, so it neither misses encoded exfil nor fires on a
// tool that merely reads env/config and calls home for unrelated reasons.
func (c *verdictCtx) taintedExfilEv() []string {
	if c.egress == "" || len(c.watched) == 0 {
		return nil
	}
	var hits []string
	for _, val := range c.watched {
		for _, f := range encodedForms(val) {
			if len(f) >= 12 && strings.Contains(c.egress, f) {
				hits = append(hits, truncField(val, 80))
				break
			}
		}
	}
	return clipList(hits)
}

// isWriteOp reports whether an FS op name represents a file write/append.
func isWriteOp(op string) bool {
	o := strings.ToLower(op)
	return strings.Contains(o, "write") || strings.Contains(o, "append")
}

// manifestAndNativeEv scans written files for two self-spread tells: a package
// manifest rewritten to carry a lifecycle hook with a shell/exec payload (the
// injection step of a self-replicating worm), and a native addon (.node) dropped
// at runtime (loading arbitrary native code). Reads the intrinsic FS view so a
// write behind a force-executed export still counts.
func (c *verdictCtx) manifestAndNativeEv() (manifest, native []string) {
	for _, e := range c.intrinsic {
		if e.Cat != CatFS || !isWriteOp(e.Op) || len(e.Args) == 0 {
			continue
		}
		path := e.Args[0]
		content := ""
		if len(e.Args) > 1 {
			content = e.Args[1]
		}
		lp := strings.ToLower(path)
		if strings.Contains(lp, "package.json") &&
			reLifecycleKey.MatchString(content) && reShellPayload.MatchString(content) {
			manifest = append(manifest, truncField(path+": "+content, 200))
		}
		// Writing an exec/shell payload into ANOTHER installed package (node_modules,
		// or a ../sibling package's code) is supply-chain self-injection - infecting
		// packages already on disk. The target-other-package path plus a shell/exec
		// payload in the content is the tell.
		if (strings.Contains(lp, "node_modules/") || strings.HasPrefix(path, "../")) &&
			(strings.HasSuffix(lp, ".js") || strings.HasSuffix(lp, ".cjs") || strings.HasSuffix(lp, ".mjs") || strings.HasSuffix(lp, ".ts")) &&
			reShellPayload.MatchString(content) {
			manifest = append(manifest, truncField("inject "+path+": "+content, 200))
		}
		if reNativeAddonDrop.MatchString(lp) {
			native = append(native, path)
		}
	}
	return clipList(manifest), clipList(native)
}

// finalizeVerdict sums the reason weights (capped at 100), maps the score to a
// level, and renders the stable, weight-sorted reason/detail lists.
func finalizeVerdict(reasons []reason) Verdict {
	score := 0
	for _, r := range reasons {
		score += r.weight
	}
	if score > 100 {
		score = 100
	}

	sort.SliceStable(reasons, func(i, j int) bool { return reasons[i].weight > reasons[j].weight })
	texts := make([]string, len(reasons))
	details := make([]ReasonDetail, len(reasons))
	for i, r := range reasons {
		texts[i] = r.text
		details[i] = ReasonDetail{Text: r.text, Weight: r.weight, Evidence: r.evidence}
	}

	level := "clean"
	switch {
	case score >= 60:
		level = "malicious"
	case score >= 30:
		level = "suspicious"
	case score > 0:
		level = "low"
	}
	if len(texts) == 0 {
		texts = []string{"no security-relevant behavior observed"}
	}
	return Verdict{Score: score, Level: level, Reasons: texts, Details: details}
}

// --- evidence helpers (read-only views over the ctx) ---

// catEv gathers the events of a category as one-line evidence strings.
func (c *verdictCtx) catEv(cats ...Category) []string {
	want := map[Category]bool{}
	for _, cat := range cats {
		want[cat] = true
	}
	var out []string
	for _, e := range c.events {
		if want[e.Cat] {
			out = append(out, e.summary())
		}
	}
	return clipList(out)
}

// iocEv lists the members of an IOC set as evidence.
func (c *verdictCtx) iocEv(m map[string]struct{}) []string { return clipList(sortedKeys(m)) }

// fetchedEvalEv finds events that EXECUTED the placeholder payload from a
// simulated network response (download-and-execute): the fetched marker reaching
// eval/Function/vm (CatEval) OR a child_process spawn (CatProc), e.g. a C2 that
// polls a gist/paste for a command and `exec`s the response. Scans `intrinsic` so
// a payload behind force-execution still counts - executing fetched content is
// unambiguous malware regardless of how it was triggered.
func (c *verdictCtx) fetchedEvalEv() []string {
	const marker = "/* fetched */"
	var out []string
	for _, e := range c.intrinsic {
		if e.Cat != CatEval && e.Cat != CatProc {
			continue
		}
		if e.Note != "" && strings.Contains(e.Note, marker) && !looksLikeRowAccessorCodegen(e.Note) {
			out = append(out, e.summary())
			continue
		}
		for _, a := range e.Args {
			if strings.Contains(a, marker) && !looksLikeRowAccessorCodegen(a) {
				out = append(out, e.summary())
				break
			}
		}
	}
	return clipList(out)
}

// reRowAccessorCodegen matches the positional row-object builder a CSV/DSV parser
// generates - `return { col: d[0] || "", … }` - where a parameter is indexed by
// integer position (d[0], d[1], …). A data-binding library (d3-dsv's csvParse/
// autoType) compiles this with `new Function` from the COLUMN NAMES of its input;
// when force-execution feeds it the simulated `/* fetched */` response, the marker
// rides into the generated body as object keys (one column whose name is the whole
// JSON, or many) even though the function only constructs a data object and never
// executes fetched content as code. A genuine download-and-execute payload evals
// the response verbatim - an object literal / script with ZERO positional
// `param[int]` accessors - so even a single such accessor inside a `return {…}`
// builder reliably marks benign codegen and is a safe exclusion from fetchedEvalEv.
var reRowAccessorCodegen = regexp.MustCompile(`[\w$]+\[\d+\]\s*(?:\|\||,|\})`)

func looksLikeRowAccessorCodegen(body string) bool {
	return strings.Contains(body, "return") && reRowAccessorCodegen.MatchString(body)
}

// scanSets runs re over the deobfuscated members of every set, returning the
// matching raw values (whitespace-collapsed, length-bounded) as a set.
func scanSets(re *regexp.Regexp, deobfuscate bool, sets ...map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	for _, set := range sets {
		for v := range set {
			s := v
			if deobfuscate {
				s = deobfuscateViews(v)
			}
			if re.MatchString(s) {
				out[truncField(v, 200)] = struct{}{}
			}
		}
	}
	return out
}

// --- detectors (each returns its own reasons; run concurrently) ---

// exfilSourceEv lists the HIGH-CONFIDENCE exfil sources: a captured
// credential-shaped VALUE (the secret itself was seen leaving), or a read of an
// infostealer-grade store (browser login/cookie DB, crypto-wallet file, OS
// keychain - paths with no benign package use), including such a read performed
// through a spawned command. Deliberately NOT here: a bare credential-shaped env
// var NAME or a generic sensitive path like .env/.npmrc - those are read by plenty
// of legitimate tools, so on their own they are not proof of theft. Their actual
// exfiltration is caught instead by taintedExfilEv (the VALUE reaching a sink).
func (c *verdictCtx) exfilSourceEv() []string {
	var ev []string
	ev = append(ev, sortedKeys(c.mic.Secrets)...)
	for _, set := range []map[string]struct{}{c.mic.Paths, c.mic.FilesWritten} {
		for _, p := range sortedKeys(set) {
			if IsInfostealerPath(p) {
				ev = append(ev, "store:"+p)
			}
		}
	}
	for _, e := range c.intrinsic {
		if e.Cat == CatProc && spawnOps[e.Op] {
			if cmd := procCommand(e); IsInfostealerPath(cmd) {
				ev = append(ev, "cmd:"+truncField(cmd, 160))
			}
		}
	}
	return ev
}

// detectExfilAndProc scores credential exfiltration and spawns of untrusted
// external processes.
func (c *verdictCtx) detectExfilAndProc() []reason {
	var b reasonBuf
	// Exfiltration with PROVEN flow. Two independent ways to establish a secret
	// actually left the box: (1) a high-confidence source (captured credential value
	// or infostealer-store read) together with an external sink, or (2) taint - a
	// watched source value showed up at a sink, raw or base64/hex-encoded. Taint is
	// what defeats disguise: base64, hex, or binary framing all still carry the value
	// verbatim, so they match even though inspecting the payload as text would not
	// reveal a "secret". (Encryption/steganography defeat value-matching; those rely
	// on the source-store read or the correlated path-read/crypto signals instead.)
	src := c.exfilSourceEv()
	tainted := c.taintedExfilEv()
	if (len(src) > 0 && len(c.intrinsicNet) > 0) || len(tainted) > 0 {
		ev := clipList(append(append(append([]string{}, src...), tainted...), sortedKeys(c.intrinsicNet)...))
		b.addEv(60, ev, "exfiltrates sensitive data (credentials/keys/secret files) to an external endpoint (infostealer)")
	}
	// Structural reverse shell / backdoor: an interactive OS shell spawned while a
	// network socket is open. The shell carries no command of its own (see
	// reInteractiveShell), so it's only useful when its stdio is wired to the
	// socket - the canonical Node backdoor (`net.connect(...); spawn('/bin/sh');
	// sock.pipe(sh.stdin)`). This complements reReverseShell, which only catches the
	// shell-string form (`bash -i >& /dev/tcp/...`); here the wiring is in JS. Scored
	// from the intrinsic view so a payload behind a connect/export gate still counts.
	if c.seenIntrinsic[CatNet] > 0 {
		var sh []string
		for _, e := range c.intrinsic {
			if e.Cat == CatProc && spawnOps[e.Op] && reInteractiveShell.MatchString(procCommand(e)) {
				sh = append(sh, e.summary())
			}
		}
		if len(sh) > 0 {
			b.addEv(60, clipList(sh), "wires an interactive shell to a network socket (reverse shell / backdoor)")
		}
	}
	return b.rs
}

// detectDynamicCode scores the dynamic-code / decode / file / network family,
// most of it gated on correlation so benign build activity stays clean.
func (c *verdictCtx) detectDynamicCode() []reason {
	var b reasonBuf
	ic := c.ic

	if c.seen[CatNet] > 0 && (c.hardNet > 0 || ic.count(ic.Payloads) > 0) {
		b.addEv(20, c.catEv(CatNet), "performs network activity (%d call(s))", c.seen[CatNet])
	}
	if ev := c.fetchedEvalEv(); len(ev) > 0 && c.seenIntrinsic[CatNet] > 0 {
		b.addEv(60, ev, "executes network-fetched payload via eval/Function/vm (download & execute)")
	}
	if c.seen[CatEval] > 0 && c.correlated {
		b.addEv(20, c.catEv(CatEval), "executes code dynamically via eval/Function/vm (%d time(s))", c.seen[CatEval])
		if c.seen[CatEval] >= 5 {
			b.addEv(15, c.catEv(CatEval), "heavy dynamic-code / deobfuscation activity (%d events) - likely packed/obfuscated", c.seen[CatEval])
		}
	}
	// A decrypted/decoded payload whose content is itself a malware loader (process
	// exec + C2 / staged eval) is intrinsic proof of malice - see
	// decodedLoaderEvidence. Scored uncorrelated and heavily.
	if ev := decodedLoaderEvidence(c.mic.Decoded); len(ev) > 0 {
		b.addEv(60, ev, "decrypts/decodes an embedded malware loader (process exec / C2 / staged eval)")
	}
	// Decrypt-then-execute: the eval/Function body is the plaintext a decipher just
	// produced (`eval(decrypt(blob))`). Recognised structurally by the sandbox, so
	// it fires for ANY cipher (AES/DES/RC4/blowfish/…) and even when our decryption
	// couldn't recover valid code. Benign packages decrypt DATA, never code-to-eval,
	// so this is near-zero false-positive. Read from the intrinsic view (force-exec
	// surfaces the gated payload).
	{
		var ev []string
		for _, e := range c.intrinsic {
			if e.Cat == CatEval && e.Op == "decrypt-then-eval" {
				ev = append(ev, e.summary())
			}
		}
		if len(ev) > 0 {
			b.addEv(60, clipList(ev), "executes the plaintext of a runtime-decrypted blob via eval/Function (decrypt-then-execute loader)")
		}
	}
	// A base64-hidden URL the package decodes at runtime is a concealed C2/staging
	// endpoint - combined with the package actually doing network or dynamic-exec,
	// this is the DPRK loader pattern (atob(url) → fetch → eval). Host-INDEPENDENT,
	// and intrinsic so it scores even when surfaced only via force-execution.
	if c.seenIntrinsic[CatNet] > 0 || c.seenIntrinsic[CatEval] > 0 {
		if ev := decodedHiddenEndpointEv(c.mic.Decoded); len(ev) > 0 {
			b.addEv(60, ev, "deobfuscates a hidden network endpoint then fetches/executes it (concealed C2 / staged loader)")
		}
	}
	// Writing files is the norm for any build (dist/, caches, marker files), so the
	// generic "dropper" reason is scored only when correlated. Writes to
	// sensitive/persistence paths are scored unconditionally elsewhere.
	if n := ic.count(ic.FilesWritten); n > 0 && c.correlated {
		b.addEv(15, c.iocEv(ic.FilesWritten), "writes %d file(s) to disk (possible dropper)", n)
	}
	if n := ic.count(ic.FilesDeleted); n > 0 {
		b.addEv(18, c.iocEv(ic.FilesDeleted), "deletes %d file/dir(s) (destructive / anti-forensic)", n)
	}
	// A wallet address is theft-relevant only when it could be exfiltrated or
	// swapped over the network - a bare address in a donation banner is benign.
	if n := ic.count(ic.Wallets); n > 0 && (len(c.netURLs) > 0 || ic.count(ic.Payloads) > 0) {
		b.addEv(30, c.iocEv(ic.Wallets), "references %d crypto wallet address(es) over the network (clipboard hijack / theft)", n)
	}
	if n := ic.count(ic.Onion); n > 0 {
		b.addEv(25, c.iocEv(ic.Onion), "contacts %d Tor .onion address(es) (covert C2)", n)
	}
	// Credential-shaped tokens appear as static fixtures in benign libraries (zod
	// ships the jwt.io example token), so - like wallets - score only when the
	// secret is correlated with actual egress.
	if n := ic.count(ic.Secrets); n > 0 && (c.suspiciousNet || c.seen[CatNet] > 0 || ic.count(ic.Payloads) > 0) {
		b.addEv(20, c.iocEv(ic.Secrets), "handles %d credential-shaped secret(s) (token/key exfil)", n)
	}
	if n := ic.count(ic.Payloads); n > 0 && c.seen[CatNet] > 0 {
		b.addEv(15, c.iocEv(ic.Payloads), "transmits %d data payload(s) over the network (exfiltration)", n)
	}
	// Cipher use plus many file writes ⇒ likely ransomware.
	hasCipher := false
	for _, op := range sortedKeys(ic.CryptoOps) {
		if strings.Contains(op, "Cipher") {
			hasCipher = true
		}
	}
	if hasCipher && ic.count(ic.FilesWritten) >= 3 {
		b.addEv(25, clipList(append(sortedKeys(ic.CryptoOps), sortedKeys(ic.FilesWritten)...)),
			"encrypts files while writing many outputs (possible ransomware)")
	}
	// Base64/hex deobfuscation is benign on its own (source maps, inlined assets,
	// config), so it is scored only when correlated with a suspicious signal.
	if n := ic.count(ic.Decoded); n > 0 && c.correlated {
		b.addEv(10, c.iocEv(ic.Decoded), "decodes %d obfuscated/base64 blob(s)", n)
	}
	// Decoded payload that itself reaches for an untrusted endpoint/spawn is a
	// classic staged-loader pattern. Gated on NOTABLE net so benign decode-then-
	// build activity doesn't trip it.
	if ic.count(ic.Decoded) > 0 && c.suspiciousNet {
		ev := append(sortedKeys(ic.Decoded), c.catEv(CatNet)...)
		b.addEv(15, clipList(ev), "decoded content leads to network or process activity (staged loader)")
	}
	// Wiper: a destructive deletion that originates from dynamically decoded AND
	// evaluated code. Benign clean-up deletes build output directly (rimraf), never
	// through eval(atob(...)); this conjunction is near-zero in benign packages.
	if ic.count(ic.FilesDeleted) > 0 && ic.count(ic.Decoded) > 0 && c.seen[CatEval] > 0 {
		ev := append(sortedKeys(ic.FilesDeleted), sortedKeys(ic.Decoded)...)
		b.addEv(45, clipList(ev), "deletes files from dynamically decoded/evaluated code (wiper)")
	}
	return b.rs
}

// detectSensitivePaths scores sensitive env/path access and infostealer reads of
// browser/wallet/credential stores.
func (c *verdictCtx) detectSensitivePaths() []reason {
	var b reasonBuf
	ic := c.ic

	if c.suspiciousNet {
		for _, k := range sortedKeys(ic.EnvAccessed) {
			if IsSensitiveEnv(k) {
				b.add(25, "reads sensitive environment variable %q (credential theft)", k)
			}
		}
	}
	checkPaths := func(set map[string]struct{}, kind string, w int) {
		for _, p := range sortedKeys(set) {
			if IsSensitivePath(p) {
				b.add(w, "%s sensitive path %q", kind, p)
			}
		}
	}
	// A sensitive-path READ scores only when correlated with a genuinely suspicious
	// signal (an exfil-capable endpoint, or a captured secret - which includes the
	// credential file's own contents once read). A lone read with no observed way to
	// exfiltrate it is not theft.
	if c.correlated {
		checkPaths(ic.Paths, "reads", 25)
	}
	// A sensitive-path WRITE (dropping into .ssh, .aws, …) is tampering in its own
	// right, so it stays unconditional; autostart/boot writes are scored separately.
	checkPaths(ic.FilesWritten, "writes", 20)

	// Writing a critical system/auth/DNS config (/etc/hosts traffic redirection,
	// sudoers/pam auth backdoor, resolv.conf DNS hijack) is system subversion with
	// no benign package use - scored unconditionally and heavily, from `mic` so a
	// payload surfaced only by force-execution still counts.
	{
		var tamper []string
		for p := range c.mic.FilesWritten {
			if IsSystemTamperPath(p) {
				tamper = append(tamper, p)
			}
		}
		if len(tamper) > 0 {
			b.addEv(60, clipList(tamper), "writes a critical system/auth/DNS config file (%d) - system tampering", len(tamper))
		}
	}

	// Registry hijack: a written .npmrc/.yarnrc that repoints the package registry to
	// a non-official host - every future install would be served by the attacker.
	{
		var hj []string
		for _, e := range c.intrinsic {
			if e.Cat != CatFS || !isWriteOp(e.Op) || len(e.Args) < 2 {
				continue
			}
			lp := strings.ToLower(e.Args[0])
			if !strings.Contains(lp, ".npmrc") && !strings.Contains(lp, ".yarnrc") && !strings.Contains(lp, "bunfig.toml") {
				continue
			}
			if url, ok := IsRegistryHijack(e.Args[1]); ok {
				hj = append(hj, e.Args[0]+" → "+url)
			}
		}
		if len(hj) > 0 {
			b.addEv(45, clipList(hj), "repoints the package-manager registry to a non-official host (registry hijack)")
		}
	}

	// Infostealer: reading a browser credential/cookie store, crypto-wallet storage,
	// password manager, or cloud-credential file (ATT&CK T1555/T1539/T1552). These
	// paths are specific enough to have no benign npm use, so they score UNCORRELATED
	// - and from `mic` (force-exec included). Reads AND writes both count.
	hits := map[string]struct{}{}
	for _, set := range []map[string]struct{}{c.mic.Paths, c.mic.FilesWritten} {
		for p := range set {
			if IsInfostealerPath(p) {
				hits[p] = struct{}{}
			}
		}
	}
	if len(hits) > 0 {
		b.addEv(40, c.iocEv(hits), "reads browser/wallet/credential stores (infostealer: %d target(s))", len(hits))
	}
	return b.rs
}

// detectCommandSignatures scores the high-fidelity command/host signatures
// (reverse shells, droppers, persistence, miners, LOLBins, C2). These read from
// `mic` (scored + force-executed IOCs) since malware commonly hides a loader in a
// non-entry file that only runs under force-execution.
func (c *verdictCtx) detectCommandSignatures() []reason {
	var b reasonBuf
	mic := c.mic

	if ev := matchAnyCommand(mic.Commands, reReverseShell); len(ev) > 0 {
		b.addEv(60, clipList(ev), "opens a reverse shell / backdoor connection (%d command(s))", len(ev))
	}
	if ev := matchAnyCommand(mic.Commands, reDownloaderPipe); len(ev) > 0 {
		b.addEv(60, clipList(ev), "pipes a remote download straight into an interpreter (curl|bash-style loader)")
	}
	if ev := matchAnyCommand(mic.Commands, reDecodePipe); len(ev) > 0 {
		b.addEv(60, clipList(ev), "decodes a blob and pipes it straight into an interpreter (base64|sh-style loader)")
	}
	// Staged download-and-execute: a remote download written to a file that is then
	// chmod +x'd or run. The file-split twin of the curl|bash pipe; correlated on the
	// target path across commands, so it survives the shell splitting `&&` chains.
	if ev := stagedDownloadExecEv(mic.Commands); len(ev) > 0 {
		b.addEv(60, ev, "downloads a remote file and executes it (staged download-and-execute dropper)")
	}
	// Drop-and-execute: the sample writes a script then spawns an interpreter on
	// that exact file (FilesWritten ∩ interpreter command) - a detached temp-dir
	// dropper that survives past install (webpack-cache-clean shape).
	if ev := dropAndExecEv(mic.Commands, mic.FilesWritten); len(ev) > 0 {
		b.addEv(60, ev, "writes a script and runs it via a spawned interpreter (drop-and-execute dropper)")
	}
	// Manifest tampering: a written package.json carrying a lifecycle hook with a
	// shell/exec payload - the injection step of a self-replicating worm.
	mev, nev := c.manifestAndNativeEv()
	if len(mev) > 0 {
		b.addEv(60, mev, "injects a malicious hook/payload into a package manifest or another installed package (self-propagation / supply-chain injection)")
	}
	// Self-propagation: republishing to the registry at runtime. `npm publish` is the
	// whole job of a release tool (np/release-it/semantic-release), so it is NOT
	// malicious on its own - it counts only as the SPREAD step of a worm, i.e. when
	// the package also rewrites a manifest or shows other malice (credential theft /
	// suspicious egress). Then it's scored heavily; alone it is left clean.
	if pub := matchAnyCommand(mic.Commands, reSelfPropagate); len(pub) > 0 {
		if len(mev) > 0 || c.correlated {
			b.addEv(60, clipList(pub), "republishes a package to the registry at runtime (self-propagating worm)")
		}
	}
	// A runtime-dropped native addon (.node) loads arbitrary native code.
	if len(nev) > 0 {
		b.addEv(60, nev, "drops a native addon (.node) at runtime (loads arbitrary native code)")
	}
	if ev := matchAnyCommand(mic.Commands, rePrivEsc); len(ev) > 0 {
		b.addEv(30, clipList(ev), "attempts privilege escalation / system tampering (%d command(s))", len(ev))
	}
	// Impair defenses (T1562): kill/disable EDR/AV/SELinux/AppArmor/firewall.
	if ev := matchAnyCommand(mic.Commands, reDefenseEvasion); len(ev) > 0 {
		b.addEv(60, clipList(ev), "disables or kills security controls / firewall (defense evasion, %d command(s))", len(ev))
	}
	// Indicator removal (T1070): clear shell history, wipe logs, shred the dropper.
	if ev := matchAnyCommand(mic.Commands, reAntiForensics); len(ev) > 0 {
		b.addEv(45, clipList(ev), "clears history / wipes logs / shreds files (anti-forensics, %d command(s))", len(ev))
	}
	// Extract-and-execute dropper: an archive extractor (7z/zip/rar/xz/tar/…) plus
	// execution from a world-writable staging dir. The archive twin of the download
	// cradle - format-agnostic, so it catches the TTP even for formats we can't
	// unpack in-process. Requiring the staging-dir RUN keeps benign build-time
	// extraction (unpack to ./build) from matching.
	if ext := matchAnyCommand(mic.Commands, reArchiveExtract); len(ext) > 0 {
		if run := matchAnyCommand(mic.Commands, reExecFromStage); len(run) > 0 {
			b.addEv(60, clipList(append(ext, run...)), "extracts an archive and runs its contents from a temp dir (extract-and-execute dropper)")
		}
	}
	// Container escape (T1611): break out of a container into the host.
	if ev := matchAnyCommand(mic.Commands, reContainerEscape); len(ev) > 0 {
		b.addEv(60, clipList(ev), "attempts container escape into the host (nsenter/chroot/proc-1-root, %d command(s))", len(ev))
	}
	// Lateral movement over SSH (T1021.004).
	if ev := matchAnyCommand(mic.Commands, reLateralSSH); len(ev) > 0 {
		b.addEv(45, clipList(ev), "automated SSH/SCP with host-key checking disabled (lateral movement, %d command(s))", len(ev))
	}
	// ICMP / covert-channel tunneling (T1095).
	if ev := matchAnyCommand(mic.Commands, reICMPExfil); len(ev) > 0 {
		b.addEv(45, clipList(ev), "exfiltrates over ICMP / uses a covert tunnel (%d command(s))", len(ev))
	}
	// Fork bomb / resource-exhaustion DoS (T1499).
	if ev := matchAnyCommand(mic.Commands, reForkBomb); len(ev) > 0 {
		b.addEv(45, clipList(ev), "runs a fork bomb / resource-exhaustion payload (denial of service)")
	}
	// Crypto-clipper (T1115): a clipboard write carrying a wallet address - the
	// hallmark of swapping a copied address for the attacker's.
	{
		var clips []string
		for cmd := range mic.Commands {
			v := deobfuscateViews(cmd)
			if reClipboardWrite.MatchString(v) && reWalletAddr.MatchString(v) {
				clips = append(clips, truncField(cmd, 200))
			}
		}
		if len(clips) > 0 {
			b.addEv(60, clipList(clips), "writes a crypto wallet address to the clipboard (clipboard hijack / crypto-clipper)")
		}
	}
	// Runtime second-stage install (dropper): the package's code spawns a package
	// manager to fetch another package and load it. Scored heavily when the install
	// also carries stealth flags (no-save/silent), which legitimate build scripts
	// don't need. Commands are deobfuscated first.
	var stagers []string
	for cmd := range mic.Commands {
		v := deobfuscateViews(cmd)
		if reRuntimeInstall.MatchString(v) && reInstallStealth.MatchString(v) {
			stagers = append(stagers, truncField(cmd, 200))
		}
	}
	if len(stagers) > 0 {
		b.addEv(60, clipList(stagers), "fetches and runs a second-stage package at runtime (dropper / runtime install)")
	}
	// Persistence: writing to an autostart/boot location (cron, systemd, shell rc,
	// Run keys, LaunchAgents, …) - no benign reason for an npm package.
	if ev := matchContains(mic.FilesWritten, persistencePaths); len(ev) > 0 {
		b.addEv(60, clipList(ev), "installs persistence via an autostart/boot location (%d file(s))", len(ev))
	}
	// Git-hook install: code-exec on future git actions, but legitimate hook
	// managers (husky, lefthook, …) do exactly this, so it's scored low on its own
	// (those tools pass) and only reaches a malicious verdict combined with other
	// signals (a real hook-dropper also taints/exfils/obfuscates).
	if ev := matchContains(mic.FilesWritten, gitHookPaths); len(ev) > 0 {
		b.addEv(20, clipList(ev), "writes a git hook - runs on future git commits/checkouts (%d file(s))", len(ev))
	}
	// Scheduled-task persistence (T1053): runtime crontab/schtasks/at/systemd-enable.
	if ev := matchAnyCommand(mic.Commands, reScheduledTask); len(ev) > 0 {
		b.addEv(60, clipList(ev), "installs persistence via a scheduled task / cron / service (%d command(s))", len(ev))
	}
	// Cryptominer / resource hijacking (T1496): mining-pool protocols or miners,
	// scanned across commands, URLs, payloads and decoded blobs (deobfuscated).
	if miners := scanSets(reCryptominer, true, mic.Commands, mic.URLs, mic.Domains, mic.Payloads, mic.Decoded); len(miners) > 0 {
		b.addEv(60, c.iocEv(miners), "connects to a mining pool / runs a cryptominer (resource hijacking)")
	}
	// PowerShell / Windows-shell abuse (T1059.001 / T1059.003): encoded/hidden PS,
	// IEX download-and-exec, certutil/bitsadmin/mshta staging; deobfuscated first.
	if ev := c.iocEv(scanSets(rePowerShell, true, mic.Commands, mic.Decoded, mic.Payloads)); len(ev) > 0 {
		b.addEv(60, ev, "executes obfuscated/encoded PowerShell (in-memory download & exec)")
	}
	if ev := c.iocEv(scanSets(reWinShell, true, mic.Commands, mic.Decoded, mic.Payloads)); len(ev) > 0 {
		b.addEv(60, ev, "stages a payload via cmd.exe + certutil/bitsadmin/mshta (LOLBin)")
	}
	if ev := c.iocEv(scanSets(reCredDump, true, mic.Commands, mic.Decoded, mic.Payloads)); len(ev) > 0 {
		b.addEv(60, ev, "dumps OS credential stores (Keychain / Credential Manager / SAM)")
	}
	// Cloud instance metadata credential theft (T1552.005): reading the link-local
	// 169.254.169.254 / metadata endpoint for cloud IAM credentials. Very specific.
	if hits := scanSets(reCloudMetadata, false, mic.URLs, mic.Domains, mic.IPs, mic.Commands, mic.Decoded); len(hits) > 0 {
		b.addEv(40, c.iocEv(hits), "queries the cloud instance metadata API for IAM credentials (T1552.005)")
	}
	// DNS tunneling / exfil (T1048.003 / T1071.004).
	{
		hits := map[string]struct{}{}
		for _, set := range []map[string]struct{}{mic.Commands, mic.Domains, mic.URLs, mic.Decoded} {
			for v := range set {
				if reDNSExfil.MatchString(v) || dnsLabelLooksEncoded(v) {
					hits[v] = struct{}{}
				}
			}
		}
		if len(hits) > 0 {
			b.addEv(60, c.iocEv(hits), "exfiltrates over DNS / uses a DNS tunnel (covert channel)")
		}
	}
	// Out-of-band C2 / exfil infrastructure across every place a host can appear.
	{
		oob := map[string]struct{}{}
		for _, set := range []map[string]struct{}{mic.URLs, mic.Domains, mic.Onion, mic.Payloads, mic.Commands, mic.Decoded} {
			for _, m := range matchContains(set, oobC2Markers) {
				oob[m] = struct{}{}
			}
		}
		if len(oob) > 0 {
			b.addEv(30, c.iocEv(oob), "contacts out-of-band C2 / exfil infrastructure (interactsh/onion/paste/tunnel)")
		}
	}
	return b.rs
}

// detectEvasionAndEndpoints scores anti-analysis sandbox probing, host
// fingerprinting, and the bare presence of remote endpoints.
func (c *verdictCtx) detectEvasionAndEndpoints() []reason {
	var b reasonBuf
	// Debug-port backdoor (inspector.open) and DNS hijack (dns.setServers): both are
	// opened/redirected from the sample's own code, which a normal package never does
	// at install/import time. Scored from the intrinsic view.
	var insp, dnsHijack []string
	for _, e := range c.intrinsic {
		switch {
		case e.Cat == CatProcess && e.Op == "inspector.open":
			insp = append(insp, e.summary())
		case e.Cat == CatNet && e.Op == "dns.setServers":
			dnsHijack = append(dnsHijack, e.summary())
		}
	}
	if len(insp) > 0 {
		b.addEv(60, clipList(insp), "opens a debugger/inspector port (remote code-execution backdoor)")
	}
	if len(dnsHijack) > 0 {
		b.addEv(45, clipList(dnsHijack), "redirects DNS resolution via dns.setServers (DNS hijack / MITM)")
	}
	// Sandbox / VM / container / CI detection - an evasion technique: malware probes
	// whether it is being analyzed before deploying its payload. Scored from
	// `intrinsic` (force-executed behavior INCLUDED): the probe is malicious by
	// nature however it was reached, and SCBoX's anti-evasion layer deliberately
	// answers believably, so the very ATTEMPT is the indicator.
	//
	// Two tiers (see detectSandboxProbes): evasion-grade tells (container marker
	// files, the init cgroup, VM-guest devices/modules) have essentially no benign
	// runtime use, so ≥2 of them score standalone. Ambient host-probing
	// (/proc/cpuinfo, /proc/meminfo, DMI, the CI env cluster) is routine for build
	// tools, so it only escalates a SINGLE evasion tell when it corroborates a
	// genuinely suspicious signal.
	sandboxProbe, ambientProbe := detectSandboxProbes(c.intrinsic)
	switch {
	case len(sandboxProbe) >= 2:
		b.addEv(20, clipList(sandboxProbe), "probes for a sandbox/VM/container analysis environment (anti-analysis evasion)")
	case len(sandboxProbe) == 1 && ambientProbe && c.correlated:
		b.addEv(20, clipList(sandboxProbe), "probes for an analysis environment alongside suspicious activity (anti-analysis evasion)")
	}

	// Host fingerprinting (os.platform/userInfo/networkInterfaces) is routine for
	// picking the right prebuilt binary; it's only a recon signal when the gathered
	// identity could actually be exfiltrated (a real endpoint present).
	if c.seen[CatOS] > 0 && c.hardNet > 0 {
		b.addEv(8, c.catEv(CatOS), "fingerprints the host via the os module")
	}
	if c.hardNet > 0 {
		b.addEv(10, clipList(append(sortedKeys(c.netURLs), sortedKeys(c.netIPs)...)), "references %d remote endpoint(s)", c.hardNet)
	}
	return b.rs
}

// detectCustomTaint scores the user-defined YAML taint rules (--rules): for
// each rule, did a value served for one of its sources reach one of its sinks,
// raw or base64/hex-encoded? Same causal-flow standard as the built-in
// credential taint - a read alone never fires, only the value arriving at a
// sink does.
func (c *verdictCtx) detectCustomTaint() []reason {
	if len(c.taintRules) == 0 {
		return nil
	}
	spaces := map[string]string{
		rules.SinkNetwork: c.egress,
		rules.SinkCommand: c.cmdSpace,
		rules.SinkFile:    c.fileSpace,
	}
	var b reasonBuf
	for _, r := range c.taintRules {
		vals := c.taintVals[r.Name]
		if len(vals) == 0 {
			continue
		}
		var ev, sinksHit []string
		for _, sink := range r.Sinks {
			space := spaces[sink]
			if space == "" {
				continue
			}
			hit := false
			for _, val := range vals {
				for _, f := range encodedForms(val) {
					if len(f) >= 12 && strings.Contains(space, f) {
						ev = append(ev, sink+": "+truncField(val, 80))
						hit = true
						break
					}
				}
			}
			if hit {
				sinksHit = append(sinksHit, sink)
			}
		}
		if len(sinksHit) == 0 {
			continue
		}
		if r.Description != "" {
			ev = append(ev, "rule: "+r.Description)
		}
		b.addEv(r.EffectiveWeight(), clipList(ev),
			"custom taint rule %q: a watched source value reached a %s sink", r.Name, strings.Join(sinksHit, "/"))
	}
	return b.rs
}

// detectStaticObfuscation scores javascript-obfuscator second-stage loaders found
// in the package source by the inert static pass (op "obfuscated-loader"). This
// is a SOURCE-shape signal, not a behavior, so it stands on its own: it catches
// dormant loaders whose payload is gated behind a runtime argument/condition and
// never fires under detonation (the behavior-only detectors see nothing). In
// published npm code the RC4 string-array cradle is an almost-exclusive malware
// marker, so it is scored as a strong standalone finding rather than gated on
// correlation.
func (c *verdictCtx) detectStaticObfuscation() []reason {
	var b reasonBuf
	var files, recovered []string
	for _, e := range c.intrinsic {
		if e.Cat != CatEval {
			continue
		}
		switch e.Op {
		case "obfuscated-loader":
			files = append(files, e.summary())
		case "deobfuscated-loader":
			for _, a := range e.Args {
				recovered = append(recovered, a)
			}
		}
	}
	if len(files) == 0 {
		return b.rs
	}
	// High confidence: the loader was deobfuscated to a live network/exec payload.
	// The recovered C2 endpoint / capability is concrete evidence, so this scores
	// malicious on its own.
	if len(recovered) > 0 {
		b.addEv(60, clipList(recovered),
			"deobfuscated javascript-obfuscator loader to a live network/exec payload (recovered C2 / capability)")
		return b.rs
	}
	// Fingerprint only - the obfuscator string-array machinery is present but no
	// payload was recoverable statically (heavily multi-layered, or gated past what
	// the recovery driver exercises). Shipping RC4 string-array-obfuscated code in a
	// published npm package is itself a reliable malware marker (the benign sweep -
	// react/vue/webpack/typescript/uglify/terser/node-forge/crypto-js/csv-parse - is
	// clean), so it is scored malicious on the fingerprint alone.
	b.addEv(60, clipList(files),
		"ships javascript-obfuscator string-array-obfuscated loader code (%d file(s)) (dormant second-stage loader)", len(files))
	return b.rs
}
