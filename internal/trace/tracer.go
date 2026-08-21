// Package trace records a time-ordered behavioral log of everything a
// sandboxed sample does, and derives indicators of compromise (IOCs) and a
// verdict from it. It is the single source of truth for analysis output.
package trace

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"scbox/internal/rules"
)

// Category groups events by the kind of capability the sample reached for.
type Category string

const (
	CatModule  Category = "module"    // require()/import of a builtin or dependency
	CatFS      Category = "fs"        // filesystem access
	CatNet     Category = "net"       // network (http/https/net/dns/tls)
	CatProc    Category = "proc"      // process spawning (child_process)
	CatEval    Category = "eval"      // dynamic code execution (eval/Function/vm)
	CatProcess Category = "process"   // process global access (env, argv, exit...)
	CatConsole Category = "console"   // console output from the sample
	CatTimer   Category = "timer"     // setTimeout/setInterval scheduling
	CatCrypto  Category = "crypto"    // crypto / hashing / ciphers
	CatOS      Category = "os"        // host fingerprinting (os module)
	CatLifecyc Category = "lifecycle" // npm lifecycle script execution
	CatExplore Category = "explore"   // force-execution of exports/files
	CatEnv     Category = "env"       // environment variable reads
)

// Event is a single recorded action, ordered by Seq.
type Event struct {
	Seq    int           `json:"seq"`
	At     time.Duration `json:"at_ns"`
	Cat    Category      `json:"category"`
	Op     string        `json:"op"`
	Args   []string      `json:"args,omitempty"`
	Note   string        `json:"note,omitempty"`
	Source string        `json:"source,omitempty"` // package the action is attributed to
	// Muted marks behavior recorded while the sandbox was force-executing/fuzzing
	// exported functions with synthetic args. It still appears in the trace (the
	// analyst can see what was exercised) but is EXCLUDED from the verdict - a
	// benign library invoked with fuzz args is not the sample acting maliciously.
	Muted bool `json:"muted,omitempty"`
}

// Tracer collects events and IOCs during a single analysis run. It is safe for
// concurrent use even though the sandbox itself runs single-threaded, because
// timers and recovery paths may record from helper goroutines.
type Tracer struct {
	mu     sync.Mutex
	start  time.Time
	seq    int
	events []Event
	iocs   *IOCSet
	scope  string // current package attribution, stamped onto events

	// devScopes names packages reached only via the analyzed package's
	// devDependencies. Their behavior is recorded and reported, but routed into
	// devIOCs and excluded from the verdict score: devDeps are never installed or
	// run by a consumer, and benign dev tooling (eslint/cypress/babel) would
	// otherwise inflate the verdict. See MarkDevScopes.
	devScopes map[string]bool
	devIOCs   *IOCSet

	// muted is set by the sandbox while it force-executes/fuzzes exported functions
	// with synthetic args. Events recorded then are tagged Muted (kept in the trace
	// but excluded from the verdict), and IOC writes are routed to mutedIOCs (never
	// scored), so a benign library exercised by the fuzzer can't manufacture a
	// verdict.
	muted     bool
	mutedIOCs *IOCSet

	// watched holds the VALUES SCBoX handed back for sensitive sources - the bait
	// for credential-shaped env vars and the content of credential/secret files the
	// sample read. The verdict later checks whether any of these (raw, or base64/hex
	// encoded) reached a network sink, which is direct proof a secret VALUE flowed
	// out (vs. a tool merely reading env/files and making unrelated requests). This
	// is the taint that makes exfil detection causal and disguise-resistant. See
	// WatchSecret and verdictCtx.taintedExfilEv.
	watched map[string]struct{}

	// taintRules are the user-defined YAML taint rules for this run (--rules).
	// taintVals holds, per rule name, the source VALUES the sandbox handed back
	// for that rule's matching env/file sources - the user-defined analogue of
	// `watched`, checked against each rule's own sinks by detectCustomTaint.
	taintRules []rules.Rule
	taintVals  map[string]map[string]struct{}
}

// SetTaintRules installs the user-defined taint rules for this run. The slice
// is read-only after detonation starts, so forked worker tracers share it.
func (t *Tracer) SetTaintRules(rs []rules.Rule) {
	t.mu.Lock()
	t.taintRules = rs
	t.mu.Unlock()
}

// TaintRules returns the user-defined taint rules (nil when none were loaded).
func (t *Tracer) TaintRules() []rules.Rule {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.taintRules
}

// WatchTaint registers a source value served for one of `rule`'s sources, to be
// matched against that rule's sinks. Same bounds policy as WatchSecret: short
// values would match incidentally, oversized ones are capped.
func (t *Tracer) WatchTaint(rule, val string) {
	if len(val) < 12 {
		return
	}
	if len(val) > 8192 {
		val = val[:8192]
	}
	t.mu.Lock()
	if t.taintVals == nil {
		t.taintVals = map[string]map[string]struct{}{}
	}
	if t.taintVals[rule] == nil {
		t.taintVals[rule] = map[string]struct{}{}
	}
	t.taintVals[rule][val] = struct{}{}
	t.mu.Unlock()
}

// taintSnapshot returns the per-rule watched values.
func (t *Tracer) taintSnapshot() map[string][]string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string][]string, len(t.taintVals))
	for rule, vals := range t.taintVals {
		out[rule] = sortedKeys(vals)
	}
	return out
}

// WatchSecret registers a sensitive source VALUE to watch for at network sinks
// (taint tracking). Short values are ignored - they'd match incidentally - and
// long ones are capped so an oversized file can't bloat the set.
func (t *Tracer) WatchSecret(val string) {
	if len(val) < 12 {
		return
	}
	if len(val) > 8192 {
		val = val[:8192]
	}
	t.mu.Lock()
	if t.watched == nil {
		t.watched = map[string]struct{}{}
	}
	t.watched[val] = struct{}{}
	t.mu.Unlock()
}

// watchedSecrets returns a snapshot of the registered source values.
func (t *Tracer) watchedSecrets() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return sortedKeys(t.watched)
}

// SetMuted toggles fuzz-sweep muting and returns the previous value, so the
// sandbox can save/restore it around a nested sweep.
func (t *Tracer) SetMuted(m bool) bool {
	t.mu.Lock()
	prev := t.muted
	t.muted = m
	t.mu.Unlock()
	return prev
}

// Muted reports the current mute state, so a deferred callback (e.g. a timer) can
// be replayed later under the same scoring rules it was scheduled with.
func (t *Tracer) Muted() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.muted
}

// New returns a Tracer with the clock started.
func New() *Tracer {
	return &Tracer{start: time.Now(), iocs: newIOCSet(), devIOCs: newIOCSet(), mutedIOCs: newIOCSet(), scope: "(root)"}
}

// MarkDevScopes records which package scopes belong to the devDependency tree so
// their indicators are kept out of the analyzed package's verdict.
func (t *Tracer) MarkDevScopes(names []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.devScopes == nil {
		t.devScopes = make(map[string]bool, len(names))
	}
	for _, n := range names {
		t.devScopes[n] = true
	}
}

// isDevScope reports whether s is attributed to the devDependency tree.
func (t *Tracer) isDevScope(s string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.devScopes[s]
}

// sink selects the IOC set indicators discovered under the current scope belong
// to: the discard set while fuzz-muted, the dev set for devDependency tooling,
// the main (scored) set otherwise.
func (t *Tracer) sink() *IOCSet {
	t.mu.Lock()
	muted := t.muted
	dev := t.devScopes[t.scope]
	t.mu.Unlock()
	switch {
	case muted:
		return t.mutedIOCs
	case dev:
		return t.devIOCs
	default:
		return t.iocs
	}
}

// DevIOCs exposes indicators attributed to the devDependency tree (reported
// separately, never scored).
func (t *Tracer) DevIOCs() *IOCSet { return t.devIOCs }

// SetScope sets the package name subsequent events are attributed to, returning
// the previous scope so callers can restore it.
func (t *Tracer) SetScope(s string) string {
	t.mu.Lock()
	prev := t.scope
	t.scope = s
	t.mu.Unlock()
	return prev
}

// Scope returns the current attribution scope.
func (t *Tracer) Scope() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.scope
}

// IOCs exposes the accumulated indicators.
func (t *Tracer) IOCs() *IOCSet { return t.iocs }

// Fork returns a worker tracer that shares this tracer's start time - so the
// timestamps of events both tracers record stay on one comparable clock - but
// records into its own independent buffers. Used to drive a separate goja VM on
// another goroutine; Absorb folds the results back in.
func (t *Tracer) Fork() *Tracer {
	t.mu.Lock()
	devScopes := t.devScopes   // read-only during detonation; safe to share
	taintRules := t.taintRules // likewise
	t.mu.Unlock()
	return &Tracer{start: t.start, iocs: newIOCSet(), devIOCs: newIOCSet(), mutedIOCs: newIOCSet(), scope: "(root)", devScopes: devScopes, taintRules: taintRules}
}

// Absorb merges the events and IOCs collected by worker tracers into t, then
// re-sorts the combined event log by timestamp and renumbers it so the report
// reads as a single coherent timeline regardless of which VM produced an event.
func (t *Tracer) Absorb(workers ...*Tracer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, w := range workers {
		if w == nil {
			continue
		}
		w.mu.Lock()
		t.events = append(t.events, w.events...)
		w.mu.Unlock()
		t.iocs.merge(w.iocs)
		if w.devIOCs != nil {
			t.devIOCs.merge(w.devIOCs)
		}
		if w.mutedIOCs != nil {
			t.mutedIOCs.merge(w.mutedIOCs)
		}
		// Carry watched source values over so taint-based exfil detection works when
		// a package detonates in a worker VM (parallel dependency-tree analysis).
		w.mu.Lock()
		if len(w.watched) > 0 {
			if t.watched == nil {
				t.watched = map[string]struct{}{}
			}
			for v := range w.watched {
				t.watched[v] = struct{}{}
			}
		}
		for rule, vals := range w.taintVals {
			if t.taintVals == nil {
				t.taintVals = map[string]map[string]struct{}{}
			}
			if t.taintVals[rule] == nil {
				t.taintVals[rule] = map[string]struct{}{}
			}
			for v := range vals {
				t.taintVals[rule][v] = struct{}{}
			}
		}
		w.mu.Unlock()
	}
	sort.SliceStable(t.events, func(i, j int) bool { return t.events[i].At < t.events[j].At })
	for i := range t.events {
		t.events[i].Seq = i + 1
	}
	t.seq = len(t.events)
}

// Events returns a copy of the recorded events.
func (t *Tracer) Events() []Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Event, len(t.events))
	copy(out, t.events)
	return out
}

// Record appends an event and auto-scans its args for network IOCs. Builtins
// add typed IOCs (paths, commands, env, decoded blobs) via the Add* helpers.
func (t *Tracer) Record(cat Category, op string, args ...string) {
	t.mu.Lock()
	t.seq++
	muted := t.muted
	t.events = append(t.events, Event{
		Seq:    t.seq,
		At:     time.Since(t.start),
		Cat:    cat,
		Op:     op,
		Args:   args,
		Source: t.scope,
		Muted:  muted,
	})
	t.mu.Unlock()
	// Always scan - but sink() routes muted (fuzz-sweep) args to the discard
	// mutedIOCs set, so they never seed the SCORED IOCs (no FP), while remaining
	// available to high-fidelity intrinsic-malice signals via the merged `mic`
	// view in Verdict (e.g. credentials exfiltrated by a force-executed stealer).
	s := t.sink()
	for _, a := range args {
		s.scan(a)
	}
}

// Note appends an event carrying a free-form note (and still scans it).
func (t *Tracer) Note(cat Category, op, note string, args ...string) {
	t.mu.Lock()
	t.seq++
	muted := t.muted
	t.events = append(t.events, Event{
		Seq:    t.seq,
		At:     time.Since(t.start),
		Cat:    cat,
		Op:     op,
		Args:   args,
		Note:   note,
		Source: t.scope,
		Muted:  muted,
	})
	t.mu.Unlock()
	// See Record: muted scans route to the discard set via sink(), not the scored
	// IOCs, so they can't cause false positives but stay available to intrinsic
	// signals.
	s := t.sink()
	s.scan(note)
	for _, a := range args {
		s.scan(a)
	}
}

func (t *Tracer) AddDomain(d string)     { s := t.sink(); s.add(&s.Domains, d) }
func (t *Tracer) AddPath(p string)       { s := t.sink(); s.add(&s.Paths, p) }
func (t *Tracer) AddCommand(c string)    { s := t.sink(); s.add(&s.Commands, c) }
func (t *Tracer) AddEnv(k string)        { s := t.sink(); s.add(&s.EnvAccessed, k) }
func (t *Tracer) AddDropped(p string)    { s := t.sink(); s.add(&s.FilesWritten, p) }
func (t *Tracer) AddDeleted(p string)    { s := t.sink(); s.add(&s.FilesDeleted, p) }
func (t *Tracer) AddHeader(h string)     { s := t.sink(); s.add(&s.Headers, h) }
func (t *Tracer) AddPayload(p string)    { s := t.sink(); s.add(&s.Payloads, p) }
func (t *Tracer) AddCrypto(a string)     { s := t.sink(); s.add(&s.CryptoOps, a) }
func (t *Tracer) AddDependency(d string) { s := t.sink(); s.add(&s.Dependencies, d) }

// AddDecoded records a base64/hex-decoded or decrypted blob and rescans it for
// nested IOCs (decoded payloads frequently hide the real URLs and commands).
//
// Unlike most Add* helpers, this ALWAYS scores into the main IOC set even while
// the sandbox is fuzz-muted: a decoded/decrypted blob is the package's OWN
// hardcoded payload being unwrapped (the ciphertext/encoded data was baked into
// the sample), so a C2 URL or command recovered from it is a genuine indicator no
// matter which code path surfaced it - including a payload gated behind a magic
// argument that only force-execution supplies. Without this, malware that does
// `eval(decrypt(blob))` inside an exported function would have its recovered C2
// URL muted away. The dev-tree routing is still honored.
func (t *Tracer) AddDecoded(decoded string) {
	const max = 4096
	shown := decoded
	if len(shown) > max {
		shown = shown[:max] + "...(truncated)"
	}
	s := t.scoredSink()
	s.add(&s.Decoded, shown)
	s.scan(decoded)
}

// scoredSink is like sink but never returns the muted discard set - used for
// intrinsic indicators (decoded/decrypted payloads) that must score regardless of
// the fuzz-mute state. It still routes dev-tree behavior to devIOCs.
func (t *Tracer) scoredSink() *IOCSet {
	t.mu.Lock()
	dev := t.devScopes[t.scope]
	t.mu.Unlock()
	if dev {
		return t.devIOCs
	}
	return t.iocs
}

// SourceStat summarizes the risky activity attributed to one package.
type SourceStat struct {
	Source  string `json:"source"`
	Events  int    `json:"events"`
	Network int    `json:"network"`
	Process int    `json:"process"`
	Eval    int    `json:"eval"`
	FS      int    `json:"fs"`
	Risk    int    `json:"risk"` // weighted, for ranking
}

// SourceStats returns per-package activity, ranked by risk (most suspicious
// first). This is what pinpoints which dependency in the tree is malicious.
func (t *Tracer) SourceStats() []SourceStat {
	stats := map[string]*SourceStat{}
	for _, e := range t.Events() {
		s := stats[e.Source]
		if s == nil {
			s = &SourceStat{Source: e.Source}
			stats[e.Source] = s
		}
		s.Events++
		switch e.Cat {
		case CatNet:
			s.Network++
			s.Risk += 3
		case CatProc:
			s.Process++
			s.Risk += 5
		case CatEval:
			s.Eval++
			s.Risk += 2
		case CatFS:
			s.FS++
			s.Risk += 2
		case CatEnv:
			s.Risk += 2
		}
	}
	out := make([]SourceStat, 0, len(stats))
	for _, s := range stats {
		out = append(out, *s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Risk > out[j].Risk })
	return out
}

// MarshalEvents renders the event log as pretty JSON.
func (t *Tracer) MarshalEvents() string {
	b, _ := json.MarshalIndent(t.Events(), "", "  ")
	return string(b)
}

func durMs(d time.Duration) string {
	return fmt.Sprintf("%6.1fms", float64(d)/float64(time.Millisecond))
}
