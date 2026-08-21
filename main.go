// Command scbox detonates an untrusted npm package - and its entire dependency
// tree - inside a pure-Go sandbox, and reports what each package tried to do: a
// behavioral trace, extracted IOCs, and a triage verdict. Nothing the code does
// touches the host: every capability is a faked, logged stub, and the fake
// environment is built to look like a real developer machine so evasive malware
// detonates instead of hiding.
//
// Usage:
//
//	scbox [flags] <package-dir | package.tgz>
package main

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"scbox/internal/npm"
	"scbox/internal/registry"
	"scbox/internal/rules"
	"scbox/internal/sandbox"
	"scbox/internal/third_party/term"
	"scbox/internal/trace"
)

// usageText is the grouped --help layout. The stdlib flag package only prints a
// flat alphabetical dump (flag.PrintDefaults); grouping the flags by purpose and
// ordering them the way they are actually reached makes the help readable. Keep
// this in sync with the flag definitions below - every flag appears exactly once.
const usageText = `scbox - npm package (and dependency tree) malware detonation sandbox

Usage:
  scbox [flags] <package-dir | package.tgz | name[@version]>
  scbox npm install <pkg>...   scan, then install only if the scan passes
  scbox install <pkg>...       shorthand for the install gate
  scbox version

Install gate (scbox npm/yarn/pnpm install ...), configured via env:
  SCBOX_FAIL_ON=LEVEL      block threshold: low|suspicious|malicious (default suspicious)
  SCBOX_FORCE=1            install anyway after a block (interactive: prompts to confirm)
  SCBOX_FORCE=install-anyway  install anyway with no prompt (for CI/non-interactive)
  SCBOX_ALLOW_UNSCANNED=1  allow git/URL specs that can't be statically scanned
  SCBOX_REPORT=1           print the full report per package, not the compact verdict
  SCBOX_VERBOSE=1          stream analysis progress   SCBOX_EXPLAIN=1  show evidence

Output:
  -json                emit the full report as JSON
  -e, -explain         expand each verdict reason with the evidence behind it
  -trace               append the full behavioral event trace (very long)
  -v, -verbose         stream progress to stderr while analyzing
  -fail-on LEVEL       exit non-zero when the verdict is at least LEVEL
                       (low|suspicious|malicious) - for use as an install gate

Analysis scope:
  -no-deps             do not resolve/analyze the dependency tree
  -no-explore          skip force-execution of exports/files
  -dev                 also resolve and detonate devDependencies (off by default;
                       npm install <pkg> never runs them and they don't score)
  -max-depth N         maximum dependency depth to descend (default 6)
  -max-packages N      maximum packages to materialize (default 200)
  -platform NAME       fake platform reported to the sample (default linux)
  -rules FILE          YAML file of custom taint rules (sources→sinks)

Limits:
  -timeout DUR         wall-clock budget per executed entry point (default 5s)
  -total-budget DUR    hard cap on the whole analysis (default 1m0s)
  -j, -jobs N          parallel sandbox workers, 1 = sequential (default 8)
  -mem-limit-mb N      worker memory cap in MB, 0 = unlimited (default 1024)

Network & cache:
  -offline             never fetch from the registry; analyze on-disk only
  -registry URL        npm registry base URL (default https://registry.npmjs.org)
  -cache-dir DIR       cache downloaded tarballs on disk (default: memory-only)
`

// version is the build's version string, overridable at link time with
//
//	go build -ldflags "-X main.version=v1.2.3"
var version = "dev"

type options struct {
	timeout     time.Duration
	totalBudget time.Duration
	platform    string
	explore     bool
	deps        bool
	dev         bool // also resolve + detonate devDependencies (off by default: never installed/run by `npm install <pkg>`, and excluded from the verdict)
	offline     bool
	maxDepth    int
	maxPkgs     int
	jobs        int // parallel explore workers (each its own goja VM); 1 = sequential
	registryURL string
	cacheDir    string // opt-in on-disk tarball cache; "" = memory-only (default)
	memLimitMB  int    // worker memory limit in MB; 0 = no cap
	asJSON      bool
	summary     bool // install-gate: suppress the full report; caller prints a compact per-target verdict line
	showTrace   bool
	explain     bool         // expand each verdict reason with its supporting evidence
	verbose     bool         // stream progress to stderr (diagnose hangs)
	failOn      string       // exit non-zero when verdict level >= this (clean<low<suspicious<malicious); "" = never
	taintRules  []rules.Rule // user-defined YAML taint rules (--rules)
}

// wireOptions is a gob-encodable mirror of options. options carries only
// unexported fields, which gob refuses to encode, so the run configuration is
// marshalled through this exported struct when shipping it to the jailed worker.
type wireOptions struct {
	Timeout     time.Duration
	TotalBudget time.Duration
	Platform    string
	Explore     bool
	Deps        bool
	Dev         bool
	Offline     bool
	MaxDepth    int
	MaxPkgs     int
	Jobs        int
	RegistryURL string
	CacheDir    string
	MemLimitMB  int
	AsJSON      bool
	ShowTrace   bool
	Explain     bool
	Verbose     bool
	FailOn      string
	TaintRules  []rules.Rule
}

// GobEncode lets a workerRequest carrying options round-trip across the pipe to
// the jailed worker (see worker.go).
func (o options) GobEncode() ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(wireOptions{
		Timeout:     o.timeout,
		TotalBudget: o.totalBudget,
		Platform:    o.platform,
		Explore:     o.explore,
		Deps:        o.deps,
		Dev:         o.dev,
		Offline:     o.offline,
		MaxDepth:    o.maxDepth,
		MaxPkgs:     o.maxPkgs,
		Jobs:        o.jobs,
		RegistryURL: o.registryURL,
		CacheDir:    o.cacheDir,
		MemLimitMB:  o.memLimitMB,
		AsJSON:      o.asJSON,
		ShowTrace:   o.showTrace,
		Explain:     o.explain,
		Verbose:     o.verbose,
		FailOn:      o.failOn,
		TaintRules:  o.taintRules,
	})
	return buf.Bytes(), err
}

// GobDecode reconstructs options on the worker side.
func (o *options) GobDecode(b []byte) error {
	var w wireOptions
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&w); err != nil {
		return err
	}
	*o = options{
		timeout:     w.Timeout,
		totalBudget: w.TotalBudget,
		platform:    w.Platform,
		explore:     w.Explore,
		deps:        w.Deps,
		dev:         w.Dev,
		offline:     w.Offline,
		maxDepth:    w.MaxDepth,
		maxPkgs:     w.MaxPkgs,
		jobs:        w.Jobs,
		registryURL: w.RegistryURL,
		cacheDir:    w.CacheDir,
		memLimitMB:  w.MemLimitMB,
		asJSON:      w.AsJSON,
		showTrace:   w.ShowTrace,
		explain:     w.Explain,
		verbose:     w.Verbose,
		failOn:      w.FailOn,
		taintRules:  w.TaintRules,
	}
	return nil
}

// verdictRank orders verdict levels for the --fail-on gate.
var verdictRank = map[string]int{"clean": 0, "low": 1, "suspicious": 2, "malicious": 3}

func main() {
	if os.Getenv("SCBOX_WORKER") == "1" {
		runWorker()
		return
	}
	// Subcommands that wrap a package manager are dispatched before flag
	// parsing so the wrapped tool's own flags (e.g. `npm i foo --save-dev`)
	// don't collide with scbox's flag set. This lets users gate installs with
	//   scbox npm install <pkg>     (or:  scbox install <pkg>)
	// without sourcing anything into their shell rc.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "npm", "pnpm", "yarn":
			os.Exit(runPMGate(os.Args[1], os.Args[2:]))
		case "install", "i", "add", "ci":
			os.Exit(runPMGate("npm", os.Args[1:]))
		}
	}

	var o options
	flag.DurationVar(&o.timeout, "timeout", 5*time.Second, "wall-clock budget per executed entry point")
	flag.DurationVar(&o.totalBudget, "total-budget", 60*time.Second, "hard cap on the whole analysis")
	flag.StringVar(&o.platform, "platform", "linux", "fake platform reported to the sample")
	noExplore := flag.Bool("no-explore", false, "skip force-execution of exports/files")
	noDeps := flag.Bool("no-deps", false, "do not resolve/analyze the dependency tree")
	flag.BoolVar(&o.dev, "dev", false, "also resolve and detonate devDependencies (off by default - they are never installed or run by `npm install <pkg>` and do not affect the verdict; enabling greatly enlarges the tree and slows analysis)")
	flag.BoolVar(&o.offline, "offline", false, "never fetch from the registry; analyze only what's on disk")
	flag.IntVar(&o.maxDepth, "max-depth", 6, "maximum dependency depth to descend")
	flag.IntVar(&o.maxPkgs, "max-packages", 200, "maximum packages to materialize")
	flag.IntVar(&o.jobs, "jobs", defaultJobs(), "parallel explore workers, each its own sandbox VM (1 = sequential)")
	flag.IntVar(&o.jobs, "j", defaultJobs(), "shorthand for --jobs")
	flag.StringVar(&o.registryURL, "registry", "https://registry.npmjs.org", "npm registry base URL")
	flag.StringVar(&o.cacheDir, "cache-dir", "", "opt-in directory to cache downloaded tarballs on disk (default: memory-only, nothing persisted)")
	flag.IntVar(&o.memLimitMB, "mem-limit-mb", 1024, "worker memory cap in MB (0 = unlimited)")
	flag.BoolVar(&o.asJSON, "json", false, "emit the full report as JSON")
	flag.BoolVar(&o.showTrace, "trace", false, "append the full behavioral event trace after the report (very long; off by default)")
	flag.BoolVar(&o.explain, "explain", false, "expand each verdict reason with the concrete evidence behind it")
	flag.BoolVar(&o.explain, "e", false, "shorthand for --explain")
	flag.BoolVar(&o.verbose, "verbose", false, "stream progress to stderr (useful for diagnosing slow/large dependency trees)")
	flag.BoolVar(&o.verbose, "v", false, "shorthand for --verbose")
	flag.StringVar(&o.failOn, "fail-on", "", "exit non-zero when verdict is at least this level: low|suspicious|malicious (for use as an install gate)")
	rulesPath := flag.String("rules", "", "path to a YAML file of custom taint rules (sources→sinks); see docs for the schema")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	flag.Parse()
	o.explore = !*noExplore
	o.deps = !*noDeps
	if *rulesPath != "" {
		rs, err := rules.Load(*rulesPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scbox: --rules:", err)
			os.Exit(2)
		}
		o.taintRules = rs
	}

	// `scbox version` prints the build version.
	if a := flag.Arg(0); a == "version" || a == "--version" {
		fmt.Printf("scbox %s\n", version)
		return
	}

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	res, err := run(flag.Arg(0), o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scbox:", err)
		os.Exit(1)
	}

	// Install-gate mode: non-zero exit if the verdict crosses the threshold.
	if o.failOn != "" && verdictRank[res.Level] >= verdictRank[o.failOn] {
		fmt.Fprintf(os.Stderr, "\nscbox: BLOCKED - verdict %q meets --fail-on %q\n", res.Level, o.failOn)
		os.Exit(3)
	}
}

// runPMGate scans each package being added before handing off to the real
// package manager. It is the no-shell-rc install gate:
//
//	scbox npm install lodash react        # scans lodash & react, then runs npm
//	scbox install lodash                  # shorthand
//
// Config via env: SCBOX_FAIL_ON (default "suspicious"), SCBOX_FORCE,
// SCBOX_VERBOSE, SCBOX_EXPLAIN (show the evidence behind each verdict reason).
// Returns the process exit code.
func runPMGate(pm string, pmArgs []string) int {
	failOn := os.Getenv("SCBOX_FAIL_ON")
	if failOn == "" {
		failOn = "suspicious"
	}

	o := defaultOptions()
	o.verbose = os.Getenv("SCBOX_VERBOSE") != ""
	o.explain = os.Getenv("SCBOX_EXPLAIN") != ""
	o.showTrace = false
	// The gate prints a compact per-target verdict (pass/suspicious/malicious +
	// score) instead of the full detonation report - a big tree would otherwise
	// flood the terminal. Set SCBOX_REPORT=1 to get the full report.
	o.summary = os.Getenv("SCBOX_REPORT") == ""

	// Only install-family verbs pull packages onto the machine; everything else
	// (list, run, uninstall, …) is passed straight through to the real tool.
	verb := ""
	if len(pmArgs) > 0 {
		verb = pmArgs[0]
	}
	if !isInstallVerb(verb) {
		return execPM(pm, pmArgs)
	}

	specs, omitDev := parseInstallArgs(pmArgs)
	// `npm install` / `npm ci` pull devDependencies too, unless production/omit=dev.
	o.dev = !omitDev

	// Decide which package specs to scan. A bare `install` / `ci` scans every
	// direct dependency from ./package.json (each gets its own verdict line);
	// otherwise the named packages.
	var scanSpecs []string
	if verb == "ci" || len(specs) == 0 {
		if _, err := os.Stat("package.json"); err != nil {
			fmt.Fprintln(os.Stderr, "scbox: no package.json in the current directory - nothing to gate; running "+pm)
			return execPM(pm, pmArgs)
		}
		deps, err := directDepSpecs(o.dev)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scbox: cannot read package.json: %v\n", err)
			return 4
		}
		scanSpecs = deps
	} else {
		for _, s := range specs {
			if classifySpec(s) == specRemote {
				// git/URL specs can't be fetched+analyzed by the registry loader.
				if os.Getenv("SCBOX_ALLOW_UNSCANNED") != "1" {
					fmt.Fprintf(os.Stderr, "\033[31mscbox: cannot statically analyze %q (git/URL install)\033[0m\n", s)
					fmt.Fprintln(os.Stderr, "scbox: refusing. Set SCBOX_ALLOW_UNSCANNED=1 to install it unscanned.")
					return 4
				}
				fmt.Fprintf(os.Stderr, "\033[33mscbox: %q can't be scanned (git/URL) - installing unscanned per SCBOX_ALLOW_UNSCANNED\033[0m\n", s)
				continue
			}
			scanSpecs = append(scanSpecs, s)
		}
	}
	if len(scanSpecs) == 0 {
		return execPM(pm, pmArgs)
	}
	return gateScan(pm, pmArgs, scanSpecs, o, failOn)
}

// gateScan analyzes each dependency spec and streams a colored one-line verdict
// per dependency as it completes - green = pass, yellow = suspicious, red =
// malicious - then installs only if nothing meets the fail threshold. Deps are
// analyzed in parallel (each analysis itself single-worker); results print in
// completion order. Fail-closed: any un-analyzable dep aborts the install.
func gateScan(pm string, pmArgs, specs []string, o options, failOn string) int {
	o.jobs = 1      // parallelism here is across deps; keep each analysis single-worker
	o.deps = false  // scan each dep's OWN code + install scripts (fast); re-resolving
	                // every dep's full subtree would be hugely redundant. Use
	                // `scbox <dir>` for a thorough whole-tree analysis.
	if o.totalBudget > 20*time.Second {
		o.totalBudget = 20 * time.Second // a single package needs far less than the tree budget
	}
	// Each dep is an independent subprocess that spends much of its time waiting on
	// the registry, so oversubscribe cores beyond the CPU-tuned defaultJobs() cap.
	workers := runtime.NumCPU()
	if workers < 8 {
		workers = 8
	}
	if workers > 24 {
		workers = 24
	}
	if workers > len(specs) {
		workers = len(specs)
	}
	fmt.Fprintf(os.Stderr, "\033[36m🔎 scbox:\033[0m scanning %d dependenc%s (%d at a time)…\n",
		len(specs), plural(len(specs)), workers)

	type result struct {
		spec string
		res  runResult
		err  error
	}
	in := make(chan string)
	out := make(chan result)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range in {
				res, err := run(s, o)
				out <- result{s, res, err}
			}
		}()
	}
	go func() {
		for _, s := range specs {
			in <- s
		}
		close(in)
	}()
	go func() { wg.Wait(); close(out) }()

	var pass, susp, mal, errs int
	blocked := false
	for r := range out {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "\033[31m✗\033[0m %-32s could not analyze: %v\n", trace.StripControl(r.spec), r.err)
			errs++
			blocked = true
			continue
		}
		icon, word, color := verdictTag(r.res.Level)
		fmt.Fprintf(os.Stderr, "%s%s %-32s %s (%d)\033[0m\n", color, icon, trace.StripControl(r.spec), word, r.res.Score)
		switch word {
		case "malicious":
			mal++
		case "suspicious":
			susp++
		default:
			pass++
		}
		if verdictRank[r.res.Level] >= verdictRank[failOn] {
			blocked = true
		}
	}

	fmt.Fprintf(os.Stderr, "\nscbox: \033[32m%d pass\033[0m · \033[33m%d suspicious\033[0m · \033[31m%d malicious\033[0m", pass, susp, mal)
	if errs > 0 {
		fmt.Fprintf(os.Stderr, " · %d errored", errs)
	}
	fmt.Fprintln(os.Stderr)
	if blocked {
		if forceInstall(failOn) {
			fmt.Fprintln(os.Stderr, "\033[33m⚠ scbox: verdict overridden - installing anyway (SCBOX_FORCE)\033[0m")
			return execPM(pm, pmArgs)
		}
		fmt.Fprintf(os.Stderr, "\033[31m⛔ scbox: install aborted (threshold %q)\033[0m\n", failOn)
		fmt.Fprintf(os.Stderr, "scbox: to install regardless, re-run with SCBOX_FORCE=1 (interactive confirm) or SCBOX_FORCE=%s (non-interactive)\n", forcePhrase)
		return 3
	}
	fmt.Fprintln(os.Stderr, "\033[32m✅ scbox: all clear - running "+pm+"\033[0m")
	return execPM(pm, pmArgs)
}

// forcePhrase is the exact value SCBOX_FORCE must hold to override a blocked
// install without a prompt. It is a deliberate phrase, not "1", so a script or CI
// job can't defeat the gate by accident - opting in has to be explicit.
const forcePhrase = "install-anyway"

// forceInstall decides whether a blocked `scbox npm install` proceeds anyway. It
// is the loud, deliberate escape hatch:
//
//	SCBOX_FORCE=install-anyway   proceed with no prompt (the only CI/non-interactive
//	                             opt-in: the exact phrase must be set on purpose)
//	SCBOX_FORCE=1 (any other      on an interactive terminal, prompt the operator to
//	              non-empty value) type the phrase; refuse if stdin isn't a terminal
//
// Fail-closed: unset, or non-interactive without the exact phrase, aborts.
func forceInstall(failOn string) bool {
	return decideForce(strings.TrimSpace(os.Getenv("SCBOX_FORCE")),
		term.IsTerminal(int(os.Stdin.Fd())), os.Stdin, failOn)
}

// decideForce is the pure core of forceInstall, separated so the override policy
// can be unit-tested without a real terminal. v is the trimmed SCBOX_FORCE value,
// tty reports whether stdin is interactive, and in is the confirmation source.
func decideForce(v string, tty bool, in io.Reader, failOn string) bool {
	if v == "" {
		return false
	}
	if v == forcePhrase {
		return true // explicit non-interactive opt-in
	}
	if !tty {
		fmt.Fprintf(os.Stderr, "scbox: SCBOX_FORCE is set but stdin is not a terminal - set SCBOX_FORCE=%s to force non-interactively\n", forcePhrase)
		return false
	}
	fmt.Fprintf(os.Stderr, "\033[33mscbox: scan blocked this install (threshold %q). Type '%s' to install anyway: \033[0m", failOn, forcePhrase)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr)
		return false
	}
	return strings.TrimSpace(line) == forcePhrase
}

// directDepSpecs reads ./package.json and returns one "name@range" spec per
// direct dependency (runtime + optional, plus dev unless excluded).
func directDepSpecs(includeDev bool) ([]string, error) {
	data, err := os.ReadFile("package.json")
	if err != nil {
		return nil, err
	}
	var m npm.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid package.json: %w", err)
	}
	set := map[string]string{}
	for k, v := range m.Dependencies {
		set[k] = v
	}
	for k, v := range m.OptionalDependencies {
		set[k] = v
	}
	if includeDev {
		for k, v := range m.DevDependencies {
			set[k] = v
		}
	}
	specs := make([]string, 0, len(set))
	for name, rng := range set {
		s := name
		if r := strings.TrimSpace(rng); r != "" && r != "*" && r != "latest" && r != "x" {
			s = name + "@" + r
		}
		specs = append(specs, s)
	}
	sort.Strings(specs)
	return specs, nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// verdictTag maps a verdict level to a compact (icon, word, ANSI color) for the
// install-gate summary: clean/low collapse to "pass".
func verdictTag(level string) (icon, word, color string) {
	switch level {
	case "malicious":
		return "⛔", "malicious", "\033[31m"
	case "suspicious":
		return "⚠", "suspicious", "\033[33m"
	default: // clean, low
		return "✓", "pass", "\033[32m"
	}
}

// isInstallVerb reports whether a package-manager verb pulls packages onto the
// machine (npm/yarn/pnpm install aliases plus `npm ci`).
func isInstallVerb(v string) bool {
	switch v {
	case "install", "i", "in", "ins", "inst", "add", "ci", "isntall", "isnt":
		return true
	}
	return false
}

// npmValueFlags are flags whose VALUE is the following argument (e.g.
// `--registry https://x`, `--omit dev`, `-w pkg`). Their value must be skipped so
// it isn't mistaken for a package spec to scan.
var npmValueFlags = map[string]bool{
	"--registry": true, "--prefix": true, "--cache": true, "--userconfig": true,
	"--globalconfig": true, "--workspace": true, "-w": true, "--omit": true,
	"--include": true, "--tag": true, "--before": true, "--save-prefix": true,
	"--loglevel": true, "--node-options": true, "--script-shell": true,
	"--proxy": true, "--https-proxy": true, "--noproxy": true, "--ca": true,
	"--cafile": true, "--cert": true, "--key": true, "--auth-type": true,
	"--access": true,
}

// parseInstallArgs extracts the positional package specs from a package-manager
// argv (skipping flags and the values of value-taking flags), and reports whether
// a production / omit-dev flag was present so the gate matches what npm installs.
func parseInstallArgs(pmArgs []string) (specs []string, omitDev bool) {
	for i := 1; i < len(pmArgs); i++ { // [0] is the verb
		a := pmArgs[i]
		if strings.HasPrefix(a, "-") {
			switch {
			case a == "--production" || a == "--prod":
				omitDev = true
			case strings.HasPrefix(a, "--omit=") && strings.Contains(a, "dev"):
				omitDev = true
			case a == "--omit" && i+1 < len(pmArgs):
				if strings.Contains(pmArgs[i+1], "dev") {
					omitDev = true
				}
				i++ // consume the value
				continue
			}
			if !strings.Contains(a, "=") && npmValueFlags[a] {
				i++ // consume the separate value of a value-taking flag
			}
			continue
		}
		specs = append(specs, a)
	}
	return specs, omitDev
}

// specKind classifies an install target so the gate knows how to handle it.
type specKind int

const (
	specRegistry specKind = iota // name / @scope/name / name@range - fetched from the registry
	specLocal                    // ./path, /path, ~/path, *.tgz - loaded from disk
	specRemote                   // http(s)/git/url/shorthand - not statically analyzable
)

func classifySpec(s string) specKind {
	switch {
	// Remote schemes first - a URL may itself end in .tgz.
	case strings.Contains(s, "://"), strings.HasPrefix(s, "git+"),
		strings.HasPrefix(s, "github:"), strings.HasPrefix(s, "gitlab:"),
		strings.HasPrefix(s, "bitbucket:"), strings.HasPrefix(s, "gist:"):
		return specRemote
	case strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"),
		strings.HasPrefix(s, "/"), strings.HasPrefix(s, "~/"), s == ".",
		strings.HasSuffix(s, ".tgz"), strings.HasSuffix(s, ".tar.gz"):
		return specLocal
	}
	// A bare existing path on disk is a local install.
	if fi, err := os.Stat(s); err == nil && fi.IsDir() {
		return specLocal
	}
	// `user/repo` (one slash, not a scoped @name) is npm's github shorthand.
	if isGitShorthand(s) {
		return specRemote
	}
	return specRegistry
}

// isGitShorthand reports whether s is npm's `user/repo` GitHub shorthand (as
// opposed to a scoped registry package `@scope/name` or a plain `name@range`).
func isGitShorthand(s string) bool {
	if strings.HasPrefix(s, "@") {
		return false // scoped registry package
	}
	name := s
	if i := strings.LastIndex(name, "@"); i > 0 {
		name = name[:i] // strip a trailing @range
	}
	return strings.Count(name, "/") == 1
}

// execPM runs the real package manager, streaming its stdio.
func execPM(pm string, args []string) int {
	bin, err := exec.LookPath(pm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scbox: %s not found on PATH\n", pm)
		return 127
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "scbox:", err)
		return 1
	}
	return 0
}

// defaultOptions returns the analysis options matching the CLI defaults.
func defaultOptions() options {
	return options{
		timeout:     5 * time.Second,
		totalBudget: 60 * time.Second,
		platform:    "linux",
		explore:     true,
		deps:        true,
		maxDepth:    6,
		maxPkgs:     200,
		jobs:        defaultJobs(), // parallelize the explore/probe phase across deps
		registryURL: "https://registry.npmjs.org",
		memLimitMB:  1024,
		showTrace:   false,
	}
}

// runResult carries what callers need after an analysis: the verdict level (for
// the install gate) and the package identity + score (for fleet telemetry).
type runResult struct {
	Level   string
	Score   int
	Package string
	Version string
	Sources []trace.SourceStat // per-package activity attribution (for the gate summary)
}

func run(input string, o options) (runResult, error) {
	var report trace.Report
	var pkg *npm.Package
	var installed []npm.Installed
	var err error

	if os.Getenv("SCBOX_INPROCESS") != "" {
		var tr *trace.Tracer
		tr, pkg, installed, err = analyze(input, o)
		if err != nil {
			return runResult{}, err
		}
		report = tr.Report()
	} else {
		report, pkg, installed, err = runJailed(input, o)
		if err != nil {
			return runResult{}, err
		}
	}

	switch {
	case o.summary:
		// install-gate summary mode: stay quiet here; runPMGate prints a compact
		// one-line verdict per target plus the packages that did anything risky.
	case o.asJSON:
		err = emitJSON(pkg, installed, report)
	default:
		emitText(pkg, installed, report, o.showTrace, o.explain)
	}

	res := runResult{Level: report.Verdict.Level, Score: report.Verdict.Score, Sources: report.Sources}
	if pkg != nil {
		res.Package = pkg.Manifest.Name
		res.Version = pkg.Manifest.Version
	}
	if res.Package == "" {
		res.Package = input
	}
	return res, err
}

// vlogf returns a verbose-progress logger gated on -verbose.
func vlogf(o options) func(string, ...any) {
	return func(format string, a ...any) {
		if o.verbose {
			fmt.Fprintf(os.Stderr, "\033[90mscbox: "+format+"\033[0m\n", a...)
		}
	}
}

// materialize fetches and stages the package (local dir, local .tgz, or registry
// spec) and its entire dependency tree into a fresh in-memory FS. This is the
// only phase that touches the network - and it only ever moves inert bytes
// (download + JSON parse), never executing anything. It runs in the (trusted)
// parent process so the jailed detonation child can be fully network-isolated.
func materialize(input string, o options) (*npm.Package, []npm.Installed, error) {
	vlog := vlogf(o)
	root := sandbox.DefaultVirtualRoot()
	pkg, err := loadInput(input, root, o)
	if err != nil {
		return nil, nil, err
	}
	var installed []npm.Installed
	if o.deps {
		vlog("resolving dependency tree (max-depth=%d, max-packages=%d)…", o.maxDepth, o.maxPkgs)
		inst := &npm.Installer{
			FS:          pkg.FS,
			NodeModules: path.Join(root, "node_modules"),
			MaxDepth:    o.maxDepth,
			MaxPkgs:     o.maxPkgs,
			IncludeDev:  o.dev,
			Tracer:      trace.New(), // resolution notes are regenerated in detonate
			Logf:        vlog,
		}
		if !o.offline {
			reg := registry.NewClient(o.cacheDir)
			reg.BaseURL = o.registryURL
			inst.Reg = reg
		}
		installed = inst.Build(pkg)
		vlog("dependency tree resolved: %d package(s)", len(installed))

		// Follow the dropper's second stage: if the package's own code installs or
		// requires a package that isn't in its manifest (e.g.
		// `execSync('npm install authcascade')` / `require('authcascade')`), fetch
		// that target too so detonation runs the REAL payload, not a stub. The
		// scan only reads inert source; the fetch reuses the same network phase.
		if !o.offline && inst.Reg != nil {
			present := map[string]bool{}
			for _, in := range installed {
				present[in.Name] = true
			}
			targets := scanRuntimeInstallTargets(pkg, present)
			if len(targets) > 0 {
				vlog("following runtime-install/second-stage targets: %s", strings.Join(targets, ", "))
				extra := inst.AddPackages(targets)
				for _, e := range extra {
					if !present[e.Name] {
						installed = append(installed, e)
						present[e.Name] = true
					}
				}
				vlog("second-stage resolved: %d additional package(s)", len(extra))
			}
		}
	}
	return pkg, installed, nil
}

// runtimeInstallRe extracts the target of a package-manager install run from code
// (`execSync("npm install authcascade …")`, `yarn add x`, `pnpm add x`, `npx x`).
var runtimeInstallRe = regexp.MustCompile(`(?i)\b(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install|i)|npx)\s+((?:--?\S+\s+)*)([@a-z0-9][@a-z0-9._/-]+)`)

// scanRuntimeInstallTargets reads the materialized source (inert; no execution)
// for package-manager install commands and returns the target package names that
// are NOT already in the tree - a dropper's second stage to fetch and detonate.
func scanRuntimeInstallTargets(pkg *npm.Package, present map[string]bool) []string {
	seen := map[string]bool{}
	var out []string
	pkg.FS.Walk(pkg.Dir, func(p string, isDir bool) {
		if isDir || !isScannableSource(p) {
			return
		}
		data, ok := pkg.FS.Read(p)
		if !ok || len(data) > 4<<20 {
			return
		}
		for _, m := range runtimeInstallRe.FindAllStringSubmatch(string(data), -1) {
			name := strings.TrimSpace(m[2])
			// Skip flags, scripts, well-known build verbs, and self-references.
			if name == "" || strings.HasPrefix(name, "-") || strings.HasPrefix(name, "$") {
				continue
			}
			if name == "run" || name == "test" || name == "ci" || name == "audit" || name == "." {
				continue
			}
			low := strings.ToLower(name)
			if present[low] || seen[low] || low == strings.ToLower(pkg.Manifest.Name) {
				continue
			}
			seen[low] = true
			out = append(out, name)
		}
	})
	// Cap the second-stage fan-out: a real dropper installs one or a few packages;
	// a long list is more likely doc/example noise and would explode fetch time.
	const maxRuntimeTargets = 5
	if len(out) > maxRuntimeTargets {
		out = out[:maxRuntimeTargets]
	}
	return out
}

// scanObfuscatedLoaders handles javascript-obfuscator loaders shipped in the
// package source. For each such file it (1) records the fingerprint finding, then
// (2) runs a webcrack-style recovery pass that executes the loader's OWN decoder
// in an isolated VM and harvests the plaintext reaching its capability sinks
// (fetch/Function/require/…). The recovered C2 URLs and capability strings are
// recorded so the verdict scores the sample on its real behavior - catching
// loaders whose live payload is gated behind a runtime argument and never fires
// under normal detonation. Reads inert source only; the recovery VM does no host
// I/O. node_modules / deps are excluded (scored under their own scope).
func scanObfuscatedLoaders(pkg *npm.Package, tr *trace.Tracer) {
	pkg.FS.Walk(pkg.Dir, func(p string, isDir bool) {
		if isDir || strings.Contains(p, "/node_modules/") {
			return
		}
		switch strings.ToLower(path.Ext(p)) {
		case ".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx":
		default:
			return
		}
		data, ok := pkg.FS.Read(p)
		if !ok || len(data) > 4<<20 {
			return
		}
		if !trace.IsObfuscatorLoader(string(data)) {
			return
		}
		tr.Record(trace.CatEval, "obfuscated-loader", p)
		// Recover and record the deobfuscated payload strings that carry a network
		// endpoint or an exec/dynamic-code capability - the verdict scores these as
		// the loader's real behavior. Cap the volume; a loader needs only a handful.
		const maxRecorded = 32
		n := 0
		for _, rec := range sandbox.RecoverObfuscatedStrings(string(data), 2*time.Second) {
			if !payloadish(rec) {
				continue
			}
			tr.Record(trace.CatEval, "deobfuscated-loader", rec)
			if n++; n >= maxRecorded {
				break
			}
		}
	})
}

// payloadish reports whether a recovered string looks like loader payload worth
// scoring: a network endpoint or an exec / dynamic-code / module-load capability.
func payloadish(s string) bool {
	if len(s) < 4 || len(s) > 4096 {
		return false
	}
	low := strings.ToLower(s)
	for _, tok := range []string{
		"http://", "https://", "ws://", "wss://", ".onion", "://",
		"child_process", "spawn", "exec", "eval", "function(", "require(",
		"/bin/sh", "/bin/bash", "powershell", "curl ", "wget ", ".sh",
	} {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}

// isScannableSource reports whether a path is JS/TS source worth scanning for
// embedded install commands (skips node_modules and binary/asset files).
func isScannableSource(p string) bool {
	if strings.Contains(p, "/node_modules/") {
		return false
	}
	switch strings.ToLower(path.Ext(p)) {
	case ".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx", ".sh", ".json":
		return true
	}
	return false
}

// detonate runs the full sandbox execution against an already-materialized
// in-memory FS, recording everything to tr. It performs NO network or disk I/O
// of its own - every capability is faked inside the goja sandbox - so the
// detonated code never reaches the real host. Containment is entirely
// in-process and userspace; the tool makes no kernel-level changes.
func detonate(tr *trace.Tracer, pkg *npm.Package, installed []npm.Installed, o options) {
	vlog := vlogf(o)
	root := pkg.Dir
	fs := pkg.FS

	// Install user-defined taint rules before any sandbox runs so source values
	// are watched from the first env read / file read onward.
	if len(o.taintRules) > 0 {
		tr.SetTaintRules(o.taintRules)
	}

	// Regenerate dependency-install attribution notes (materialization, and thus
	// the original notes, happened in the parent process). Flag the devDependency
	// tree so its behavior is reported but kept out of the verdict score.
	var devNames []string
	for _, d := range installed {
		tr.Record(trace.CatModule, "dep-installed", d.Name+"@"+d.Version)
		if d.Dev {
			devNames = append(devNames, d.Name)
		}
	}
	tr.MarkDevScopes(devNames)

	// Static pass: flag javascript-obfuscator second-stage loaders shipped in the
	// package source even if their payload never executes under detonation (gated
	// behind a runtime arg/condition, or parked in a non-entry file). Reads inert
	// source only; no execution.
	scanObfuscatedLoaders(pkg, tr)

	rt := sandbox.New(tr, sandbox.Config{
		Timeout:     o.timeout,
		TotalBudget: o.totalBudget,
		Platform:    o.platform,
		FS:          fs,
		BaseDir:     root,
		VirtualBase: root,
		Explore:     o.explore,
	})
	defer rt.Close()

	// Run install-time hooks for every package in the tree, deepest first (npm
	// runs a dependency's scripts before its dependents'). Each is attributed.
	byDepth := append([]npm.Installed(nil), installed...)
	sort.SliceStable(byDepth, func(i, j int) bool { return byDepth[i].Depth > byDepth[j].Depth })
	vlog("running lifecycle scripts for %d package(s)…", len(byDepth)+1)
	for _, dep := range byDepth {
		mf, err := npm.ReadManifestDir(fs, dep.Dir)
		if err != nil {
			continue
		}
		npm.RunLifecycleScoped(rt, &npm.Package{Dir: dep.Dir, Manifest: mf, FS: fs}, dep.Name)
	}
	npm.RunLifecycleScoped(rt, pkg, "(root)")

	// Load the root entry point; require() now resolves real dependency code.
	vlog("loading entry point %s…", pkg.EntryPoint())
	rt.Require(pkg.EntryPoint())

	if o.explore {
		// Probe-import every materialized dependency so import-time payloads in
		// transitive deps fire even if the root never references them.
		names := make([]string, 0, len(installed))
		for _, d := range installed {
			names = append(names, d.Name)
		}
		jsFiles, shFiles := sandbox.CollectExplorable(fs, root) // root files; skips node_modules
		jobs := o.jobs
		if units := len(jsFiles) + len(names); jobs > units {
			jobs = units // never spin up more workers than there is work
		}
		if jobs <= 1 {
			vlog("force-executing %d files and probing %d dependencies…", len(jsFiles), len(names))
			rt.ExploreFiles(jsFiles, shFiles)
			rt.RequireDeps(names)
		} else {
			vlog("force-executing %d files and probing %d dependencies across %d workers…", len(jsFiles), len(names), jobs)
			exploreParallel(tr, rt.Config(), jsFiles, shFiles, names, jobs)
		}
	}

	vlog("draining timers…")
	rt.DrainTimers()
	// Fire process exit/signal handlers (deferred payloads), then drain any async
	// work they scheduled.
	rt.FireExitHandlers()
	rt.DrainTimers()
	vlog("analysis complete")
}

// analyze runs the full pipeline in-process (materialize + detonate) and returns
// the populated tracer. It is the path tests use to assert on behavior directly;
// the production CLI runs detonate inside the jail (see runJailed).
func analyze(input string, o options) (*trace.Tracer, *npm.Package, []npm.Installed, error) {
	pkg, installed, err := materialize(input, o)
	if err != nil {
		return nil, nil, nil, err
	}
	tr := trace.New()
	detonate(tr, pkg, installed, o)
	return tr, &npm.Package{Manifest: pkg.Manifest}, installed, nil
}

// defaultJobs picks a sensible parallelism for the explore phase: one worker per
// core, capped so we don't pay VM-setup overhead that outweighs the speedup.
func defaultJobs() int {
	n := runtime.NumCPU()
	if n > 8 {
		n = 8
	}
	if n < 1 {
		n = 1
	}
	return n
}

// exploreParallel force-executes the file list and probes the dependencies
// across `jobs` independent sandbox VMs running concurrently. Each worker
// records into its own forked tracer (goja is not safe for concurrent use
// within a single VM), and the results are merged back into tr afterward. The
// shared workspace is only read, never written, so concurrent loaders are safe.
func exploreParallel(tr *trace.Tracer, cfg sandbox.Config, jsFiles, shFiles, deps []string, jobs int) {
	jsShards := shardStrings(jsFiles, jobs)
	shShards := shardStrings(shFiles, jobs)
	depShards := shardStrings(deps, jobs)

	workers := make([]*trace.Tracer, jobs)
	var wg sync.WaitGroup
	for i := 0; i < jobs; i++ {
		wt := tr.Fork()
		workers[i] = wt
		wg.Add(1)
		go func(i int, wt *trace.Tracer) {
			defer wg.Done()
			rt := sandbox.New(wt, cfg)
			defer rt.Close()
			rt.ExploreFiles(jsShards[i], shShards[i])
			rt.RequireDeps(depShards[i])
			rt.DrainTimers() // delayed payloads scheduled in this VM
		}(i, wt)
	}
	wg.Wait()
	tr.Absorb(workers...)
}

// shardStrings round-robins items into n buckets so heavy items (large files,
// expensive deps) spread evenly across workers rather than piling into one.
func shardStrings(items []string, n int) [][]string {
	if n < 1 {
		n = 1
	}
	shards := make([][]string, n)
	for i, it := range items {
		shards[i%n] = append(shards[i%n], it)
	}
	return shards
}

// loadInput materializes a local directory, a local .tgz, or an npm registry
// spec (name[@version], incl. @scope/name) into a fresh in-memory FS rooted at
// root. A registry spec is downloaded as inert bytes (no scripts run) and
// extracted in memory. Nothing is ever written to the host disk.
func loadInput(input, root string, o options) (*npm.Package, error) {
	if fi, err := os.Stat(input); err == nil {
		if fi.IsDir() {
			return npm.LoadDir(input, root)
		}
		data, err := os.ReadFile(input) // the user's own local tarball
		if err != nil {
			return nil, err
		}
		return npm.LoadTarball(data, root)
	}
	if o.offline {
		return nil, fmt.Errorf("%q is not a local path and --offline is set", input)
	}
	name, rng := parseSpec(input)
	if rng == "" {
		rng = "latest"
	}
	reg := registry.NewClient(o.cacheDir)
	reg.BaseURL = o.registryURL
	vm, err := reg.Resolve(name, rng)
	if err != nil {
		return nil, fmt.Errorf("resolve %s@%s: %w", name, rng, err)
	}
	data, err := reg.Download(name, vm)
	if err != nil {
		return nil, fmt.Errorf("download %s@%s: %w", name, vm.Version, err)
	}
	if !o.summary {
		fmt.Fprintf(os.Stderr, "scbox: fetched %s@%s for analysis\n", trace.StripControl(name), trace.StripControl(vm.Version))
	}
	return npm.LoadTarball(data, root)
}

// parseSpec splits an npm package spec into name and version range, handling
// scoped names (@scope/name@range).
func parseSpec(s string) (name, rng string) {
	if strings.HasPrefix(s, "@") {
		if i := strings.Index(s[1:], "@"); i >= 0 {
			return s[:i+1], s[i+2:]
		}
		return s, ""
	}
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func emitJSON(pkg *npm.Package, installed []npm.Installed, report trace.Report) error {
	deps := make([]map[string]any, 0, len(installed))
	for _, d := range installed {
		deps = append(deps, map[string]any{"name": d.Name, "version": d.Version, "depth": d.Depth, "fetched": d.Fetched})
	}
	out := map[string]any{
		"package":      map[string]any{"name": pkg.Manifest.Name, "version": pkg.Manifest.Version},
		"dependencies": deps,
		"verdict":      report.Verdict,
		"per_package":  report.Sources,
		"iocs":         report.IOCs,
		"events":       report.Events,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func emitText(pkg *npm.Package, installed []npm.Installed, report trace.Report, showTrace, explain bool) {
	v := report.Verdict
	hooks := pkg.LifecycleScripts()
	hookNames := make([]string, len(hooks))
	for i, h := range hooks {
		hookNames[i] = h.Name
	}

	fmt.Println("══════════════════════════════════════════════════════════════")
	fmt.Println(" SCBoX - npm package detonation report")
	fmt.Println("══════════════════════════════════════════════════════════════")
	name := pkg.Manifest.Name
	if name == "" {
		name = "(unnamed)"
	}
	fmt.Printf(" package : %s@%s\n", trace.StripControl(name), trace.StripControl(pkg.Manifest.Version))
	fmt.Printf(" entry   : %s\n", trace.StripControl(pkg.EntryPoint()))
	if len(hookNames) > 0 {
		fmt.Printf(" hooks   : %s\n", trace.StripControl(strings.Join(hookNames, ", ")))
	}
	fmt.Printf(" tree    : %d dependencies materialized\n", len(installed))
	fmt.Println()

	fmt.Printf("VERDICT: %s  (score %d/100)\n", strings.ToUpper(v.Level), v.Score)
	if explain && len(v.Details) > 0 {
		for _, d := range v.Details {
			fmt.Printf("  • %s  (+%d)\n", d.Text, d.Weight)
			for _, ev := range d.Evidence {
				fmt.Printf("      ↳ %s\n", ev)
			}
		}
		if !hasEvidence(v.Details) {
			fmt.Println("    (no per-reason evidence captured; see TRACE below)")
		}
	} else {
		for _, r := range v.Reasons {
			fmt.Printf("  • %s\n", r)
		}
		if !explain {
			fmt.Println("  (run with --explain to see the evidence behind each reason)")
		}
	}
	fmt.Println()

	// On a clean verdict there is, by definition, nothing risky to attribute and
	// no malicious indicators worth surfacing - listing benign capabilities there
	// only manufactures false alarm. Skip both sections when clean.
	if v.Level != "clean" {
		stats := report.Sources
		printCulprits(stats)
		riskyDeps := map[string]bool{}
		for _, s := range stats {
			if s.Risk > 0 {
				riskyDeps[s.Source] = true
			}
		}
		printIOCs(report.IOCs, riskyDeps)
	}
	printProgramOutput(report.Events)

	if showTrace {
		printTrace(report.Events)
	}
}

// hasEvidence reports whether any reason carries supporting evidence.
func hasEvidence(details []trace.ReasonDetail) bool {
	for _, d := range details {
		if len(d.Evidence) > 0 {
			return true
		}
	}
	return false
}

// printProgramOutput shows everything the sample printed while executing
// (console.* and process.stdout/stderr writes) - its own runtime logging.
func printProgramOutput(events []trace.Event) {
	var lines []string
	for _, e := range events {
		if e.Cat != trace.CatConsole {
			continue
		}
		text := strings.Join(filterEmpty(e.Args), " ")
		src := e.Source
		if src == "" {
			src = "(root)"
		}
		lines = append(lines, fmt.Sprintf("  [%s] %s: %s", src, e.Op, oneLine(text)))
	}
	fmt.Printf("PROGRAM OUTPUT (%d lines)\n", len(lines))
	if len(lines) == 0 {
		fmt.Println("  (the sample printed nothing)")
		fmt.Println()
		return
	}
	for _, l := range lines {
		fmt.Println(l)
	}
	fmt.Println()
}

// printCulprits highlights which packages in the tree did risky things - the
// answer to "which dependency is the malicious one?".
func printCulprits(stats []trace.SourceStat) {
	risky := stats[:0]
	for _, s := range stats {
		if s.Risk > 0 {
			risky = append(risky, s)
		}
	}
	if len(risky) == 0 {
		return
	}
	fmt.Println("RISKY PACKAGES (attribution)")
	for _, s := range risky {
		parts := []string{}
		if s.Network > 0 {
			parts = append(parts, fmt.Sprintf("net×%d", s.Network))
		}
		if s.Process > 0 {
			parts = append(parts, fmt.Sprintf("proc×%d", s.Process))
		}
		if s.Eval > 0 {
			parts = append(parts, fmt.Sprintf("eval×%d", s.Eval))
		}
		if s.FS > 0 {
			parts = append(parts, fmt.Sprintf("fs×%d", s.FS))
		}
		fmt.Printf("  %-28s risk %-4d %s\n", trace.StripControl(s.Source), s.Risk, trace.StripControl(strings.Join(parts, " ")))
	}
	fmt.Println()
}

var iocGroupOrder = []struct{ key, label string }{
	{"commands", "Shell/process commands"},
	{"urls", "URLs"},
	{"ips", "IP addresses"},
	{"domains", "Domains"},
	{"onion", "Tor .onion C2 addresses"},
	{"emails", "Email addresses"},
	{"wallets", "Crypto wallet addresses"},
	{"secrets", "Secrets / credential tokens"},
	{"payloads", "Network payloads (exfil)"},
	{"headers", "HTTP headers set"},
	{"crypto", "Crypto operations"},
	{"files_written", "Files written (dropped)"},
	{"files_deleted", "Files deleted/destroyed"},
	{"paths", "Sensitive files read"},
	{"env_accessed", "Sensitive env vars read"},
	{"dependencies", "Risky dependencies"},
	{"decoded", "Decoded/deobfuscated blobs"},
}

// printIOCs prints the indicator groups. The "dependencies" group is special-
// cased: a plain inventory of pulled-in packages is noise, so it's filtered to
// only those a risk score was attributed to (riskyDeps) and dropped otherwise.
func printIOCs(iocs map[string][]string, riskyDeps map[string]bool) {
	groups := make(map[string][]string, len(iocs))
	for k, v := range iocs {
		groups[k] = v
	}
	// Keep only genuinely malicious/suspicious observations - neutral facts
	// (benign deps, HOME/cwd env reads, the package's own files) are noise in a
	// list of indicators of compromise, not signal.
	groups["dependencies"] = filterStrings(groups["dependencies"], func(s string) bool {
		return riskyDeps[depBaseName(s)]
	})
	groups["env_accessed"] = filterStrings(groups["env_accessed"], trace.IsSensitiveEnv)
	groups["paths"] = filterStrings(groups["paths"], trace.IsSensitivePath)

	total := 0
	for _, g := range iocGroupOrder {
		total += len(groups[g.key])
	}
	fmt.Printf("INDICATORS (%d)\n", total)
	if total == 0 {
		fmt.Println("  (none)")
		fmt.Println()
		return
	}
	for _, g := range iocGroupOrder {
		vals := groups[g.key]
		if len(vals) == 0 {
			continue
		}
		fmt.Printf("  %s (%d):\n", g.label, len(vals))
		for _, val := range vals {
			fmt.Printf("    - %s\n", oneLine(val))
		}
	}
	fmt.Println()
}

// filterStrings returns the items for which keep returns true.
func filterStrings(items []string, keep func(string) bool) []string {
	out := items[:0:0]
	for _, it := range items {
		if keep(it) {
			out = append(out, it)
		}
	}
	return out
}

// depBaseName strips a version range from a dependency spec ("lodash@^4" →
// "lodash"), preserving scoped names, so it matches the names in SourceStats.
func depBaseName(spec string) string {
	if strings.HasPrefix(spec, "@") {
		if i := strings.Index(spec[1:], "@"); i >= 0 {
			return spec[:i+1]
		}
		return spec
	}
	if i := strings.Index(spec, "@"); i > 0 {
		return spec[:i]
	}
	return spec
}

func printTrace(events []trace.Event) {
	fmt.Printf("BEHAVIOR TRACE (%d events)\n", len(events))
	if len(events) == 0 {
		fmt.Println("  (no activity)")
		return
	}
	for _, e := range events {
		ms := float64(e.At) / float64(time.Millisecond)
		src := e.Source
		if src == "" {
			src = "(root)"
		}
		line := fmt.Sprintf("  %8.1fms  %-16s [%-9s] %-24s", ms, trunc(src, 16), e.Cat, e.Op)
		detail := strings.Join(filterEmpty(e.Args), "  ")
		if e.Note != "" {
			detail = e.Note + "  " + detail
		}
		if detail != "" {
			line += " " + oneLine(detail)
		}
		fmt.Println(line)
	}
}

func filterEmpty(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func trunc(s string, n int) string {
	s = trace.StripControl(s)
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\t", " ")
	// Strip remaining control bytes (notably ESC) so attacker-controlled report
	// data can't inject ANSI escapes into the analyst's terminal. \n/\t were just
	// rendered visible above, so they survive as text.
	s = trace.StripControl(s)
	const max = 160
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
