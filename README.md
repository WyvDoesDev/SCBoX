# SCBoX

SCBoX is a dynamic-analysis sandbox for npm packages. It runs an untrusted package and its full dependency tree inside a pure-Go JavaScript interpreter where every system capability is faked and logged, so it can report what a package does at install time and import time without any of it touching the host. It can also gate `npm install`: a package is scanned first and installed only if the scan passes.

Detection is built and tested against DPRK npm malware from the [DPRK npm packages tracker](https://dprk-research.kmsec.uk/). SCBoX runs fully offline and has no license, keys, or telemetry.

```
$ scbox ./suspicious-package
```

For each run it reports a verdict, the per-package attribution (which dependency in the tree was responsible), the extracted IOCs, and a behavioral trace that includes everything the sample printed.

## Why

The dangerous package is usually not the one you installed. It is often a transitive dependency several levels down, or a `postinstall` script that runs the moment you type `npm install`. SCBoX answers two questions without running the code on a real machine:

1. What does this package and its dependencies do when installed and used?
2. Is it safe?

The threat model is Node.js install-time and import-time supply-chain malware: malicious lifecycle scripts, credential stealers, droppers, reverse shells, crypto-wallet hijackers, and self-propagating worms.

## Safety: nothing executes on the host

This holds because of how the sandbox is built:

- The sample runs only inside [goja](https://github.com/dop251/goja), a pure-Go ES interpreter with no cgo and no V8. goja exposes no host JavaScript context, so there is no real `process`, `require`, or `fs` to reach. A sandbox-escape gadget such as `({}).constructor.constructor('return process')()` resolves to the fake global instead.
- The only bridge to the host is the set of Go functions SCBoX installs. They are opaque to the script, which cannot traverse them to reach new capabilities.
- Every side-effecting API is faked. File writes and deletes, process spawns, network requests, and DNS return plausible fake results and are logged. An in-memory filesystem keeps write-then-read consistent without touching the disk.
- Other guards: a per-call timeout and a total wall-clock budget bound runtime, a bounded call stack prevents stack overflow, module reads are symlink-contained to the package, and dependency tarballs are extracted with pure-Go tar so no scripts run.
- TypeScript is transpiled with esbuild, which parses and rewrites the code without executing it. Shell scripts run through `mvdan.cc/sh` with faked exec and file handlers, so real `bash` is never spawned.

SCBoX is a triage tool: use its verdicts to prioritize review. It does not prove a package is safe. Run the analyzer itself in a locked-down environment (container, unprivileged user, no egress).

## Anti-evasion: looks like a real machine

Evasive malware fingerprints its environment and stops running when it detects an analysis sandbox. SCBoX inverts the common checks (see [MITRE T1497](https://attack.mitre.org/techniques/T1497/) and [evasions.checkpoint.com](https://evasions.checkpoint.com/)) so the sample runs anyway. The fake environment looks like an Arch Linux developer workstation:

- Identity: hostname, user, 16 CPUs, 32 GB RAM, a non-VM MAC OUI, an Arch kernel and `os-release`, ASUS DMI.
- Files return realistic content and length for `/etc/passwd`, `/proc/cpuinfo`, dotfiles, and so on. Credential files (`~/.ssh/id_rsa`, `~/.npmrc`, `~/.aws/credentials`) return bait, so when malware exfiltrates them SCBoX captures exactly what it tried to steal. Recon commands (`whoami`, `gh auth token`, IMDS) and a clipboard read (`xclip -o`, `pbpaste`) also return bait, so credential grabbers and crypto clippers that only fire on a hit still run.
- VM and sandbox artifacts (`/.dockerenv`, `/proc/vz`) report as absent, and `readdir` returns populated listings.
- Virtual clock: `Date.now()` and `setTimeout` advance virtual time, so time-gated payloads fire and busy-wait sleeps used to outlast analysis exit in milliseconds.
- No `CI` env var (which would trigger `if (process.env.CI) return`), no leaked instrumentation globals, native-code `toString` masking, virtual paths with no `/tmp` leak, and Node-shape parity (`Timeout` objects, `Error.captureStackTrace`, `process.hrtime.bigint`, `crypto`, `WebAssembly`).

A 64-check escape, detection, and evasion self-test lives in `testdata/megaprobe`.

## Install

All third-party dependencies are vendored in-tree under `internal/third_party/`, so builds need no network and no module downloads (`GOPROXY=off` works). Requires Go 1.26+.

From a checkout of this repo:

```
./install.sh                    # build from source, install to ~/.local/bin
```

Or use the Makefile or go directly:

```
make build          # -> ./scbox   (trimmed and stripped binary)
make install        # build, then install to ~/.local/bin
make test           # go test over first-party packages
make vet            # go vet over first-party packages
make release        # cross-platform prebuilt binaries via goreleaser
make clean          # remove ./scbox

# or without make:
go build -o scbox .
```

`make install` and `install.sh` honor `INSTALL_DIR` (default `~/.local/bin`) and `BIN` (default `scbox`). `make` also honors `PREFIX` (default `~/.local`) and `VERSION` (stamped into `scbox version`).

To gate `npm install` so packages are scanned before they are installed:

```
source scripts/npm-guard.sh    # add to ~/.bashrc or ~/.zshrc
```

## Usage

```
scbox [flags] <package-dir | package.tgz>
```

| Flag | Default | Description |
|------|---------|-------------|
| `--timeout` | `5s` | wall-clock budget per executed entry point or callback |
| `--total-budget` | `60s` | hard cap on the whole analysis (DoS guard) |
| `--jobs`, `-j` | `8` | parallel sandbox workers, each its own VM, capped at CPU count (1 = sequential) |
| `--mem-limit-mb` | `1024` | worker memory cap in MB (0 = unlimited) |
| `--platform` | `linux` | fake platform reported to the sample |
| `--no-explore` | off | skip force-execution of exports and files |
| `--no-deps` | off | do not resolve or analyze the dependency tree |
| `--dev` | off | also resolve and detonate devDependencies (enlarges the tree and slows analysis) |
| `--max-depth` | `6` | maximum dependency depth to descend |
| `--max-packages` | `200` | maximum packages to materialize |
| `--offline` | off | never fetch from the registry; analyze only what is on disk |
| `--registry` | `https://registry.npmjs.org` | npm registry base URL |
| `--cache-dir` | (memory-only) | directory to cache downloaded tarballs on disk |
| `--json` | off | emit the full report as JSON |
| `--trace` | off | append the full behavioral event trace after the report (very long) |
| `--explain`, `-e` | off | expand each verdict reason with the evidence behind it |
| `--verbose`, `-v` | off | stream analysis progress to stderr |
| `--rules` | (off) | path to a YAML file of custom taint rules (see [Custom taint rules](#custom-taint-rules)) |
| `--fail-on` | (off) | exit non-zero when the verdict is at least `low`, `suspicious`, or `malicious` (install-gate mode) |

Point SCBoX at a local directory or a published tarball. With the dependency tree enabled (the default) it fetches each dependency as inert bytes, runs every package's lifecycle scripts, and lets `require()` load real dependency code so the whole chain runs. Use `--offline` to analyze only what is already on disk, such as a shipped `node_modules`.

## Install gate

The gate wraps your package manager so nothing lands on the machine until it has been scanned. SCBoX scans each package and its install scripts, prints a one-line verdict per dependency, and then runs the real `npm`, `yarn`, or `pnpm`. The install is aborted if any package crosses the threshold.

Run `scbox install <pkg>` anywhere you would run `npm install <pkg>`. It is a drop-in front end: SCBoX scans first and hands off to the real `npm install` only if the scan passes, so the end result is the same install you would have gotten, minus the packages that failed. You can also prefix a full command as `scbox npm install <pkg>` (or `scbox yarn add`, `scbox pnpm add`) if you want to keep the package manager explicit.

You do not have to name packages one at a time. Run a bare `scbox install` (or `scbox npm install`) in a project directory and SCBoX reads `package.json`, scans every declared dependency in parallel, prints a verdict per package, and installs the whole set only if all of them pass. Add `--dev` to include devDependencies. This is the fast way to vet everything a project pulls into `node_modules` in one pass.

```
scbox install                      # scan every dependency in ./package.json, then install all
scbox install lodash               # drop-in for: npm install lodash
scbox npm install lodash react     # scan lodash and react, then npm install if clean
scbox npm ci                       # scan every dep, then npm ci
```

Non-install verbs (`list`, `run`, `uninstall`, and so on) pass straight through. To route `npm` itself through the gate, source the shim:

```
source scripts/npm-guard.sh        # add to ~/.bashrc or ~/.zshrc
```

The gate is configured with environment variables so the wrapped tool's own flags pass through cleanly:

| Env var | Default | Effect |
|---------|---------|--------|
| `SCBOX_FAIL_ON` | `suspicious` | Block threshold: `low`, `suspicious`, or `malicious`. |
| `SCBOX_FORCE` | (unset) | Install after a block. `SCBOX_FORCE=1` prompts for a typed confirmation on an interactive terminal; `SCBOX_FORCE=install-anyway` proceeds with no prompt (the only non-interactive opt-in). |
| `SCBOX_ALLOW_UNSCANNED` | (unset) | `=1` lets git or URL specs that cannot be statically analyzed install unscanned. |
| `SCBOX_REPORT` | (unset) | `=1` prints the full report per package instead of the compact verdict line. |
| `SCBOX_VERBOSE` | (unset) | `=1` streams analysis progress to stderr. |
| `SCBOX_EXPLAIN` | (unset) | `=1` shows the evidence behind each verdict reason. |

Exit codes: `0` clean or installed, `3` blocked by the gate, `4` usage or config error.

### Installing after a block

`SCBOX_FORCE` is not a plain truthy flag. A bare `SCBOX_FORCE=1` only unlocks an interactive confirmation, so a script or CI job cannot silently defeat the gate:

```
# Interactive: you are prompted to type "install-anyway"
SCBOX_FORCE=1 scbox npm install some-flagged-pkg

# Non-interactive: the exact phrase is required
SCBOX_FORCE=install-anyway scbox npm install some-flagged-pkg
```

The gate is fail-closed. If `SCBOX_FORCE` is unset, or the terminal is non-interactive without the exact phrase, the install aborts.

## Custom taint rules

Beyond the built-in credential taint, you can define your own data-flow rules in YAML and pass them with `--rules`:

```
scbox --rules my-rules.yml ./suspicious-package
```

A rule names sources (env vars or files the sample reads, matched by glob) and sinks (where a value must show up to count: `network`, `command`, or `file`). SCBoX serves a bait value for each source, or your own `bait:`, and flags the rule only when that exact bait reaches a sink, raw or base64/hex-encoded. A read on its own does nothing. This is the same causal-flow standard as the built-in credential-exfil detector, with sources, sinks, severity, and attribution you control.

```yaml
taint:
  - name: corp-api-token
    description: internal Acme API token must never leave the box
    severity: malicious            # low | suspicious | malicious  (weights 10/30/60)
    sources:
      - env: ACME_API_TOKEN
        bait: acme_live_3f9c8b21d7e64a05b1c2
    sinks: [network, command, file]

  - name: corp-config-leak
    description: ~/.config/acme/*.json holds signing keys
    sources:
      - file: "~/.config/acme/*.json"   # * stops at /, ** crosses it, ~ = any home
    sinks: [network]                     # defaults to [network] if omitted
```

Runnable presets live in [`examples/taint/`](examples/taint). `builtin-credentials.yml` restates SCBoX's native credential and infostealer sources in this format so you can copy and extend them, and `custom-example.yml` is a documented starting point for org-specific secrets.

## What it does to a package

1. Extracts the package (tarball or dir) into an isolated workspace. No scripts run yet.
2. Resolves and materializes the dependency tree, from the registry or on disk.
3. Runs lifecycle scripts (`preinstall`, `install`, `postinstall`, and so on) for every package, deepest first, through the faked shell.
4. Requires the entry point, so real dependency code runs inline.
5. Force-execution: invokes every export with fuzzed args, requires every dependency, and runs every `.js`, `.ts`, and `.sh` file to trip dormant payloads.
6. Drains timers on the virtual clock so delayed payloads fire.
7. Renders the verdict, attribution, IOCs, program output, and trace.

## Output

- Verdict: `clean`, `low`, `suspicious`, or `malicious`, with a score and ranked reasons.
- Risky packages: per-package attribution of which dependency did the network, process, eval, or fs activity.
- Indicators: URLs, IPs, domains, `.onion` addresses, emails, crypto wallets, secrets and tokens, network payloads (exfil bodies), HTTP headers, crypto ops, files written, deleted, or read, env vars read, dependencies, decoded or deobfuscated blobs, and shell commands.
- Program output: everything the sample printed (`console.*`, `stdout`, `stderr`).
- Behavioral trace: a time-ordered, per-package event log. Use `--json` for the full machine-readable report.

## Architecture

```
main.go                       CLI, orchestration (analyze), report rendering
internal/
  sandbox/                    the faked Node runtime (goja)
    runtime.go                VM, limits, budgets, virtual clock, global-hiding
    globals.go                console, Buffer (Uint8Array-backed), timers, fetch, web globals
    eval.go                   eval / Function-constructor-chain / deobfuscation hooks
    require.go                CommonJS loader, module resolution, logging-Proxy for missing deps
    builtins.go               fake fs / child_process / http(s) / net / dns / os / crypto / vm / ...
    process.go                fake process global + bait env
    evasion.go                Arch profile + fake-filesystem content
    commands.go               recon-command output (whoami/id/uname/gh/IMDS/...)
    transpile.go              TS/JSX/ESM to CommonJS via esbuild (parse-only)
    shell.go                  .sh + lifecycle execution via mvdan.cc/sh (faked handlers)
    explore.go                force-execution of exports/files/deps
    nodecompat.go             Error.captureStackTrace, crypto, WebAssembly, ...
  npm/                        package load, tarball extraction, lifecycle runner, dep-tree installer
  registry/                   npm registry client + minimal semver
  rules/                      user-defined YAML taint rules (sources to sinks, glob matching)
  trace/                      events, IOC extraction, verdict heuristics, per-package stats
testdata/                     fixtures (benign, evil, evasive, transitive, deleter, probe, megaprobe)
```

## Testing

```
go test ./...
```

The suite checks the core invariants end to end: benign packages stay clean, malicious fixtures are flagged, transitive malware is attributed to the right dependency, destructive ops (`unlinkSync`, `rm -rf`) and writes never touch the real disk, and credential bait is captured on exfil. The 64-check mega-probe checks for instrumentation-global leaks, `/tmp` path leaks, identity fidelity, real buffer indexing, native-code masking, and busy-wait-sleep defeat.

## Use with caution

SCBoX is not perfect and should not be your only line of defense. It is a heuristic triage tool. It can miss malware that is novel or well hidden (false negatives), and it can flag benign packages that happen to behave like malware (false positives). A clean verdict lowers your risk but does not prove a package is safe. A malicious verdict is a strong reason to look closely before you install. Treat the output as one signal among several: read the trace, review flagged packages by hand, keep your other controls (lockfiles, pinned versions, registry policies) in place, and run the analyzer itself in an isolated environment. If a package matters and the verdict is uncertain, do not rely on SCBoX alone.

## Limitations

- Triage signal, not a formal classifier. Tune the verdict weights for your corpus.
- goja targets roughly ES2018. esbuild downlevels most modern and TypeScript syntax, but exotic constructs may not transpile.
- TypeScript projects that need a custom build toolchain (for example `bun run build`) are not built. Point SCBoX at runnable JS/TS, or transpile first.
- Python loaders are logged as commands, not executed.
- An in-process interpreter cannot guarantee immunity to a goja bug, so isolate the analyzer process.

## Dependencies

SCBoX has no external module dependencies. Every third-party library is vendored, frozen, and audited in-tree under `internal/third_party/`, so the tool builds fully offline (`GOPROXY=off`) and its own supply chain cannot be tampered with at build time. The upstream projects these copies come from:

| Vendored as | Upstream | Role |
|-------------|----------|------|
| `internal/third_party/goja` | [github.com/dop251/goja](https://github.com/dop251/goja) | pure-Go ECMAScript interpreter (the sandbox VM) |
| `internal/third_party/esbuild` | [github.com/evanw/esbuild](https://github.com/evanw/esbuild) | TS/JSX/ESM to CommonJS transpilation (parse-only) |
| `internal/third_party/sh` | [mvdan.cc/sh](https://github.com/mvdan/sh) | pure-Go shell parser and interpreter (faked lifecycle scripts) |
| `internal/third_party/regexp2` | [github.com/dlclark/regexp2](https://github.com/dlclark/regexp2) | .NET-compatible regex engine (goja dependency) |
| `internal/third_party/sourcemap` | [github.com/go-sourcemap/sourcemap](https://github.com/go-sourcemap/sourcemap) | source-map consumer (goja dependency) |
| `internal/third_party/pprof` | [github.com/google/pprof](https://github.com/google/pprof) | profile proto (goja dependency) |
| `internal/third_party/yaml` | [gopkg.in/yaml.v3](https://github.com/go-yaml/yaml) | YAML parser (custom taint rules) |

## References

The anti-evasion profile was researched against these catalogs of sandbox and VM detection techniques:

- [evasions.checkpoint.com](https://evasions.checkpoint.com/) - Check Point's encyclopedia of evasion techniques.
- [github.com/a0rtega/pafish](https://github.com/a0rtega/pafish) - Pafish, a tool that demonstrates the checks malware uses to detect analysis environments.
- [MITRE ATT&CK T1497](https://attack.mitre.org/techniques/T1497/) - Virtualization/Sandbox Evasion.
