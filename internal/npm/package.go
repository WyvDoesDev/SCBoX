// Package npm loads an npm package (directory or .tgz tarball) for analysis and
// drives its lifecycle scripts through the sandbox. Everything is materialized
// into an in-memory vfs.FS - tarballs are extracted in memory with pure Go, a
// source directory is read (never copied to disk) - so no untrusted byte ever
// touches the host filesystem and no real `npm install` ever runs.
package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"scbox/internal/vfs"
)

// Manifest is the subset of package.json relevant to triage.
type Manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Main                 string            `json:"main"`
	Scripts              map[string]string `json:"scripts"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// UnmarshalJSON parses package.json leniently. Real-world manifests sometimes
// carry non-string values where this triage subset expects strings - e.g. a
// "scripts" entry whose value is an object, or a numeric version. Standard
// encoding/json aborts the entire parse on the first such mismatch, which would
// make scbox refuse to analyze (and the install gate fail-closed on) an otherwise
// perfectly installable package. We decode each field into json.RawMessage and
// keep only the string-coercible parts, dropping the rest, so a quirky manifest
// degrades gracefully instead of failing.
func (m *Manifest) UnmarshalJSON(data []byte) error {
	var raw struct {
		Name                 json.RawMessage            `json:"name"`
		Version              json.RawMessage            `json:"version"`
		Main                 json.RawMessage            `json:"main"`
		Scripts              map[string]json.RawMessage `json:"scripts"`
		Dependencies         map[string]json.RawMessage `json:"dependencies"`
		OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
		DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
		PeerDependencies     map[string]json.RawMessage `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.Name = rawString(raw.Name)
	m.Version = rawString(raw.Version)
	m.Main = rawString(raw.Main)
	m.Scripts = rawStringMap(raw.Scripts)
	m.Dependencies = rawStringMap(raw.Dependencies)
	m.OptionalDependencies = rawStringMap(raw.OptionalDependencies)
	m.DevDependencies = rawStringMap(raw.DevDependencies)
	m.PeerDependencies = rawStringMap(raw.PeerDependencies)
	return nil
}

// rawString coerces a JSON value to a string, returning "" for anything that
// isn't a JSON string (object/array/number/null).
func rawString(r json.RawMessage) string {
	var s string
	if len(r) > 0 && json.Unmarshal(r, &s) == nil {
		return s
	}
	return ""
}

// rawStringMap keeps only the string-valued entries of a decoded JSON object.
func rawStringMap(in map[string]json.RawMessage) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if s := rawString(v); s != "" {
			out[k] = s
		}
	}
	return out
}

// Package is a loaded, ready-to-analyze package. Dir is its (virtual) directory
// inside FS; nothing here is backed by the real disk.
type Package struct {
	Dir      string
	Manifest Manifest
	FS       *vfs.FS
}

// Close is retained for callers but has nothing to clean up: there are no temp
// files - the whole package lives in memory and is freed with the FS.
func (p *Package) Close() {}

// lifecycleOrder is the npm install-time hook order we replay.
var lifecycleOrder = []string{"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"}

// LifecycleScript is a single hook to run.
type LifecycleScript struct {
	Name    string
	Command string
}

// LifecycleScripts returns the present install-time hooks in execution order.
func (p *Package) LifecycleScripts() []LifecycleScript {
	var out []LifecycleScript
	for _, name := range lifecycleOrder {
		if cmd, ok := p.Manifest.Scripts[name]; ok && strings.TrimSpace(cmd) != "" {
			out = append(out, LifecycleScript{Name: name, Command: cmd})
		}
	}
	return out
}

// Dependencies returns the names that would be installed (runtime + optional).
func (p *Package) Dependencies() []string {
	set := map[string]struct{}{}
	for k := range p.Manifest.Dependencies {
		set[k] = struct{}{}
	}
	for k := range p.Manifest.OptionalDependencies {
		set[k] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// EntryPoint returns the relative module path to require first.
func (p *Package) EntryPoint() string {
	if p.Manifest.Main != "" {
		return "./" + strings.TrimPrefix(p.Manifest.Main, "./")
	}
	return "./index.js"
}

// LoadDir ingests a real package directory into a fresh in-memory FS rooted at
// root. The user's files are READ; nothing is ever written back to disk.
func LoadDir(dir, root string) (*Package, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(abs, "package.json")); err != nil {
		return nil, fmt.Errorf("no package.json in %q: %w", abs, err)
	}
	fs := vfs.New()
	if err := ingestDir(abs, fs, root); err != nil {
		return nil, err
	}
	mf, err := readManifest(fs, root)
	if err != nil {
		return nil, err
	}
	return &Package{Dir: root, Manifest: mf, FS: fs}, nil
}

// LoadTarball ingests an in-memory .tgz into a fresh FS rooted at root.
func LoadTarball(data []byte, root string) (*Package, error) {
	fs := vfs.New()
	pkgDir, err := extractPackage(data, fs, root)
	if err != nil {
		return nil, err
	}
	mf, err := readManifest(fs, pkgDir)
	if err != nil {
		return nil, err
	}
	return &Package{Dir: pkgDir, Manifest: mf, FS: fs}, nil
}

// ingestDir reads a real directory tree into fs under destRoot. Symlinks and
// special files are skipped (never followed onto the host).
func ingestDir(srcAbs string, fs *vfs.FS, destRoot string) error {
	return filepath.Walk(srcAbs, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, e := filepath.Rel(srcAbs, p)
		if e != nil {
			return e
		}
		dest := path.Join(destRoot, filepath.ToSlash(rel))
		if info.IsDir() {
			fs.Mkdir(dest)
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil // skip symlinks/devices
		}
		data, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		fs.Write(dest, data)
		return nil
	})
}

// extractPackage extracts a gzipped npm tarball into fs under destRoot, stripping
// the conventional leading wrapper directory so the package's files land
// directly under destRoot. Returns destRoot.
func extractPackage(data []byte, fs *vfs.FS, destRoot string) (string, error) {
	staging := vfs.New()
	if err := extractTarGzToFS(bytes.NewReader(data), staging, "/"); err != nil {
		return "", err
	}
	pkgRoot, err := findPackageRoot(staging)
	if err != nil {
		return "", err
	}
	prefix := pkgRoot
	if prefix != "/" {
		prefix += "/"
	}
	staging.Walk(pkgRoot, func(p string, isDir bool) {
		if p == pkgRoot {
			return
		}
		dest := path.Join(destRoot, strings.TrimPrefix(p, prefix))
		if isDir {
			fs.Mkdir(dest)
			return
		}
		if b, ok := staging.Read(p); ok {
			fs.Write(dest, b)
		}
	})
	return destRoot, nil
}

// extractTarGzToFS unpacks a gzipped tarball into fs under destRoot, rejecting
// path-traversal entries and capping total extracted bytes.
func extractTarGzToFS(r io.Reader, fs *vfs.FS, destRoot string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("not a gzip tarball: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	const maxBytes = 256 << 20  // 256MB extraction cap (content bytes)
	const maxEntries = 200000   // cap entry COUNT: a tarball of millions of empty
	                            // files passes the byte cap (0-byte files add
	                            // nothing to total) but would still bloat the
	                            // in-memory vfs maps in the unsandboxed parent.
	var total int64
	var entries int
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if entries++; entries > maxEntries {
			return fmt.Errorf("tarball exceeds %d entry cap", maxEntries)
		}
		clean := path.Clean(filepath.ToSlash(hdr.Name))
		if strings.HasPrefix(clean, "..") || strings.Contains(clean, "../") {
			continue // skip traversal attempts
		}
		target := path.Join(destRoot, clean)
		if !withinRoot(destRoot, target) {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			fs.Mkdir(target)
		case tar.TypeReg:
			var buf bytes.Buffer
			n, err := io.CopyN(&buf, tr, maxBytes-total)
			total += n
			if err != nil && err != io.EOF {
				return err
			}
			fs.Write(target, buf.Bytes())
			if total >= maxBytes {
				return fmt.Errorf("tarball exceeds %d byte extraction cap", maxBytes)
			}
		}
	}
	return nil
}

// withinRoot reports whether target is at or under root (both virtual paths).
func withinRoot(root, target string) bool {
	root = vfs.Clean(root)
	target = vfs.Clean(target)
	if root == "/" || target == root {
		return true
	}
	return strings.HasPrefix(target, root+"/")
}

// readManifest parses package.json from a directory inside fs.
func readManifest(fs *vfs.FS, dir string) (Manifest, error) {
	var mf Manifest
	data, ok := fs.Read(path.Join(dir, "package.json"))
	if !ok {
		return mf, fmt.Errorf("no package.json in %q", dir)
	}
	if err := json.Unmarshal(data, &mf); err != nil {
		return mf, fmt.Errorf("invalid package.json: %w", err)
	}
	return mf, nil
}

// ReadManifestDir parses package.json from an already-materialized FS directory.
func ReadManifestDir(fs *vfs.FS, dir string) (Manifest, error) { return readManifest(fs, dir) }

// findPackageRoot locates the shallowest directory in fs containing a
// package.json (npm tarballs conventionally nest everything under "package/").
func findPackageRoot(fs *vfs.FS) (string, error) {
	if fs.Exists("/package/package.json") {
		return "/package", nil
	}
	found := ""
	best := 1 << 30
	fs.Walk("/", func(p string, isDir bool) {
		if isDir || path.Base(p) != "package.json" {
			return
		}
		if depth := strings.Count(p, "/"); depth < best {
			best = depth
			found = path.Dir(p)
		}
	})
	if found == "" {
		return "", fmt.Errorf("no package.json found in tarball")
	}
	return found, nil
}
