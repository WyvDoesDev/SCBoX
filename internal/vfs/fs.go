// Package vfs is a purely in-memory filesystem. scbox materializes the package
// under analysis (and its entire dependency tree) into an FS instead of onto the
// host disk, so no untrusted byte is ever written to the real filesystem. The
// sandbox's module loader, shell, and explorer all read source from here.
//
// Paths are normalized to clean, absolute, forward-slash form. The zero value is
// not usable; call New. An FS is safe for concurrent readers (the parallel
// explore phase runs several sandbox VMs against one shared, read-only base FS),
// guarded by an RWMutex.
package vfs

import (
	"path"
	"sort"
	"strings"
	"sync"
)

// FS is an in-memory tree of files and directories.
type FS struct {
	mu    sync.RWMutex
	files map[string][]byte
	dirs  map[string]bool
}

// New returns an empty FS containing only the root directory.
func New() *FS {
	return &FS{files: map[string][]byte{}, dirs: map[string]bool{"/": true}}
}

// Clean normalizes p to an absolute, slash-separated, lexically-clean path. It
// is exported so callers building paths (extraction, the loader) share exactly
// the same normalization the FS keys on. Note that path.Clean resolves any
// ".." segments lexically; callers that must prevent escaping a root (tarball
// extraction) check containment separately before writing.
func Clean(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

// Write stores data at p, creating parent directories.
func (f *FS) Write(p string, data []byte) {
	p = Clean(p)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[p] = data
	f.mkdirAllLocked(path.Dir(p))
}

// Mkdir records p (and its parents) as a directory.
func (f *FS) Mkdir(p string) {
	p = Clean(p)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mkdirAllLocked(p)
}

func (f *FS) mkdirAllLocked(d string) {
	for {
		if d == "" {
			d = "/"
		}
		f.dirs[d] = true
		if d == "/" {
			return
		}
		d = path.Dir(d)
	}
}

// Read returns the content stored at p, and whether it exists as a file.
func (f *FS) Read(p string) ([]byte, bool) {
	p = Clean(p)
	f.mu.RLock()
	defer f.mu.RUnlock()
	b, ok := f.files[p]
	return b, ok
}

// Exists reports whether p is a known file or directory.
func (f *FS) Exists(p string) bool {
	p = Clean(p)
	f.mu.RLock()
	defer f.mu.RUnlock()
	if _, ok := f.files[p]; ok {
		return true
	}
	return f.dirs[p]
}

// Stat reports whether p is a directory and whether it exists at all.
func (f *FS) Stat(p string) (isDir, exists bool) {
	p = Clean(p)
	f.mu.RLock()
	defer f.mu.RUnlock()
	if _, ok := f.files[p]; ok {
		return false, true
	}
	if f.dirs[p] {
		return true, true
	}
	return false, false
}

// Delete removes a file or (empty-or-not) directory entry at p. Used to model a
// sample deleting a file; it never touches the host.
func (f *FS) Delete(p string) {
	p = Clean(p)
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.files, p)
	delete(f.dirs, p)
}

// ReadDir returns the immediate child names of dir (files and subdirectories),
// sorted. Names only, not full paths.
func (f *FS) ReadDir(dir string) []string {
	dir = Clean(dir)
	prefix := dir
	if prefix != "/" {
		prefix += "/"
	}
	seen := map[string]bool{}
	var out []string
	collect := func(p string) {
		if !strings.HasPrefix(p, prefix) {
			return
		}
		rest := p[len(prefix):]
		if rest == "" {
			return
		}
		name := rest
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			name = rest[:i]
		}
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	f.mu.RLock()
	for p := range f.files {
		collect(p)
	}
	for p := range f.dirs {
		collect(p)
	}
	f.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Walk visits every file and directory at or under root, directories first then
// files, each in sorted order. fn must not call back into mutating FS methods.
func (f *FS) Walk(root string, fn func(p string, isDir bool)) {
	root = Clean(root)
	prefix := root
	if prefix != "/" {
		prefix += "/"
	}
	within := func(p string) bool { return p == root || strings.HasPrefix(p, prefix) }

	f.mu.RLock()
	var files, dirs []string
	for p := range f.dirs {
		if within(p) {
			dirs = append(dirs, p)
		}
	}
	for p := range f.files {
		if within(p) {
			files = append(files, p)
		}
	}
	f.mu.RUnlock()

	sort.Strings(dirs)
	sort.Strings(files)
	for _, d := range dirs {
		fn(d, true)
	}
	for _, p := range files {
		fn(p, false)
	}
}

// NumFiles returns the number of files stored (test/diagnostic helper).
func (f *FS) NumFiles() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.files)
}

// Snapshot is a fully-exported, serializable view of an FS, used to hand the
// materialized package tree from the parent process to the jailed detonation
// child over a pipe.
type Snapshot struct {
	Files map[string][]byte
	Dirs  []string
}

// Snapshot copies the FS into a serializable form.
func (f *FS) Snapshot() Snapshot {
	f.mu.RLock()
	defer f.mu.RUnlock()
	files := make(map[string][]byte, len(f.files))
	for k, v := range f.files {
		files[k] = v
	}
	dirs := make([]string, 0, len(f.dirs))
	for d := range f.dirs {
		dirs = append(dirs, d)
	}
	return Snapshot{Files: files, Dirs: dirs}
}

// FromSnapshot rebuilds an FS from a Snapshot.
func FromSnapshot(s Snapshot) *FS {
	f := New()
	for k, v := range s.Files {
		f.files[k] = v
	}
	for _, d := range s.Dirs {
		f.dirs[d] = true
	}
	return f
}
