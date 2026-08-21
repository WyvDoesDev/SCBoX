package npm

import (
	"fmt"
	"path"
	"sort"
	"sync"

	"scbox/internal/registry"
	"scbox/internal/trace"
	"scbox/internal/vfs"
)

// Installed is one package materialized into the analysis workspace.
type Installed struct {
	Name             string
	Version          string
	Dir              string
	Depth            int
	Fetched          bool // true if downloaded, false if already present on disk
	Dev              bool // reached only via the analyzed package's devDependencies (not part of the install surface)
	RuntimeInstalled bool // fetched because the analyzed code installs/requires it at runtime (dropper second stage)
}

// Installer resolves and materializes a dependency tree into a node_modules
// directory WITHOUT executing anything. The sandbox later detonates the code;
// the installer only ever moves inert bytes.
type Installer struct {
	Reg         *registry.Client // nil ⇒ offline (use only what's already in FS)
	FS          *vfs.FS          // in-memory tree everything is materialized into
	NodeModules string           // <virtual-root>/node_modules
	MaxDepth    int
	MaxPkgs     int
	Concurrency int  // max packages fetched in parallel per depth level; <=0 ⇒ default
	IncludeDev  bool // also resolve+detonate the devDependency tree (off ⇒ install surface only)
	Tracer      *trace.Tracer
	Logf        func(format string, a ...any) // optional progress sink (verbose mode)
}

func (in *Installer) logf(format string, a ...any) {
	if in.Logf != nil {
		in.Logf(format, a...)
	}
}

type treeItem struct {
	name, rng string
	depth     int
	dev       bool // reached only through the analyzed package's devDependencies
}

// Build walks the dependency graph breadth-first, materializing each package
// (flat/hoisted by name, first-wins) and returning everything installed.
//
// Resolution runs on a fixed pool of Concurrency workers that continuously pull
// the shallowest unclaimed package from a shared frontier. There are no per-depth
// barriers: a deep package starts downloading the instant a worker is free, even
// while a slow sibling at a shallower depth is still in flight - so a few large
// tarballs (e.g. typescript's dev tree) no longer stall the whole walk. Each name
// is still claimed first-wins at the shallowest depth it appears (workers always
// take the lowest-depth job), so the resulting flat tree matches a serial BFS.
func (in *Installer) Build(root *Package) []Installed {
	if in.MaxDepth <= 0 {
		in.MaxDepth = 6
	}
	if in.MaxPkgs <= 0 {
		in.MaxPkgs = 200
	}
	conc := in.Concurrency
	if conc <= 0 {
		conc = 32 // resolution is network/latency-bound, so oversubscribe cores
	}

	// peerMaxDepth caps how deep peer dependencies recurse. Peer trees can be far
	// larger than runtime trees, so without a bound the walk could balloon; 20 is
	// deep enough to make real packages run while staying finite.
	const peerMaxDepth = 20

	var (
		mu        sync.Mutex
		cond      = sync.NewCond(&mu)
		frontier  []treeItem // discovered-but-unclaimed jobs
		visited   = map[string]bool{}
		installed []Installed
		active    int  // workers currently fetching
		done      bool // no further work will appear; wake everyone to exit
	)

	// push adds child deps to the frontier (caller holds mu), tagging them with
	// the dev taint of their parent so dev-tree members can be attributed apart
	// from the real install surface later.
	push := func(deps map[string]string, depth int, dev bool) {
		for n, r := range deps {
			if !visited[n] {
				frontier = append(frontier, treeItem{name: n, rng: r, depth: depth, dev: dev})
			}
		}
	}

	// Seed level 1 from the analyzed package. By default we resolve only the real
	// install surface - runtime + optional + peer deps - because that is exactly
	// what `npm install <pkg>` downloads and runs for a consumer, and it is what
	// the verdict scores. devDependencies are skipped: they are never installed or
	// run by consumers, do not affect the verdict, and dragging in their (often
	// enormous) trees is the dominant cost. --dev (IncludeDev) opts into resolving
	// and detonating them for a full development-time behavior report.
	mu.Lock()
	push(root.Manifest.Dependencies, 1, false)
	push(root.Manifest.OptionalDependencies, 1, false)
	push(root.Manifest.PeerDependencies, 1, false)
	if in.IncludeDev {
		push(root.Manifest.DevDependencies, 1, true)
	}
	mu.Unlock()

	// claim removes and returns the lowest-depth (then lexically-first) unvisited
	// job, marking it visited. Caller holds mu. ok=false if none is claimable.
	claim := func() (treeItem, bool) {
		best := -1
		for i := range frontier {
			it := frontier[i]
			if visited[it.name] || it.depth > peerMaxDepth {
				continue
			}
			if best == -1 || it.depth < frontier[best].depth ||
				(it.depth == frontier[best].depth && it.name < frontier[best].name) {
				best = i
			}
		}
		if best == -1 {
			return treeItem{}, false
		}
		it := frontier[best]
		frontier = append(frontier[:best], frontier[best+1:]...)
		visited[it.name] = true
		return it, true
	}

	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				var it treeItem
				var ok bool
				for {
					if done || len(installed) >= in.MaxPkgs {
						mu.Unlock()
						return
					}
					if it, ok = claim(); ok {
						active++
						break
					}
					// Nothing claimable right now. If no one is fetching, the walk
					// is complete; otherwise wait for an in-flight worker to push.
					if active == 0 {
						done = true
						cond.Broadcast()
						mu.Unlock()
						return
					}
					cond.Wait()
				}
				mu.Unlock()

				depDir := path.Join(in.NodeModules, it.name)
				in.logf("resolving %s@%s (depth %d)", it.name, it.rng, it.depth)
				mf, fetched, err := in.materialize(it.name, it.rng, depDir)

				mu.Lock()
				active--
				if err != nil {
					in.logf("  ! %s@%s failed: %v", it.name, it.rng, err)
					in.Tracer.Note(trace.CatModule, "dep-resolve-failed", err.Error(), it.name+"@"+it.rng)
				} else {
					in.Tracer.Record(trace.CatModule, "dep-installed", it.name+"@"+mf.Version)
					installed = append(installed, Installed{
						Name: it.name, Version: mf.Version, Dir: depDir, Depth: it.depth, Fetched: fetched, Dev: it.dev,
					})
					// Recurse runtime + peer edges only, inheriting the dev taint.
					// Transitive devDependencies are deliberately NOT followed - npm
					// never installs them, and pulling them is what ballooned the tree
					// and drowned verdicts in benign dev-tooling behavior.
					if it.depth < in.MaxDepth {
						push(mf.Dependencies, it.depth+1, it.dev)
						push(mf.OptionalDependencies, it.depth+1, it.dev)
					}
					if it.depth < peerMaxDepth {
						push(mf.PeerDependencies, it.depth+1, it.dev)
					}
				}
				// Wake workers: there may be new jobs, or this may have been the
				// last in-flight fetch (so idle workers can now terminate).
				cond.Broadcast()
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Workers append in completion order; sort for a deterministic, BFS-shaped
	// result (shallowest first, then by name) independent of fetch timing.
	sort.SliceStable(installed, func(i, j int) bool {
		if installed[i].Depth != installed[j].Depth {
			return installed[i].Depth < installed[j].Depth
		}
		return installed[i].Name < installed[j].Name
	})
	if len(installed) > in.MaxPkgs {
		installed = installed[:in.MaxPkgs]
	}
	return installed
}

// materialize ensures depDir contains the package in the in-memory FS, fetching
// + extracting from the registry (into memory) if it isn't already present.
// Returns its manifest. No real file is ever written.
// AddPackages materializes a set of explicitly-named packages (and their runtime
// dependency trees) into node_modules, on top of whatever Build already staged.
// It is used to follow a dropper's second stage: when the analyzed package's code
// runs `npm install <pkg>` / `require('<pkg>')` for something not in its manifest,
// we fetch <pkg> so detonation loads and detonates the REAL payload instead of a
// stub. Returned Installed entries are tagged so the report shows they came from a
// runtime install, not the declared tree. Names already present are skipped.
func (in *Installer) AddPackages(names []string) []Installed {
	if in.Reg == nil || len(names) == 0 {
		return nil
	}
	// Reuse Build by synthesizing a root whose dependencies are the targets, so
	// their transitive runtime deps come along too.
	deps := map[string]string{}
	for _, n := range names {
		deps[n] = "latest"
	}
	synthetic := &Package{
		Dir:      in.NodeModules, // unused for resolution; deps drive the walk
		Manifest: Manifest{Name: "(runtime-install)", Dependencies: deps},
		FS:       in.FS,
	}
	added := in.Build(synthetic)
	for i := range added {
		added[i].RuntimeInstalled = true
	}
	return added
}

func (in *Installer) materialize(name, rng, depDir string) (Manifest, bool, error) {
	// Already present (shipped node_modules ingested into FS, or fetched earlier).
	if in.FS.Exists(path.Join(depDir, "package.json")) {
		mf, err := ReadManifestDir(in.FS, depDir)
		return mf, false, err
	}
	if in.Reg == nil {
		return Manifest{}, false, fmt.Errorf("offline: %s not present", name)
	}

	vm, err := in.Reg.Resolve(name, rng)
	if err != nil {
		return Manifest{}, false, err
	}
	data, err := in.Reg.Download(name, vm)
	if err != nil {
		return Manifest{}, false, err
	}
	// Extract in memory (no execution, no disk), re-rooted under depDir.
	if _, err := extractPackage(data, in.FS, depDir); err != nil {
		return Manifest{}, false, err
	}
	mf, err := ReadManifestDir(in.FS, depDir)
	return mf, true, err
}
