package npm

import (
	"scbox/internal/sandbox"
	"scbox/internal/trace"
)

// RunLifecycleScoped runs a package's hooks with trace events attributed to the
// given package name.
func RunLifecycleScoped(rt *sandbox.Runtime, pkg *Package, scope string) {
	prev := rt.Tracer().SetScope(scope)
	defer rt.Tracer().SetScope(prev)
	RunLifecycle(rt, pkg)
}

// RunLifecycle replays the package's install-time hooks through the sandbox.
// The whole command line is interpreted by the faked shell (mvdan.cc/sh), which
// handles &&, pipes, $(...), env expansion, etc.; node/ts-node/bash invocations
// are bridged into goja/the shell analyzer, and every other command is logged
// and faked.
func RunLifecycle(rt *sandbox.Runtime, pkg *Package) {
	tr := rt.Tracer()
	for _, s := range pkg.LifecycleScripts() {
		tr.Note(trace.CatLifecyc, s.Name, s.Command)
		rt.RunShellScript(s.Command, pkg.Dir)
	}
}
