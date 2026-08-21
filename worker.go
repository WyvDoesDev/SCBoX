package main

import (
	"context"
	"encoding/gob"
	"errors"
	"os"
	"os/exec"
	"runtime/debug"
	"time"

	"scbox/internal/npm"
	"scbox/internal/trace"
	"scbox/internal/vfs"
)

type workerRequest struct {
	Options   options
	PkgDir    string
	Manifest  npm.Manifest
	Installed []npm.Installed
	FS        vfs.Snapshot
}

type workerResponse struct {
	Report trace.Report
	Err    string
}

func runJailed(input string, o options) (trace.Report, *npm.Package, []npm.Installed, error) {
	pkg, installed, err := materialize(input, o)
	if err != nil {
		return trace.Report{}, nil, nil, err
	}

	budget := o.totalBudget
	if budget <= 0 {
		budget = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget+15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = append(os.Environ(), "SCBOX_WORKER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return trace.Report{}, nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return trace.Report{}, nil, nil, err
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return trace.Report{}, nil, nil, err
	}

	enc := gob.NewEncoder(stdin)
	dec := gob.NewDecoder(stdout)

	encErr := make(chan error, 1)
	go func() {
		err := enc.Encode(workerRequest{
			Options:   o,
			PkgDir:    pkg.Dir,
			Manifest:  pkg.Manifest,
			Installed: installed,
			FS:        pkg.FS.Snapshot(),
		})
		encErr <- err
		_ = stdin.Close()
	}()

	var resp workerResponse
	if err := dec.Decode(&resp); err != nil {
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return trace.Report{}, nil, nil, ctx.Err()
		}
		// A failed request encode truncates the worker's input and surfaces here
		// as an opaque EOF; prefer the underlying cause.
		if e := <-encErr; e != nil {
			return trace.Report{}, nil, nil, e
		}
		return trace.Report{}, nil, nil, err
	}
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return trace.Report{}, nil, nil, ctx.Err()
		}
		return trace.Report{}, nil, nil, err
	}
	if resp.Err != "" {
		return trace.Report{}, nil, nil, errors.New(resp.Err)
	}
	return resp.Report, pkg, installed, nil
}

func runWorker() {
	dec := gob.NewDecoder(os.Stdin)
	enc := gob.NewEncoder(os.Stdout)

	var req workerRequest
	if err := dec.Decode(&req); err != nil {
		_ = enc.Encode(workerResponse{Err: err.Error()})
		return
	}

	// Containment is purely in-process and userspace: the detonated code runs
	// inside the goja interpreter with every OS capability (fs, child_process,
	// net, dns, shell exec, …) faked, so it never issues a real syscall against
	// the host. By design the tool performs NO kernel-level isolation (no
	// namespaces, seccomp, capability drops, or rlimits) - it must run unmodified
	// on any user's machine as a pre-install checker. The worker still runs as a
	// separate process purely for crash/OOM isolation and a userspace memory cap;
	// the wall-clock guard is the parent's context timeout.
	if req.Options.memLimitMB > 0 {
		debug.SetMemoryLimit(int64(req.Options.memLimitMB) << 20)
	}

	tr := trace.New()
	tr.Record(trace.CatProcess, "sandbox", "in-process goja fakes; no kernel-level isolation (by design)")

	pkg := &npm.Package{Dir: req.PkgDir, Manifest: req.Manifest, FS: vfs.FromSnapshot(req.FS)}
	detonate(tr, pkg, req.Installed, req.Options)

	_ = enc.Encode(workerResponse{Report: tr.Report()})
}
