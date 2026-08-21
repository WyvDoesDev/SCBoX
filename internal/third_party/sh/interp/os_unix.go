// Copyright (c) 2017, Andrey Nering <andrey.nering@gmail.com>
// See LICENSE for licensing information

//go:build unix

package interp

import (
	"context"
	"os"
	"syscall"

	"scbox/internal/third_party/sh/syntax"
)

// access checks whether path is accessible with the requested permission. The
// mode bits are the access(2) constants access_R_OK/W_OK/X_OK, which conveniently
// match the low octal permission triad.
//
// SCBoX patch: upstream issued a real access(2) syscall against the host
// (unix.Access), which both leaked real host files to untrusted scripts (e.g.
// `[ -x /usr/bin/sudo ]`, sandbox-detection probes like `[ -e /.dockerenv ]`)
// and bypassed the embedder's faked filesystem entirely. We now route the probe
// through the stat handler — which the embedder fakes against its in-memory FS —
// and check the reported owner permission bits. No host syscall is issued.
func (r *Runner) access(ctx context.Context, path string, mode uint32) error {
	info, err := r.statHandler(ctx, path, true)
	if err != nil {
		return err
	}
	want := os.FileMode(mode & 0o7)
	owner := (info.Mode().Perm() >> 6) & 0o7
	if owner&want != want {
		return syscall.EACCES
	}
	return nil
}

// unTestOwnOrGrp implements the -O and -G unary tests.
//
// SCBoX patch: upstream consulted the real host user (user.Current) and the
// underlying *syscall.Stat_t, which leaked host identity and panicked on a faked
// FileInfo whose Sys() is nil. In the sandbox every file in the virtual FS is
// owned by the (faked) current user, so ownership reduces to existence.
func (r *Runner) unTestOwnOrGrp(ctx context.Context, op syntax.UnTestOperator, x string) bool {
	_, err := r.stat(ctx, x)
	return err == nil
}

type waitStatus = syscall.WaitStatus
