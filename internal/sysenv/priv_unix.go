//go:build !windows

package sysenv

import (
	"io/fs"
	"os"
	"syscall"
)

func isPrivileged() bool { return os.Geteuid() == 0 }

// FileOwner returns the owning uid/gid when the platform exposes them.
func FileOwner(fi fs.FileInfo) (uid, gid uint32, ok bool) {
	if st, isStat := fi.Sys().(*syscall.Stat_t); isStat && st != nil {
		return st.Uid, st.Gid, true
	}
	return 0, 0, false
}
