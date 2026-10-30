//go:build windows

package sysenv

import (
	"io/fs"

	"golang.org/x/sys/windows"
)

func isPrivileged() bool { return windows.GetCurrentProcessToken().IsElevated() }

// FileOwner is not available on Windows.
func FileOwner(fs.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }
