// Package sysenv abstracts the host the checks run against: filesystem,
// command execution, Windows registry and host identity. Every probe goes
// through these interfaces so checks are deterministic under test.
package sysenv

import (
	"io/fs"
	"os"
	"path/filepath"
)

// FS is the read-only filesystem view used by checks and collectors.
type FS interface {
	ReadFile(name string) ([]byte, error)
	Stat(name string) (fs.FileInfo, error)
	Lstat(name string) (fs.FileInfo, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	Readlink(name string) (string, error)
	Glob(pattern string) ([]string, error)
	WalkDir(root string, fn fs.WalkDirFunc) error
}

// OSFS is the real filesystem.
type OSFS struct{}

func (OSFS) ReadFile(n string) ([]byte, error)            { return os.ReadFile(n) }
func (OSFS) Stat(n string) (fs.FileInfo, error)           { return os.Stat(n) }
func (OSFS) Lstat(n string) (fs.FileInfo, error)          { return os.Lstat(n) }
func (OSFS) ReadDir(n string) ([]fs.DirEntry, error)      { return os.ReadDir(n) }
func (OSFS) Readlink(n string) (string, error)            { return os.Readlink(n) }
func (OSFS) Glob(p string) ([]string, error)              { return filepath.Glob(p) }
func (OSFS) WalkDir(root string, fn fs.WalkDirFunc) error { return filepath.WalkDir(root, fn) }
