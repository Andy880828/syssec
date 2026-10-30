package sysenv

import "errors"

var (
	// ErrUnsupported is returned by registry access on non-Windows hosts.
	ErrUnsupported = errors.New("not supported on this platform")
	// ErrNotExist is returned when a registry key or value is absent.
	ErrNotExist = errors.New("registry key or value does not exist")
)

// Registry is read-only access to the Windows registry. Paths use the
// `HKLM\SOFTWARE\...` form.
type Registry interface {
	Integer(path, name string) (uint64, error)
	String(path, name string) (string, error)
	SubKeys(path string) ([]string, error)
}
