//go:build !windows

package sysenv

type noRegistry struct{}

func (noRegistry) Integer(string, string) (uint64, error) { return 0, ErrUnsupported }
func (noRegistry) String(string, string) (string, error)  { return "", ErrUnsupported }
func (noRegistry) SubKeys(string) ([]string, error)       { return nil, ErrUnsupported }

// NewRegistry returns the platform registry implementation.
func NewRegistry() Registry { return noRegistry{} }
