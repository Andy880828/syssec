//go:build windows

package sysenv

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type winRegistry struct{}

// NewRegistry returns the platform registry implementation.
func NewRegistry() Registry { return winRegistry{} }

func openKey(path string) (registry.Key, error) {
	root, sub, _ := strings.Cut(path, `\`)
	var base registry.Key
	switch strings.ToUpper(root) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		base = registry.LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		base = registry.CURRENT_USER
	case "HKU", "HKEY_USERS":
		base = registry.USERS
	default:
		return 0, fmt.Errorf("unsupported registry root %q", root)
	}
	k, err := registry.OpenKey(base, sub, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, ErrNotExist
	}
	return k, err
}

func (winRegistry) Integer(path, name string) (uint64, error) {
	k, err := openKey(path)
	if err != nil {
		return 0, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, ErrNotExist
	}
	return v, err
}

func (winRegistry) String(path, name string) (string, error) {
	k, err := openKey(path)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", ErrNotExist
	}
	return v, err
}

func (winRegistry) SubKeys(path string) ([]string, error) {
	k, err := openKey(path)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.ReadSubKeyNames(-1)
}
