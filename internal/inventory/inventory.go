// Package inventory enumerates installed software by reading package
// manager databases directly (dpkg, apk, pacman, Homebrew, Windows
// Uninstall registry), falling back to the native CLI only for rpm.
package inventory

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

// Collector reads one package manager's database.
type Collector interface {
	Name() string
	Applicable(env *sysenv.Env) bool
	Collect(ctx context.Context, env *sysenv.Env) ([]core.Package, error)
}

// Collectors is the ordered list of known package sources. Append to it to
// support a new package manager.
var Collectors = []Collector{dpkg{}, apk{}, rpm{}, pacman{}, brew{}, winUninstall{}}

// Collect runs every applicable collector. Errors are per-collector and non-fatal.
func Collect(ctx context.Context, env *sysenv.Env) ([]core.Package, []error) {
	var pkgs []core.Package
	var errs []error
	for _, c := range Collectors {
		if !c.Applicable(env) {
			continue
		}
		got, err := c.Collect(ctx, env)
		if err != nil {
			errs = append(errs, fmt.Errorf("inventory %s: %w", c.Name(), err))
		}
		pkgs = append(pkgs, got...)
	}
	slices.SortFunc(pkgs, func(a, b core.Package) int {
		if c := strings.Compare(a.Manager, b.Manager); c != 0 {
			return c
		}
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Arch, b.Arch)
	})
	pkgs = slices.CompactFunc(pkgs, func(a, b core.Package) bool { return a.Key() == b.Key() && a.Version == b.Version })
	return pkgs, errs
}

// Ecosystem maps the host distribution onto an OSV ecosystem name.
// An empty result means advisories cannot be matched for this distro.
func Ecosystem(env *sysenv.Env) string {
	r := env.OSRelease
	id, ver := r["ID"], r["VERSION_ID"]
	major, _, _ := strings.Cut(ver, ".")
	switch id {
	case "debian":
		if major != "" {
			return "Debian:" + major
		}
	case "ubuntu":
		if ver != "" {
			eco := "Ubuntu:" + ver
			if strings.Contains(r["VERSION"], "LTS") {
				eco += ":LTS"
			}
			return eco
		}
	case "alpine":
		parts := strings.SplitN(ver, ".", 3)
		if len(parts) >= 2 {
			return "Alpine:v" + parts[0] + "." + parts[1]
		}
	case "rocky":
		return "Rocky Linux:" + major
	case "almalinux":
		return "AlmaLinux:" + major
	}
	return ""
}
