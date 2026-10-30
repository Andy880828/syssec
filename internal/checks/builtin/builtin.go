// Package builtin contains syssec's built-in rule sets. Every rule is
// compiled on every platform and filtered at runtime by CheckMeta.Platforms,
// which keeps the whole catalog testable from any OS.
package builtin

import (
	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/core"
)

var (
	linux   = []string{"linux"}
	darwin  = []string{"darwin"}
	windows = []string{"windows"}
	unix    = []string{"linux", "darwin"}
)

type severity = core.Severity

const (
	info     = core.SeverityInfo
	low      = core.SeverityLow
	medium   = core.SeverityMedium
	high     = core.SeverityHigh
	critical = core.SeverityCritical
)

// meta is a compact constructor for rule metadata.
func meta(id string, sev core.Severity, category, title string, platforms []string, remediation string, refs ...string) core.CheckMeta {
	return core.CheckMeta{
		ID: id, Severity: sev, Category: category, Title: title,
		Platforms: platforms, Remediation: remediation, References: refs,
	}
}

// host marks a control that only the host (not a container) can change.
func host(m core.CheckMeta) core.CheckMeta {
	m.Tags = append(m.Tags, core.TagHostOnly)
	return m
}

// All returns every built-in check.
func All() []checks.Check {
	var out []checks.Check
	for _, set := range [][]checks.Check{
		sshChecks(), kernelChecks(), networkSysctlChecks(), filesystemChecks(),
		accountChecks(), networkChecks(), linuxSystemChecks(), restartChecks(), darwinChecks(), windowsChecks(),
	} {
		out = append(out, set...)
	}
	return withProfiles(out)
}

// Register adds the built-in catalog to r.
func Register(r *checks.Registry) { r.MustRegister(All()...) }
