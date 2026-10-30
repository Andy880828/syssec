package builtin

import (
	"github.com/Andy880828/syssec/internal/checks"
)

// cisLevel maps built-in checks onto CIS Benchmark levels by intent. CIS
// section numbers differ per benchmark (Ubuntu, RHEL, macOS, Windows), so
// syssec maps levels only and does not claim certified coverage. Checks
// without an entry (exposure inventory, restart gaps, container sockets)
// are syssec's own and belong to no CIS profile.
var cisLevel = map[string]string{
	// SSH
	"SSH-001": "cis-l1", "SSH-002": "cis-l2", "SSH-003": "cis-l1", "SSH-004": "cis-l1",
	"SSH-005": "cis-l1", "SSH-006": "cis-l1", "SSH-007": "cis-l1", "SSH-008": "cis-l1",
	// Kernel & network parameters
	"KRN-001": "cis-l1", "KRN-004": "cis-l1", "KRN-005": "cis-l1", "KRN-006": "cis-l1", "KRN-007": "cis-l1",
	"KRN-002": "cis-l2", "KRN-003": "cis-l2", "KRN-008": "cis-l2", "KRN-009": "cis-l2", "KRN-010": "cis-l2",
	"NET-101": "cis-l1", "NET-102": "cis-l1", "NET-103": "cis-l1", "NET-104": "cis-l1", "NET-105": "cis-l1",
	"NET-106": "cis-l1", "NET-107": "cis-l1", "NET-108": "cis-l1", "NET-109": "cis-l1",
	// Filesystem, accounts, system
	"FS-001": "cis-l1", "FS-002": "cis-l1", "FS-003": "cis-l1", "FS-004": "cis-l1", "FS-005": "cis-l1",
	"FS-006": "cis-l1", "FS-007": "cis-l1", "FS-010": "cis-l1", "FS-011": "cis-l1", "FS-020": "cis-l1", "FS-021": "cis-l1",
	"ACC-001": "cis-l1", "ACC-002": "cis-l1", "ACC-003": "cis-l1", "ACC-004": "cis-l1", "ACC-005": "cis-l2",
	"SYS-001": "cis-l1", "SYS-002": "cis-l2", "SYS-004": "cis-l1", "SYS-005": "cis-l1",
	// macOS
	"MAC-001": "cis-l1", "MAC-002": "cis-l1", "MAC-003": "cis-l1", "MAC-004": "cis-l1", "MAC-005": "cis-l2",
	"MAC-006": "cis-l1", "MAC-007": "cis-l1", "MAC-008": "cis-l1", "MAC-009": "cis-l1", "MAC-010": "cis-l1",
	// Windows
	"WIN-001": "cis-l1", "WIN-002": "cis-l1", "WIN-003": "cis-l1", "WIN-004": "cis-l1", "WIN-005": "cis-l1",
	"WIN-006": "cis-l1", "WIN-007": "cis-l1", "WIN-008": "cis-l1", "WIN-009": "cis-l1", "WIN-010": "cis-l1",
	"WIN-011": "cis-l1", "WIN-012": "cis-l1", "WIN-013": "cis-l1", "WIN-014": "cis-l2", "WIN-015": "cis-l1", "WIN-016": "cis-l1",
}

// withProfiles attaches profile membership to built-in checks.
func withProfiles(cs []checks.Check) []checks.Check {
	for i, c := range cs {
		if f, ok := c.(checks.Func); ok {
			if lvl, ok := cisLevel[f.M.ID]; ok {
				f.M.Profiles = append(f.M.Profiles, lvl)
				cs[i] = f
			}
		}
	}
	return cs
}
