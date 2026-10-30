package builtin

import (
	"context"
	"path"
	"slices"
	"strings"
	"unicode"

	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/reach"
	"github.com/Andy880828/syssec/internal/sysenv"
)

// Patching is only half the job: the fix is live after the kernel or the
// affected services restart. These checks catch the gap on any distro.
func restartChecks() []checks.Check {
	return []checks.Check{
		checks.New(host(meta("SYS-007", medium, "system", "The newest installed kernel is running", linux,
			"Reboot into the newest installed kernel; kernel security fixes are not active until then.")),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				running := env.Host.Kernel
				installed := installedKernels(env)
				switch {
				case running == "":
					return checks.Skip("running kernel unknown")
				case len(installed) == 0:
					return checks.Skip("no package-managed kernels found in /boot or /lib/modules")
				case !slices.Contains(installed, running):
					return checks.Skip("running kernel %s is not package-managed (custom or VM-provided)", running)
				}
				newest := slices.MaxFunc(installed, VersionCompare)
				if VersionCompare(newest, running) > 0 {
					return checks.Fail("running %s, newest installed %s: reboot pending", running, newest)
				}
				return checks.Pass("running the newest installed kernel %s", running)
			}),
		checks.New(meta("SYS-008", medium, "system", "No process runs replaced (deleted) system libraries", linux,
			"Restart the listed services (or use `needrestart`) so upgraded libraries are actually loaded."),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				u, err := reach.Scan(env)
				if err != nil {
					return checks.Skip("cannot read /proc: %v", err)
				}
				if len(u.Stale) == 0 {
					if !u.Complete {
						return checks.Skip("only %d processes readable (run as root for full coverage)", u.Processes)
					}
					return checks.Pass("%d processes checked, none use replaced files", u.Processes)
				}
				var items []string // no PIDs: evidence must be stable across restarts for drift tracking
				for _, s := range u.Stale {
					items = append(items, s.Process+": "+path.Base(s.Files[0]))
				}
				items = dedupe(items)
				return checks.Warn("%d processes need a restart: %s", len(u.Stale), sample(items, 10))
			}),
	}
}

// installedKernels lists kernel release strings from /boot and /lib/modules.
func installedKernels(env *sysenv.Env) []string {
	var out []string
	if imgs, _ := env.FS.Glob("/boot/vmlinuz-*"); len(imgs) > 0 {
		for _, i := range imgs {
			out = append(out, strings.TrimPrefix(path.Base(i), "vmlinuz-"))
		}
		return out
	}
	mods, _ := env.FS.ReadDir("/lib/modules")
	for _, m := range mods {
		if _, err := env.FS.Stat("/lib/modules/" + m.Name() + "/modules.dep"); err == nil {
			out = append(out, m.Name())
		}
	}
	return out
}

// VersionCompare orders version-like strings by comparing digit runs
// numerically and everything else lexically ("6.8.0-47" < "6.8.0-100").
func VersionCompare(a, b string) int {
	ta, tb := tokens(a), tokens(b)
	for i := 0; i < len(ta) && i < len(tb); i++ {
		x, y := ta[i], tb[i]
		if isNum(x) && isNum(y) {
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				return len(x) - len(y)
			}
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	return len(ta) - len(tb)
}

func tokens(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		j := i + 1
		for j < len(s) && unicode.IsDigit(rune(s[j])) == unicode.IsDigit(rune(s[i])) {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	return out
}

func isNum(s string) bool { return s != "" && unicode.IsDigit(rune(s[0])) }
