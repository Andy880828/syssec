package inventory

import (
	"context"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

var uninstallKeys = []string{
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
}

type winUninstall struct{}

func (winUninstall) Name() string                    { return "windows-uninstall" }
func (winUninstall) Applicable(env *sysenv.Env) bool { return env.GOOS == "windows" }

func (winUninstall) Collect(_ context.Context, env *sysenv.Env) ([]core.Package, error) {
	var out []core.Package
	for _, root := range uninstallKeys {
		subs, err := env.Reg.SubKeys(root)
		if err != nil {
			continue
		}
		for _, s := range subs {
			key := root + `\` + s
			name, err := env.Reg.String(key, "DisplayName")
			if err != nil || name == "" {
				continue
			}
			if sc, err := env.Reg.Integer(key, "SystemComponent"); err == nil && sc == 1 {
				continue
			}
			ver, _ := env.Reg.String(key, "DisplayVersion")
			out = append(out, core.Package{Name: name, Version: ver, Manager: "windows"})
		}
	}
	return out, nil
}
