package builtin

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/sysenv"
)

func linuxSystemChecks() []checks.Check {
	return []checks.Check{
		checks.New(host(meta("SYS-001", high, "system", "A mandatory access control LSM is active", linux,
			"Enable AppArmor (Debian/Ubuntu/SUSE) or SELinux in enforcing mode (RHEL family).")),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				lsm, _ := env.FS.ReadFile("/sys/kernel/security/lsm")
				active := string(lsm)
				if enf, err := env.FS.ReadFile("/sys/fs/selinux/enforce"); err == nil {
					if strings.TrimSpace(string(enf)) == "1" {
						return checks.Pass("SELinux enforcing")
					}
					return checks.Fail("SELinux present but permissive")
				}
				if b, err := env.FS.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil && strings.TrimSpace(string(b)) == "Y" {
					return checks.Pass("AppArmor enabled (lsm: %s)", strings.TrimSpace(active))
				}
				for _, l := range []string{"selinux", "apparmor", "smack", "tomoyo"} {
					if strings.Contains(active, l) {
						return checks.Pass("LSM active: %s", strings.TrimSpace(active))
					}
				}
				if active == "" {
					return checks.Warn("could not determine LSM state (securityfs not mounted or not readable)")
				}
				return checks.Fail("no MAC LSM active (lsm: %s)", strings.TrimSpace(active))
			}),
		checks.New(host(meta("SYS-002", medium, "system", "UEFI Secure Boot is enabled", linux,
			"Enable Secure Boot in firmware settings to block unsigned bootloaders and kernel rootkits.")),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				if _, err := env.FS.Stat("/sys/firmware/efi"); err != nil {
					return checks.Skip("not booted via UEFI (or container)")
				}
				vars, _ := env.FS.Glob("/sys/firmware/efi/efivars/SecureBoot-*")
				if len(vars) == 0 {
					return checks.Skip("SecureBoot variable not present")
				}
				b, err := env.FS.ReadFile(vars[0])
				if err != nil || len(b) < 5 {
					return checks.Skip("SecureBoot variable unreadable")
				}
				if b[4] == 1 { // 4-byte attribute header, then the value
					return checks.Pass("Secure Boot enabled")
				}
				return checks.Fail("Secure Boot disabled")
			}),
		checks.New(host(meta("SYS-003", medium, "system", "No reboot is pending for security updates", linux,
			"Reboot to load the patched kernel and libraries.")),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				if _, err := env.FS.Stat("/var/run/reboot-required"); err == nil {
					pkgs, _ := env.FS.ReadFile("/var/run/reboot-required.pkgs")
					return checks.Warn("reboot required; packages: %s", strings.Join(strings.Fields(string(pkgs)), ", "))
				}
				return checks.Pass("no reboot-required marker")
			}),
		checks.New(meta("SYS-004", medium, "system", "Automatic security updates are configured", linux,
			"Debian/Ubuntu: `apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades`. RHEL/Fedora: `dnf install dnf-automatic && systemctl enable --now dnf-automatic.timer`."),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				if confs, _ := env.FS.Glob("/etc/apt/apt.conf.d/*"); len(confs) > 0 {
					for _, c := range confs {
						b, _ := env.FS.ReadFile(c)
						if strings.Contains(string(b), `Unattended-Upgrade "1"`) {
							return checks.Pass("unattended-upgrades enabled (%s)", c)
						}
					}
					return checks.Fail("apt present but unattended-upgrades not enabled")
				}
				for _, pat := range []string{"/etc/systemd/system/timers.target.wants/dnf-automatic*", "/etc/systemd/system/timers.target.wants/yum-cron*", "/etc/systemd/system/multi-user.target.wants/yum-cron*"} {
					if m, _ := env.FS.Glob(pat); len(m) > 0 {
						return checks.Pass("automatic updates timer enabled (%s)", m[0])
					}
				}
				if _, err := env.FS.Stat("/etc/dnf"); err == nil {
					return checks.Fail("dnf present but dnf-automatic timer not enabled")
				}
				return checks.Skip("package manager auto-update mechanism not recognised")
			}),
		checks.New(host(meta("SYS-005", medium, "system", "A host firewall is active", linux,
			"Enable a default-deny inbound policy with ufw, firewalld or nftables.")),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				if b, err := env.FS.ReadFile("/etc/ufw/ufw.conf"); err == nil && strings.Contains(string(b), "ENABLED=yes") {
					return checks.Pass("ufw enabled")
				}
				if procRunning(env, "firewalld") {
					return checks.Pass("firewalld running")
				}
				for _, p := range []string{"sysinit.target.wants", "multi-user.target.wants"} {
					if _, err := env.FS.Stat("/etc/systemd/system/" + p + "/nftables.service"); err == nil {
						return checks.Pass("nftables service enabled")
					}
				}
				if b, err := env.FS.ReadFile("/proc/net/ip_tables_names"); err == nil && len(strings.TrimSpace(string(b))) > 0 {
					return checks.Warn("iptables tables loaded (%s) but no managed firewall detected; verify the ruleset", strings.Join(strings.Fields(string(b)), ","))
				}
				return checks.Warn("no ufw, firewalld or nftables service detected")
			}),
		checks.New(meta("SYS-006", critical, "system", "Container runtime sockets are not world-accessible", linux,
			"`chmod 660 /var/run/docker.sock` and limit the docker group: socket access equals root."),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				var bad, seen []string
				for _, s := range []string{"/var/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock"} {
					fi, err := env.FS.Stat(s)
					if errors.Is(err, fs.ErrNotExist) || err != nil {
						continue
					}
					seen = append(seen, s)
					if fi.Mode().Perm()&0o006 != 0 {
						bad = append(bad, s)
					}
				}
				switch {
				case len(bad) > 0:
					return checks.Fail("world-accessible: %s", strings.Join(bad, ", "))
				case len(seen) == 0:
					return checks.Skip("no container runtime sockets found")
				}
				return checks.Pass("restricted: %s", strings.Join(seen, ", "))
			}),
	}
}

func procRunning(env *sysenv.Env, name string) bool {
	comms, _ := env.FS.Glob("/proc/[0-9]*/comm")
	for _, c := range comms {
		if b, err := env.FS.ReadFile(c); err == nil && strings.TrimSpace(string(b)) == name {
			return true
		}
	}
	return false
}
