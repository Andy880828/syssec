package builtin

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

func filesystemChecks() []checks.Check {
	fm := func(id string, sev severity, path string, mode fs.FileMode, plats []string) checks.Check {
		return checks.FileMode(meta(id, sev, "filesystem", fmt.Sprintf("%s permissions are restrictive", path), plats, ""), path, mode)
	}
	return []checks.Check{
		fm("FS-001", high, "/etc/passwd", 0o644, unix),
		fm("FS-002", critical, "/etc/shadow", 0o640, linux),
		fm("FS-003", high, "/etc/gshadow", 0o640, linux),
		fm("FS-004", medium, "/etc/group", 0o644, unix),
		fm("FS-005", medium, "/etc/ssh/sshd_config", 0o600, unix),
		fm("FS-006", high, "/etc/sudoers", 0o440, unix),
		fm("FS-007", low, "/etc/crontab", 0o600, linux),
		mountOptions(host(meta("FS-010", low, "filesystem", "/tmp is mounted nodev,nosuid", linux,
			"Mount /tmp as a separate tmpfs with `nodev,nosuid,noexec` (systemd: `systemctl enable tmp.mount`).")),
			"/tmp", "nodev", "nosuid"),
		mountOptions(host(meta("FS-011", medium, "filesystem", "/dev/shm is mounted nodev,nosuid,noexec", linux,
			"Add `tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0` to /etc/fstab and remount.")),
			"/dev/shm", "nodev", "nosuid", "noexec"),
		worldWritable(),
		suidInTempDirs(),
	}
}

type mount struct {
	Device, Point, Type string
	Opts                []string
}

func readMounts(env *sysenv.Env) ([]mount, error) {
	return checks.Cached(env, "mounts", func() ([]mount, error) {
		b, err := env.FS.ReadFile("/proc/mounts")
		if err != nil {
			return nil, err
		}
		var out []mount
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 {
				out = append(out, mount{f[0], f[1], f[2], strings.Split(f[3], ",")})
			}
		}
		return out, nil
	})
}

func mountOptions(m core.CheckMeta, point string, required ...string) checks.Check {
	return checks.New(m, func(_ context.Context, env *sysenv.Env) checks.Outcome {
		ms, err := readMounts(env)
		if err != nil {
			return checks.Skip("cannot read /proc/mounts: %v", err)
		}
		var found *mount
		for i := range ms { // last mount on a point wins
			if ms[i].Point == point {
				found = &ms[i]
			}
		}
		if found == nil {
			return checks.Warn("%s is not a separate mount", point)
		}
		var missing []string
		for _, o := range required {
			if !slices.Contains(found.Opts, o) {
				missing = append(missing, o)
			}
		}
		if len(missing) > 0 {
			return checks.Fail("%s (%s) missing options: %s", point, found.Type, strings.Join(missing, ","))
		}
		return checks.Pass("%s mounted with %s", point, strings.Join(required, ","))
	})
}

var systemDirs = []string{"/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/lib/systemd/system", "/etc/systemd/system"}

func worldWritable() checks.Check {
	m := meta("FS-020", high, "filesystem", "No world-writable files in system directories", unix,
		"Remove the world-writable bit: `chmod o-w <path>`; investigate how it was introduced.")
	m.Description = "World-writable binaries or configs under system paths let any local user escalate privileges."
	return checks.New(m, func(ctx context.Context, env *sysenv.Env) checks.Outcome {
		var hits []string
		visited := 0
		for _, root := range systemDirs {
			_ = env.FS.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil || ctx.Err() != nil {
					if d != nil && d.IsDir() && err != nil {
						return fs.SkipDir
					}
					return ctx.Err()
				}
				if visited++; visited > 200_000 {
					return fs.SkipAll
				}
				if d.Type()&fs.ModeSymlink != 0 {
					return nil
				}
				fi, err := d.Info()
				if err != nil {
					return nil
				}
				mode := fi.Mode()
				if mode.Perm()&0o002 != 0 && !(mode.IsDir() && mode&fs.ModeSticky != 0) {
					hits = append(hits, p)
				}
				return nil
			})
		}
		if len(hits) > 0 {
			return checks.Fail("%d world-writable: %s", len(hits), sample(hits, 10))
		}
		return checks.Pass("scanned %d entries, none world-writable", visited)
	})
}

func suidInTempDirs() checks.Check {
	m := meta("FS-021", critical, "filesystem", "No SUID/SGID binaries in temporary or user directories", unix,
		"Delete or `chmod u-s,g-s` the binary and investigate it as a likely persistence/backdoor artifact.")
	return checks.New(m, func(ctx context.Context, env *sysenv.Env) checks.Outcome {
		var hits []string
		for _, root := range []string{"/tmp", "/var/tmp", "/dev/shm", "/home", "/Users"} {
			_ = env.FS.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					if d != nil && d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if strings.Count(p, "/") > 8 && d.IsDir() {
					return fs.SkipDir
				}
				if !d.Type().IsRegular() {
					return nil
				}
				if fi, err := d.Info(); err == nil && fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
					hits = append(hits, p)
				}
				return nil
			})
		}
		if len(hits) > 0 {
			return checks.Fail("SUID/SGID files: %s", sample(hits, 10))
		}
		return checks.Pass("no SUID/SGID files in temp or home directories")
	})
}

func sample(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" (+%d more)", len(items)-n)
}

func readable(err error) checks.Outcome {
	if errors.Is(err, fs.ErrPermission) {
		return checks.Skip("permission denied (run as root for full coverage)")
	}
	if errors.Is(err, fs.ErrNotExist) {
		return checks.Skip("not present on this system")
	}
	return checks.Errorf("%v", err)
}
