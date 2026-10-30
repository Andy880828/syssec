package checks

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

// Declarative building blocks. Built-in rules and JSON rule packs are both
// expressed with these, so adding a control is usually a one-liner.

func withDefaults(m core.CheckMeta, platforms []string, desc, fix string) core.CheckMeta {
	if len(m.Platforms) == 0 {
		m.Platforms = platforms
	}
	if m.Description == "" {
		m.Description = desc
	}
	if m.Remediation == "" {
		m.Remediation = fix
	}
	return m
}

// Sysctl checks a Linux kernel parameter via /proc/sys.
func Sysctl(m core.CheckMeta, key string, want Expect) Check {
	m = withDefaults(m, []string{"linux"},
		fmt.Sprintf("Kernel parameter %s should be %s.", key, want),
		fmt.Sprintf("Run `sysctl -w %s=%s` and persist it in /etc/sysctl.d/99-syssec.conf.", key, want.Suggest()))
	return New(m, func(_ context.Context, env *sysenv.Env) Outcome {
		p := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
		b, err := env.FS.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			return Skip("%s is not available on this kernel", key)
		}
		if err != nil {
			return Errorf("read %s: %v", p, err)
		}
		v := strings.Join(strings.Fields(string(b)), " ")
		ok, err := want.Match(v)
		switch {
		case err != nil:
			return Errorf("%v", err)
		case ok:
			return Pass("%s = %s", key, v)
		}
		return Fail("%s = %s (expected %s)", key, v, want)
	})
}

// SSHDOption checks an effective sshd_config keyword.
func SSHDOption(m core.CheckMeta, key string, want Expect) Check {
	m = withDefaults(m, []string{"linux", "darwin"},
		fmt.Sprintf("sshd option %s should be %s.", key, want),
		fmt.Sprintf("Set `%s %s` in /etc/ssh/sshd_config (or a drop-in under sshd_config.d) and reload sshd.", key, want.Suggest()))
	return New(m, func(ctx context.Context, env *sysenv.Env) Outcome {
		cfg, err := LoadSSHD(ctx, env)
		if errors.Is(err, ErrNoSSHD) {
			return Skip("OpenSSH server is not installed")
		}
		if err != nil {
			return Errorf("sshd config: %v", err)
		}
		v, isDefault := cfg.Get(key)
		origin := "configured"
		if isDefault {
			origin = "default"
		}
		ok, err := want.Match(v)
		switch {
		case err != nil:
			return Errorf("%v", err)
		case ok:
			return Pass("%s %s (%s, via %s)", key, v, origin, cfg.Source)
		}
		return Fail("%s %s (%s, via %s; expected %s)", key, v, origin, cfg.Source, want)
	})
}

// FileMode verifies a file is root-owned and no more permissive than max.
func FileMode(m core.CheckMeta, path string, max fs.FileMode) Check {
	m = withDefaults(m, []string{"linux", "darwin"},
		fmt.Sprintf("%s should be owned by root with mode %04o or stricter.", path, max),
		fmt.Sprintf("chown root %s && chmod %04o %s", path, max, path))
	return New(m, func(_ context.Context, env *sysenv.Env) Outcome {
		fi, err := env.FS.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return Skip("%s does not exist", path)
		}
		if err != nil {
			return Errorf("stat %s: %v", path, err)
		}
		perm := fi.Mode().Perm()
		if extra := perm &^ max; extra != 0 {
			return Fail("%s mode %04o grants extra bits %04o (max %04o)", path, perm, extra, max)
		}
		if uid, _, ok := sysenv.FileOwner(fi); ok && uid != 0 {
			return Fail("%s is owned by uid %d, expected root", path, uid)
		}
		return Pass("%s mode %04o", path, perm)
	})
}

// FileRegex passes when pattern is present (present=true) or absent in a file.
// missing decides the status when the file does not exist.
func FileRegex(m core.CheckMeta, path, pattern string, present bool, missing core.Status) Check {
	re := regexp.MustCompile(pattern)
	return New(m, func(_ context.Context, env *sysenv.Env) Outcome {
		b, err := env.FS.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return Outcome{Status: missing, Evidence: path + " does not exist"}
		}
		if errors.Is(err, fs.ErrPermission) {
			return Skip("%s is not readable (run as root for full coverage)", path)
		}
		if err != nil {
			return Errorf("read %s: %v", path, err)
		}
		loc := re.Find(b)
		switch {
		case present && loc != nil:
			return Pass("%s contains %q", path, string(loc))
		case present:
			return Fail("%s lacks /%s/", path, pattern)
		case loc != nil:
			return Fail("%s contains %q", path, string(loc))
		}
		return Pass("%s does not match /%s/", path, pattern)
	})
}

// RegistryValue checks a Windows registry value. missing decides the status
// when the value is absent (often the secure OS default).
func RegistryValue(m core.CheckMeta, path, name string, want Expect, missing core.Status) Check {
	m = withDefaults(m, []string{"windows"},
		fmt.Sprintf(`Registry value %s\%s should be %s.`, path, name, want),
		fmt.Sprintf(`Set %s\%s to %s via Group Policy or reg.exe.`, path, name, want.Suggest()))
	return New(m, func(_ context.Context, env *sysenv.Env) Outcome {
		v, err := ReadRegistry(env.Reg, path, name)
		switch {
		case errors.Is(err, sysenv.ErrUnsupported):
			return Skip("registry not available on this platform")
		case errors.Is(err, sysenv.ErrNotExist):
			return Outcome{Status: missing, Evidence: name + " is not set (OS default applies)"}
		case err != nil:
			return Errorf("registry %s\\%s: %v", path, name, err)
		}
		ok, err := want.Match(v)
		switch {
		case err != nil:
			return Errorf("%v", err)
		case ok:
			return Pass("%s = %s", name, v)
		}
		return Fail("%s = %s (expected %s)", name, v, want)
	})
}

// ReadRegistry reads a value as a string, accepting DWORD/QWORD or string types.
func ReadRegistry(reg sysenv.Registry, path, name string) (string, error) {
	if n, err := reg.Integer(path, name); err == nil {
		return fmt.Sprint(n), nil
	} else if errors.Is(err, sysenv.ErrNotExist) || errors.Is(err, sysenv.ErrUnsupported) {
		return "", err
	}
	return reg.String(path, name)
}

// CommandOutput runs an OS-native probe and matches its output. The exit
// status is ignored when output is produced (e.g. `spctl --status` exits 1
// when disabled).
func CommandOutput(m core.CheckMeta, argv []string, pattern string, present bool) Check {
	re := regexp.MustCompile(pattern)
	if m.Description == "" {
		m.Description = fmt.Sprintf("Output of `%s` should %smatch /%s/.", strings.Join(argv, " "), map[bool]string{true: "", false: "not "}[present], pattern)
	}
	return New(m, func(ctx context.Context, env *sysenv.Env) Outcome {
		out, err := env.Exec.Run(ctx, argv[0], argv[1:]...)
		if errors.Is(err, sysenv.ErrCommandNotFound) {
			return Skip("%s not available", argv[0])
		}
		text := strings.TrimSpace(string(out))
		if err != nil && text == "" {
			return Errorf("%s: %v", argv[0], err)
		}
		first := text
		if i := strings.IndexByte(first, '\n'); i >= 0 {
			first = first[:i]
		}
		if re.MatchString(text) == present {
			return Pass("%s", first)
		}
		return Fail("%s", first)
	})
}
