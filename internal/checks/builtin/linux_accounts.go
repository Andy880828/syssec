package builtin

import (
	"context"
	"strings"

	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/sysenv"
)

type passwdEntry struct {
	Name, UID, GID, Home, Shell string
}

func readPasswd(env *sysenv.Env) ([]passwdEntry, error) {
	return checks.Cached(env, "passwd", func() ([]passwdEntry, error) {
		b, err := env.FS.ReadFile("/etc/passwd")
		if err != nil {
			return nil, err
		}
		var out []passwdEntry
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(line, ":")
			if len(f) < 7 || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "+") {
				continue
			}
			out = append(out, passwdEntry{f[0], f[2], f[3], f[5], f[6]})
		}
		return out, nil
	})
}

var nonLoginShells = []string{"nologin", "false", "sync", "shutdown", "halt", "true"}

func interactive(shell string) bool {
	for _, s := range nonLoginShells {
		if strings.HasSuffix(shell, "/"+s) {
			return false
		}
	}
	return shell != ""
}

func accountChecks() []checks.Check {
	return []checks.Check{
		checks.New(meta("ACC-001", critical, "accounts", "Only root has UID 0", linux,
			"Remove or re-number the extra UID 0 account; it is a classic backdoor."),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				users, err := readPasswd(env)
				if err != nil {
					return readable(err)
				}
				var extra []string
				for _, u := range users {
					if u.UID == "0" && u.Name != "root" {
						extra = append(extra, u.Name)
					}
				}
				if len(extra) > 0 {
					return checks.Fail("UID 0 accounts besides root: %s", strings.Join(extra, ", "))
				}
				return checks.Pass("root is the only UID 0 account")
			}),
		checks.New(meta("ACC-002", critical, "accounts", "No accounts have an empty password", linux,
			"Lock the account (`passwd -l <user>`) or set a strong password."),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				b, err := env.FS.ReadFile("/etc/shadow")
				if err != nil {
					return readable(err)
				}
				var empty []string
				for _, line := range strings.Split(string(b), "\n") {
					f := strings.Split(line, ":")
					if len(f) > 1 && f[1] == "" {
						empty = append(empty, f[0])
					}
				}
				if len(empty) > 0 {
					return checks.Fail("accounts with empty password: %s", strings.Join(empty, ", "))
				}
				return checks.Pass("all shadow entries have a password hash or lock marker")
			}),
		checks.New(meta("ACC-003", medium, "accounts", "UIDs are unique", linux,
			"Assign unique UIDs; shared UIDs break accountability and file ownership."),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				users, err := readPasswd(env)
				if err != nil {
					return readable(err)
				}
				seen := map[string]string{}
				var dups []string
				for _, u := range users {
					if prev, ok := seen[u.UID]; ok {
						dups = append(dups, prev+"="+u.Name+"("+u.UID+")")
					}
					seen[u.UID] = u.Name
				}
				if len(dups) > 0 {
					return checks.Fail("duplicate UIDs: %s", strings.Join(dups, ", "))
				}
				return checks.Pass("%d accounts, all UIDs unique", len(users))
			}),
		checks.New(meta("ACC-004", low, "accounts", "System accounts have no interactive shell", linux,
			"`usermod -s /usr/sbin/nologin <user>` for service accounts."),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				users, err := readPasswd(env)
				if err != nil {
					return readable(err)
				}
				var bad []string
				for _, u := range users {
					if u.Name == "root" || len(u.UID) > 3 || !interactive(u.Shell) {
						continue // UIDs >= 1000 are human users
					}
					bad = append(bad, u.Name+"("+u.Shell+")")
				}
				if len(bad) > 0 {
					return checks.Warn("system accounts with login shells: %s", sample(bad, 10))
				}
				return checks.Pass("no system account has an interactive shell")
			}),
		checks.New(meta("ACC-005", low, "accounts", "sudo rules require a password", unix,
			"Remove NOPASSWD from sudoers unless it is scoped to a specific, audited command."),
			func(_ context.Context, env *sysenv.Env) checks.Outcome {
				files := []string{"/etc/sudoers"}
				more, _ := env.FS.Glob("/etc/sudoers.d/*")
				files = append(files, more...)
				var hits []string
				readAny := false
				for _, f := range files {
					b, err := env.FS.ReadFile(f)
					if err != nil {
						continue
					}
					readAny = true
					for _, line := range strings.Split(string(b), "\n") {
						line = strings.TrimSpace(line)
						if !strings.HasPrefix(line, "#") && strings.Contains(line, "NOPASSWD") {
							hits = append(hits, f+": "+line)
						}
					}
				}
				if !readAny {
					return checks.Skip("sudoers not readable (run as root for full coverage)")
				}
				if len(hits) > 0 {
					return checks.Warn("%s", sample(hits, 5))
				}
				return checks.Pass("no NOPASSWD rules")
			}),
	}
}
