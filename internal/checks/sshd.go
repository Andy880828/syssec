package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/Andy880828/syssec/internal/sysenv"
)

// ErrNoSSHD means the OpenSSH server is not installed.
var ErrNoSSHD = errors.New("OpenSSH server configuration not found")

// SSHDConfig is the effective global sshd configuration.
type SSHDConfig struct {
	Values map[string]string // lower-case keyword -> first value
	Source string            // "sshd -T" or "parsed"
}

// sshdDefaults mirrors upstream OpenSSH (9.x) defaults for keys we audit.
var sshdDefaults = map[string]string{
	"permitrootlogin":         "prohibit-password",
	"passwordauthentication":  "yes",
	"permitemptypasswords":    "no",
	"x11forwarding":           "no",
	"maxauthtries":            "6",
	"pubkeyauthentication":    "yes",
	"hostbasedauthentication": "no",
	"ignorerhosts":            "yes",
	"permituserenvironment":   "no",
	"logingracetime":          "120",
	"allowtcpforwarding":      "yes",
	"allowagentforwarding":    "yes",
	"clientaliveinterval":     "0",
	"loglevel":                "INFO",
}

// Get returns the effective value and whether it came from the defaults.
func (c *SSHDConfig) Get(key string) (value string, isDefault bool) {
	key = strings.ToLower(key)
	if v, ok := c.Values[key]; ok {
		return v, false
	}
	return sshdDefaults[key], true
}

// LoadSSHD returns the effective config. When privileged it asks the daemon
// itself (`sshd -T`, authoritative incl. Match/Include semantics); otherwise
// it parses /etc/ssh/sshd_config with first-match-wins and Include support.
func LoadSSHD(ctx context.Context, env *sysenv.Env) (*SSHDConfig, error) {
	return Cached(env, "sshd", func() (*SSHDConfig, error) {
		const main = "/etc/ssh/sshd_config"
		if _, err := env.FS.Stat(main); errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNoSSHD
		}
		if env.Host.Privileged {
			if out, err := env.Exec.Run(ctx, "sshd", "-T"); err == nil && bytes.Contains(out, []byte("permitrootlogin")) {
				cfg := &SSHDConfig{Values: map[string]string{}, Source: "sshd -T"}
				parseSSHDLines(out, func(k, v string) bool { cfg.Values[k] = v; return true })
				return cfg, nil
			}
		}
		cfg := &SSHDConfig{Values: map[string]string{}, Source: "parsed"}
		err := parseSSHDFile(env.FS, main, cfg.Values, 0)
		return cfg, err
	})
}

func parseSSHDFile(fsys sysenv.FS, file string, into map[string]string, depth int) error {
	if depth > 8 {
		return errors.New("sshd_config: Include nesting too deep")
	}
	data, err := fsys.ReadFile(file)
	if err != nil {
		if depth > 0 && errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	var incErr error
	parseSSHDLines(data, func(k, v string) bool {
		switch k {
		case "match":
			return false // global section ends at the first Match block
		case "include":
			for _, pat := range strings.Fields(v) {
				if !path.IsAbs(pat) {
					pat = path.Join("/etc/ssh", pat)
				}
				files, _ := fsys.Glob(pat)
				slices.Sort(files)
				for _, f := range files {
					if err := parseSSHDFile(fsys, f, into, depth+1); err != nil && incErr == nil {
						incErr = err
					}
				}
			}
		default:
			if _, seen := into[k]; !seen {
				into[k] = v
			}
		}
		return true
	})
	return incErr
}

// parseSSHDLines yields keyword/value pairs until fn returns false.
func parseSSHDLines(data []byte, fn func(key, value string) bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		i := strings.IndexAny(line, " \t=")
		if i < 0 {
			continue
		}
		key := strings.ToLower(line[:i])
		val := strings.Trim(strings.TrimLeft(line[i:], " \t="), `"`)
		if !fn(key, val) {
			return
		}
	}
}
