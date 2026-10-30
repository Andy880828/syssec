// Package config resolves settings from SYSSEC_* environment variables.
// syssec deliberately has no config file: everything it persists lives in
// one directory (SYSSEC_HOME) as the database, rules/ and waivers.json.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Config is the effective configuration.
type Config struct {
	Home        string        `json:"home"`
	DBPath      string        `json:"db_path"`
	RulesDirs   []string      `json:"rules_dirs"`
	WaiversPath string        `json:"waivers_path"`
	OSVURL      string        `json:"osv_url,omitempty"`
	KEVURL      string        `json:"kev_url,omitempty"`
	EPSSURL     string        `json:"epss_url,omitempty"`
	HTTPTimeout time.Duration `json:"-"`
	IntelTTL    time.Duration `json:"-"` // reuse OSV answers for unchanged package versions
}

// Load builds the configuration from the environment.
func Load() Config {
	home := os.Getenv("SYSSEC_HOME")
	if home == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			base = "."
		}
		home = filepath.Join(base, "syssec")
	}
	c := Config{
		Home:        home,
		DBPath:      env("SYSSEC_DB", filepath.Join(home, "syssec.db")),
		RulesDirs:   append([]string{filepath.Join(home, "rules")}, filepath.SplitList(os.Getenv("SYSSEC_RULES_DIR"))...),
		WaiversPath: filepath.Join(home, "waivers.json"),
		OSVURL:      os.Getenv("SYSSEC_OSV_URL"),
		KEVURL:      os.Getenv("SYSSEC_KEV_URL"),
		EPSSURL:     os.Getenv("SYSSEC_EPSS_URL"),
		HTTPTimeout: time.Duration(envInt("SYSSEC_HTTP_TIMEOUT", 30)) * time.Second,
		IntelTTL:    time.Duration(envInt("SYSSEC_INTEL_TTL_HOURS", 6)) * time.Hour,
	}
	return c
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v >= 0 {
		return v
	}
	return def
}
