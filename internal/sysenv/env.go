package sysenv

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Andy880828/syssec/internal/core"
)

// Env bundles every host probe a check or collector may use.
type Env struct {
	GOOS      string
	FS        FS
	Exec      Runner
	Reg       Registry
	Host      core.Host
	OSRelease map[string]string // /etc/os-release on Linux

	memoMu sync.Mutex
	memo   map[string]*memoEntry
}

type memoEntry struct {
	once sync.Once
	val  any
	err  error
}

// Memo computes fn once per key for the lifetime of the Env, letting
// several checks share an expensive probe (sshd -T, /proc walks, ...).
func (e *Env) Memo(key string, fn func() (any, error)) (any, error) {
	e.memoMu.Lock()
	if e.memo == nil {
		e.memo = map[string]*memoEntry{}
	}
	ent, ok := e.memo[key]
	if !ok {
		ent = &memoEntry{}
		e.memo[key] = ent
	}
	e.memoMu.Unlock()
	ent.once.Do(func() { ent.val, ent.err = fn() })
	return ent.val, ent.err
}

// Detect builds an Env for the running host.
func Detect(ctx context.Context) *Env {
	e := &Env{
		GOOS: runtime.GOOS,
		FS:   OSFS{},
		Exec: ExecRunner{Timeout: 15 * time.Second},
		Reg:  NewRegistry(),
	}
	e.Host = core.Host{OS: e.GOOS, Arch: runtime.GOARCH, Privileged: isPrivileged()}
	e.Host.Hostname, _ = os.Hostname()
	e.Host.Container = DetectContainer(e.FS)
	switch e.GOOS {
	case "linux":
		if b, err := e.FS.ReadFile("/etc/os-release"); err == nil {
			e.OSRelease = ParseOSRelease(b)
		} else if b, err := e.FS.ReadFile("/usr/lib/os-release"); err == nil {
			e.OSRelease = ParseOSRelease(b)
		}
		e.Host.Distro = e.OSRelease["ID"]
		e.Host.Version = e.OSRelease["VERSION_ID"]
		e.Host.Pretty = e.OSRelease["PRETTY_NAME"]
		if b, err := e.FS.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			e.Host.Kernel = strings.TrimSpace(string(b))
		}
	case "darwin":
		e.Host.Distro = "macos"
		if out, err := e.Exec.Run(ctx, "sw_vers", "-productVersion"); err == nil {
			e.Host.Version = strings.TrimSpace(string(out))
			e.Host.Pretty = "macOS " + e.Host.Version
		}
		if out, err := e.Exec.Run(ctx, "uname", "-r"); err == nil {
			e.Host.Kernel = strings.TrimSpace(string(out))
		}
	case "windows":
		const cv = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
		e.Host.Distro = "windows"
		e.Host.Pretty, _ = e.Reg.String(cv, "ProductName")
		e.Host.Version, _ = e.Reg.String(cv, "DisplayVersion")
		e.Host.Kernel, _ = e.Reg.String(cv, "CurrentBuild")
	}
	return e
}

// DetectContainer identifies the container runtime we run inside, if any.
func DetectContainer(fsys FS) string {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "kubernetes"
	}
	if _, err := fsys.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	if _, err := fsys.Stat("/run/.containerenv"); err == nil {
		return "podman"
	}
	if b, err := fsys.ReadFile("/proc/1/environ"); err == nil && bytes.Contains(b, []byte("container=")) {
		for _, kv := range bytes.Split(b, []byte{0}) {
			if v, ok := bytes.CutPrefix(kv, []byte("container=")); ok {
				return string(v)
			}
		}
	}
	if b, err := fsys.ReadFile("/proc/1/cgroup"); err == nil {
		for _, m := range []struct{ marker, name string }{
			{"kubepods", "kubernetes"}, {"docker", "docker"}, {"lxc", "lxc"}, {"containerd", "container"},
		} {
			if bytes.Contains(b, []byte(m.marker)) {
				return m.name
			}
		}
	}
	return ""
}

// ParseOSRelease parses the freedesktop os-release format.
func ParseOSRelease(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}
