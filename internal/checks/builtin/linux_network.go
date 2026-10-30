package builtin

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/sysenv"
)

// Listener is a socket accepting connections.
type Listener struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
	inode   string
}

func (l Listener) Exposed() bool {
	ip := net.ParseIP(l.Addr)
	return ip != nil && ip.IsUnspecified()
}

func (l Listener) String() string {
	s := fmt.Sprintf("%s/%d", l.Proto, l.Port)
	if l.Process != "" {
		s += "(" + l.Process + ")"
	}
	return s
}

// riskyPorts are services that should never face untrusted networks.
var riskyPorts = map[int]string{
	21: "ftp", 23: "telnet", 69: "tftp", 111: "rpcbind", 135: "msrpc", 139: "netbios",
	445: "smb", 512: "rexec", 513: "rlogin", 514: "rsh", 873: "rsync", 2049: "nfs",
	2375: "docker-api", 2379: "etcd", 3306: "mysql", 5432: "postgres", 5900: "vnc",
	5984: "couchdb", 6379: "redis", 9200: "elasticsearch", 10250: "kubelet",
	11211: "memcached", 27017: "mongodb",
}

// ReadListeners parses /proc/net/{tcp,tcp6,udp,udp6} and best-effort maps
// sockets to process names via /proc/<pid>/fd.
func ReadListeners(env *sysenv.Env) ([]Listener, error) {
	return checks.Cached(env, "listeners", func() ([]Listener, error) {
		var out []Listener
		var lastErr error
		for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
			b, err := env.FS.ReadFile("/proc/net/" + proto)
			if err != nil {
				lastErr = err
				continue
			}
			out = append(out, parseProcNet(b, proto)...)
		}
		if len(out) == 0 && lastErr != nil {
			return nil, lastErr
		}
		owners := socketOwners(env)
		for i := range out {
			out[i].Process = owners[out[i].inode]
		}
		slices.SortFunc(out, func(a, b Listener) int { return a.Port - b.Port })
		return out, nil
	})
}

func parseProcNet(b []byte, proto string) []Listener {
	var out []Listener
	isTCP := strings.HasPrefix(proto, "tcp")
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 10 {
			continue
		}
		if isTCP && f[3] != "0A" { // TCP_LISTEN
			continue
		}
		if !isTCP && !strings.HasSuffix(f[2], ":0000") {
			continue // connected UDP socket
		}
		hexIP, hexPort, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if err != nil {
			continue
		}
		ip := decodeProcIP(hexIP)
		if ip == nil {
			continue
		}
		out = append(out, Listener{Proto: strings.TrimSuffix(proto, "6"), Addr: ip.String(), Port: int(port), inode: f[9]})
	}
	return out
}

// decodeProcIP decodes the kernel's per-32-bit-word little-endian hex form.
func decodeProcIP(s string) net.IP {
	raw, err := hex.DecodeString(s)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil
	}
	for w := 0; w < len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	return net.IP(raw)
}

func socketOwners(env *sysenv.Env) map[string]string {
	owners := map[string]string{}
	procs, err := env.FS.ReadDir("/proc")
	if err != nil {
		return owners
	}
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		dir := path.Join("/proc", p.Name())
		fds, err := env.FS.ReadDir(dir + "/fd")
		if err != nil {
			continue // other users' processes need root
		}
		var comm string
		for _, fd := range fds {
			target, err := env.FS.Readlink(dir + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			if comm == "" {
				b, _ := env.FS.ReadFile(dir + "/comm")
				comm = strings.TrimSpace(string(b))
			}
			owners[strings.Trim(target[7:], "[]")] = comm
		}
	}
	return owners
}

func networkChecks() []checks.Check {
	risky := meta("NET-001", high, "network", "No high-risk services listen on all interfaces", linux,
		"Bind the service to 127.0.0.1 or a private interface, or firewall the port. Docker API (2375) and kubelet must never be exposed.")
	risky.Description = "Databases, caches, file-sharing and legacy remote-shell services exposed on 0.0.0.0/:: are a top initial-access vector."
	exposure := meta("NET-002", info, "network", "Inventory of services listening on all interfaces", linux,
		"Review each exposed service; close what is not needed.")
	return []checks.Check{
		checks.New(risky, func(_ context.Context, env *sysenv.Env) checks.Outcome {
			ls, err := ReadListeners(env)
			if err != nil {
				return checks.Skip("cannot read /proc/net: %v", err)
			}
			var bad []string
			for _, l := range ls {
				if name, ok := riskyPorts[l.Port]; ok && l.Exposed() {
					bad = append(bad, name+"="+l.String())
				}
			}
			if len(bad) > 0 {
				return checks.Fail("exposed: %s", strings.Join(dedupe(bad), ", "))
			}
			return checks.Pass("no high-risk service exposed among %d listeners", len(ls))
		}),
		checks.New(exposure, func(_ context.Context, env *sysenv.Env) checks.Outcome {
			ls, err := ReadListeners(env)
			if err != nil {
				return checks.Skip("cannot read /proc/net: %v", err)
			}
			var exposed []string
			for _, l := range ls {
				if l.Exposed() {
					exposed = append(exposed, l.String())
				}
			}
			exposed = dedupe(exposed)
			if len(exposed) > 0 {
				return checks.Warn("%d exposed: %s", len(exposed), sample(exposed, 15))
			}
			return checks.Pass("no services listen on all interfaces")
		}),
	}
}

func dedupe(in []string) []string {
	slices.Sort(in)
	return slices.Compact(in)
}
