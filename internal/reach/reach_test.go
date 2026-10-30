package reach

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

const maps = `55d0-55d1 r-xp 00000000 08:01 123 /usr/sbin/sshd
7f00-7f01 r-xp 00000000 08:01 456 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7f02-7f03 r-xp 00000000 08:01 789 /usr/lib/x86_64-linux-gnu/libc.so.6
7f04-7f05 rw-p 00000000 00:00 0 [heap]
7f06-7f07 rw-s 00000000 00:01 9 /memfd:pulse (deleted)
7f08-7f09 r--p 00000000 08:01 999 /tmp/my lib.so (deleted)
`

func env() *sysenv.Env {
	m := sysenv.MemFS{
		"proc/100/maps": &fstest.MapFile{Data: []byte(maps)},
		"proc/100/comm": &fstest.MapFile{Data: []byte("sshd\n")},
		"proc/200/maps": &fstest.MapFile{Data: []byte("")}, // kernel thread
		"lib":           &fstest.MapFile{Data: []byte("usr/lib"), Mode: fs.ModeSymlink},
	}
	return &sysenv.Env{GOOS: "linux", FS: m}
}

func TestScanAndStale(t *testing.T) {
	u, err := Scan(env())
	if err != nil {
		t.Fatal(err)
	}
	if u.Processes != 1 || !u.Complete {
		t.Errorf("processes=%d complete=%v", u.Processes, u.Complete)
	}
	if got := u.ByFile["/usr/lib/x86_64-linux-gnu/libc.so.6"]; len(got) != 1 || got[0] != "sshd" {
		t.Errorf("libc users: %v", got)
	}
	if len(u.Stale) != 1 || u.Stale[0].Files[0] != "/usr/lib/x86_64-linux-gnu/libssl.so.3" {
		t.Errorf("only the replaced system lib is stale (not memfd, not /tmp): %+v", u.Stale)
	}
}

func TestCanonicalizerAndAnnotate(t *testing.T) {
	e := env()
	canon := Canonicalizer(e.FS)
	if got := canon("/lib/x86_64-linux-gnu/libc.so.6"); got != "/usr/lib/x86_64-linux-gnu/libc.so.6" {
		t.Errorf("usrmerge canon: %s", got)
	}
	u, _ := Scan(e)
	owners := map[string]string{"/usr/lib/x86_64-linux-gnu/libc.so.6": "libc6"}
	pkgs := []core.Package{{Name: "libc6", SourceName: "glibc"}, {Name: "zlib1g", SourceName: "zlib"}, {Name: "lodash", Path: "/app/package-lock.json"}}
	vulns := []core.Vuln{{ID: "CVE-1", Package: "glibc"}, {ID: "CVE-2", Package: "zlib"}, {ID: "CVE-3", Package: "lodash"}}
	u.Annotate(vulns, pkgs, owners)
	if !vulns[0].Running() || vulns[0].Processes[0] != "sshd" {
		t.Errorf("glibc should be running in sshd: %+v", vulns[0])
	}
	if vulns[1].InUse == nil || *vulns[1].InUse {
		t.Errorf("complete walk: zlib is known not running: %+v", vulns[1])
	}
	if vulns[2].InUse != nil {
		t.Errorf("language deps stay unknown: %+v", vulns[2])
	}
}
