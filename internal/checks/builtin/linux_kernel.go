package builtin

import "github.com/Andy880828/syssec/internal/checks"

func kernelChecks() []checks.Check {
	k := func(id string, sev severity, title, key string, want checks.Expect) checks.Check {
		return checks.Sysctl(host(meta(id, sev, "kernel", title, linux, "")), key, want)
	}
	return []checks.Check{
		k("KRN-001", high, "ASLR is fully enabled", "kernel.randomize_va_space", checks.Eq("2")),
		k("KRN-002", medium, "Kernel pointers are hidden from unprivileged users", "kernel.kptr_restrict", checks.GE(1)),
		k("KRN-003", low, "dmesg is restricted to privileged users", "kernel.dmesg_restrict", checks.Eq("1")),
		k("KRN-004", medium, "ptrace is restricted (Yama)", "kernel.yama.ptrace_scope", checks.GE(1)),
		k("KRN-005", medium, "SUID core dumps are disabled", "fs.suid_dumpable", checks.Eq("0")),
		k("KRN-006", medium, "Symlink protection is enabled", "fs.protected_symlinks", checks.Eq("1")),
		k("KRN-007", medium, "Hardlink protection is enabled", "fs.protected_hardlinks", checks.Eq("1")),
		k("KRN-008", medium, "Unprivileged eBPF is disabled", "kernel.unprivileged_bpf_disabled", checks.GE(1)),
		k("KRN-009", low, "FIFO/regular file protection in sticky dirs", "fs.protected_fifos", checks.GE(1)),
		k("KRN-010", low, "SysRq key is restricted", "kernel.sysrq", checks.In("0", "176", "16")),
	}
}

func networkSysctlChecks() []checks.Check {
	n := func(id string, sev severity, title, key string, want checks.Expect) checks.Check {
		return checks.Sysctl(meta(id, sev, "network", title, linux, ""), key, want)
	}
	ipFwd := checks.Sysctl(meta("NET-101", medium, "network", "IPv4 forwarding is disabled", linux,
		"Disable with `sysctl -w net.ipv4.ip_forward=0` unless this host is a router or container host (Docker/Kubernetes need forwarding; accept this finding there)."),
		"net.ipv4.ip_forward", checks.Eq("0"))
	return []checks.Check{
		ipFwd,
		n("NET-102", medium, "ICMP redirects are not accepted (IPv4)", "net.ipv4.conf.all.accept_redirects", checks.Eq("0")),
		n("NET-103", medium, "ICMP redirects are not accepted (IPv6)", "net.ipv6.conf.all.accept_redirects", checks.Eq("0")),
		n("NET-104", medium, "ICMP redirects are not sent", "net.ipv4.conf.all.send_redirects", checks.Eq("0")),
		n("NET-105", medium, "Source-routed packets are rejected", "net.ipv4.conf.all.accept_source_route", checks.Eq("0")),
		n("NET-106", medium, "TCP SYN cookies are enabled", "net.ipv4.tcp_syncookies", checks.Eq("1")),
		n("NET-107", low, "Reverse path filtering is enabled", "net.ipv4.conf.all.rp_filter", checks.In("1", "2")),
		n("NET-108", low, "Broadcast ICMP echo is ignored", "net.ipv4.icmp_echo_ignore_broadcasts", checks.Eq("1")),
		n("NET-109", low, "Martian packets are logged", "net.ipv4.conf.all.log_martians", checks.Eq("1")),
	}
}
