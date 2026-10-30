package builtin

import "github.com/Andy880828/syssec/internal/checks"

const cisSSH = "https://www.cisecurity.org/benchmark/distribution_independent_linux"

func sshChecks() []checks.Check {
	return []checks.Check{
		checks.SSHDOption(meta("SSH-001", high, "ssh", "SSH root login is disabled", unix,
			"Set `PermitRootLogin no` and use sudo from an unprivileged account.", cisSSH),
			"PermitRootLogin", checks.In("no")),
		checks.SSHDOption(meta("SSH-002", medium, "ssh", "SSH password authentication is disabled", unix,
			"Set `PasswordAuthentication no` after deploying SSH keys.", cisSSH),
			"PasswordAuthentication", checks.Eq("no")),
		checks.SSHDOption(meta("SSH-003", critical, "ssh", "SSH empty passwords are rejected", unix, ""),
			"PermitEmptyPasswords", checks.Eq("no")),
		checks.SSHDOption(meta("SSH-004", low, "ssh", "SSH X11 forwarding is disabled", unix, ""),
			"X11Forwarding", checks.Eq("no")),
		checks.SSHDOption(meta("SSH-005", low, "ssh", "SSH MaxAuthTries is 4 or less", unix, ""),
			"MaxAuthTries", checks.LE(4)),
		checks.SSHDOption(meta("SSH-006", medium, "ssh", "SSH host-based authentication is disabled", unix, ""),
			"HostbasedAuthentication", checks.Eq("no")),
		checks.SSHDOption(meta("SSH-007", medium, "ssh", "SSH user environment processing is disabled", unix, ""),
			"PermitUserEnvironment", checks.Eq("no")),
		checks.SSHDOption(meta("SSH-008", low, "ssh", "SSH LoginGraceTime is 60s or less", unix, ""),
			"LoginGraceTime", checks.LE(60)),
	}
}
