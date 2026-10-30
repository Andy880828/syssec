package builtin

import (
	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/core"
)

// macOS controls use OS-native probes (fdesetup, spctl, csrutil, ...):
// they ship with every macOS install, so no third-party dependency is added.
func darwinChecks() []checks.Check {
	return []checks.Check{
		checks.CommandOutput(meta("MAC-001", critical, "encryption", "FileVault disk encryption is on", darwin,
			"System Settings > Privacy & Security > FileVault > Turn On, or `sudo fdesetup enable`."),
			[]string{"fdesetup", "status"}, `FileVault is On`, true),
		checks.CommandOutput(meta("MAC-002", high, "system", "Gatekeeper is enabled", darwin,
			"`sudo spctl --master-enable`"),
			[]string{"spctl", "--status"}, `assessments enabled`, true),
		checks.CommandOutput(meta("MAC-003", critical, "system", "System Integrity Protection is enabled", darwin,
			"Boot into Recovery and run `csrutil enable`."),
			[]string{"csrutil", "status"}, `status: enabled`, true),
		checks.CommandOutput(meta("MAC-004", high, "network", "Application firewall is enabled", darwin,
			"`sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on`"),
			[]string{"/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"}, `(?i)enabled|State = [12]`, true),
		checks.CommandOutput(meta("MAC-005", low, "network", "Firewall stealth mode is enabled", darwin,
			"`sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on`"),
			[]string{"/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"}, `(?i)stealth mode (is )?(enabled|on)`, true),
		checks.CommandOutput(meta("MAC-006", medium, "updates", "Automatic update checks are enabled", darwin,
			"`sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true`"),
			// An unset key means the macOS default, which is enabled.
			[]string{"defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"}, `(?m)^1$|does not exist`, true),
		checks.CommandOutput(meta("MAC-007", medium, "updates", "Critical security updates install automatically", darwin,
			"`sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true`"),
			[]string{"defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"}, `(?m)^1$|does not exist`, true),
		checks.CommandOutput(meta("MAC-008", low, "accounts", "Guest account is disabled", darwin,
			"`sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false`"),
			[]string{"defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"}, `(?m)^1$`, false),
		checks.CommandOutput(meta("MAC-009", medium, "ssh", "Remote Login (sshd) is disabled", darwin,
			"System Settings > General > Sharing > Remote Login off, or `sudo systemsetup -setremotelogin off`."),
			// Fail only when explicitly enabled: an unlisted service keeps its
			// launchd default, which is disabled for sshd.
			[]string{"launchctl", "print-disabled", "system"}, `"com\.openssh\.sshd" => (false|enabled)`, false),
		checks.CommandOutput(core.CheckMeta{ID: "MAC-010", Severity: medium, Category: "system", Title: "Automatic login is disabled",
			Platforms: darwin, Remediation: "`sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser`"},
			[]string{"defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"}, `(?i)does not exist`, true),
	}
}
