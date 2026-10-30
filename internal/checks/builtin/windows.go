package builtin

import (
	"context"
	"errors"

	"github.com/Andy880828/syssec/internal/checks"
	"github.com/Andy880828/syssec/internal/core"
	"github.com/Andy880828/syssec/internal/sysenv"
)

const (
	regPolicySystem = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	regFirewall     = `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`
	regLSA          = `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
	regTS           = `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
)

func windowsChecks() []checks.Check {
	rv := func(id string, sev severity, cat, title, path, name string, want checks.Expect, missing core.Status, fix string) checks.Check {
		return checks.RegistryValue(meta(id, sev, cat, title, windows, fix), path, name, want, missing)
	}
	return []checks.Check{
		rv("WIN-001", critical, "system", "User Account Control is enabled", regPolicySystem, "EnableLUA", checks.Eq("1"), core.StatusPass, ""),
		rv("WIN-002", high, "system", "UAC prompts administrators for consent", regPolicySystem, "ConsentPromptBehaviorAdmin", checks.NotIn("0"), core.StatusPass,
			"Set ConsentPromptBehaviorAdmin to 2 (prompt on secure desktop) or 5 (default)."),
		rv("WIN-003", high, "network", "Firewall is enabled for the Domain profile", regFirewall+"DomainProfile", "EnableFirewall", checks.Eq("1"), core.StatusFail, "`Set-NetFirewallProfile -Profile Domain -Enabled True`"),
		rv("WIN-004", high, "network", "Firewall is enabled for the Private profile", regFirewall+"StandardProfile", "EnableFirewall", checks.Eq("1"), core.StatusFail, "`Set-NetFirewallProfile -Profile Private -Enabled True`"),
		rv("WIN-005", critical, "network", "Firewall is enabled for the Public profile", regFirewall+"PublicProfile", "EnableFirewall", checks.Eq("1"), core.StatusFail, "`Set-NetFirewallProfile -Profile Public -Enabled True`"),
		rv("WIN-006", critical, "malware", "Defender real-time protection is not disabled by policy",
			`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring", checks.NotIn("1"), core.StatusPass,
			"Remove the DisableRealtimeMonitoring policy and run `Set-MpPreference -DisableRealtimeMonitoring $false`."),
		rv("WIN-007", critical, "malware", "Defender is not disabled by policy",
			`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, "DisableAntiSpyware", checks.NotIn("1"), core.StatusPass, "Remove the DisableAntiSpyware policy value."),
		rv("WIN-008", high, "credentials", "WDigest does not cache cleartext credentials",
			`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, "UseLogonCredential", checks.NotIn("1"), core.StatusPass, "Set UseLogonCredential to 0."),
		rv("WIN-009", medium, "credentials", "LSA protection (RunAsPPL) is enabled", regLSA, "RunAsPPL", checks.In("1", "2"), core.StatusFail,
			"Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1 and reboot."),
		rv("WIN-010", medium, "credentials", "Anonymous SAM enumeration is restricted", regLSA, "RestrictAnonymousSAM", checks.Eq("1"), core.StatusFail, ""),
		rv("WIN-011", low, "system", "AutoRun is disabled for all drives",
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`, "NoDriveTypeAutoRun", checks.Eq("255"), core.StatusFail, ""),
		rv("WIN-012", low, "network", "LLMNR is disabled",
			`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast", checks.Eq("0"), core.StatusFail,
			"GPO: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution."),
		rv("WIN-013", medium, "updates", "Automatic Updates are not disabled by policy",
			`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "NoAutoUpdate", checks.NotIn("1"), core.StatusPass, ""),
		rv("WIN-014", low, "logging", "PowerShell script block logging is enabled",
			`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging", checks.Eq("1"), core.StatusFail, ""),
		smbv1(),
		rdpNLA(),
	}
}

func smbv1() checks.Check {
	m := meta("WIN-015", high, "network", "SMBv1 is disabled", windows,
		"`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` (EternalBlue/WannaCry vector).")
	return checks.New(m, func(_ context.Context, env *sysenv.Env) checks.Outcome {
		v, err := checks.ReadRegistry(env.Reg, `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1")
		switch {
		case errors.Is(err, sysenv.ErrUnsupported):
			return checks.Skip("registry not available")
		case err == nil && v == "0":
			return checks.Pass("SMB1 = 0")
		case err == nil:
			return checks.Fail("SMB1 = %s", v)
		}
		if start, err := checks.ReadRegistry(env.Reg, `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10`, "Start"); err == nil && start != "4" {
			return checks.Fail("mrxsmb10 driver present (Start=%s)", start)
		}
		return checks.Pass("SMBv1 feature not installed")
	})
}

func rdpNLA() checks.Check {
	m := meta("WIN-016", high, "network", "RDP requires Network Level Authentication", windows,
		"System Properties > Remote > allow connections only with Network Level Authentication.")
	return checks.New(m, func(_ context.Context, env *sysenv.Env) checks.Outcome {
		deny, err := checks.ReadRegistry(env.Reg, regTS, "fDenyTSConnections")
		if errors.Is(err, sysenv.ErrUnsupported) {
			return checks.Skip("registry not available")
		}
		if err != nil || deny == "1" {
			return checks.Pass("RDP disabled")
		}
		nla, err := checks.ReadRegistry(env.Reg, regTS+`\WinStations\RDP-Tcp`, "UserAuthentication")
		if err == nil && nla == "1" {
			return checks.Pass("RDP enabled with NLA")
		}
		return checks.Fail("RDP enabled without NLA (UserAuthentication=%q)", nla)
	})
}
