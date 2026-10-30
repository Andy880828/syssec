---
name: syssec
description: Assess and track the security posture of the local host (Linux, macOS, Windows): hardening checks, installed-package vulnerabilities prioritised by real-world exploitation (OSV + CISA KEV + EPSS), accepted-risk waivers, and how all of it changed over time. Use when asked "is this machine secure?", "what should I patch first?", "what changed since last week?", "are we affected by CVE-X?", or to gate a change on security regressions.
---

# syssec — Agent Operating Manual

`syssec` is one static binary that audits the host it runs on and keeps a
local SQLite history. It is read-only towards the system and never contacts
people. Deciding whether and how to alert someone is your job: syssec gives
you `regression`, priorities and exit codes so you can decide.

## 0. Ground rules

1. **Start with `syssec status --json`.** It is offline and instant. It tells
   you whether a baseline exists, how old it is, whether the last scan
   regressed, whether threat intel is fresh, and gives `next_steps`.
2. **Always pass `--json`** (or export `SYSSEC_OUTPUT=json`). Check `ok`
   first. On failure, act on `error.code` and `error.hint`.
3. **Read history before re-scanning.** `status`, `report`, `vulns`, `diff`,
   `history` and `explain <CHECK>` are local. Run `scan` when the data is
   stale (`last_scan.age_hours`) or the user asks for current state.
4. **Root/Administrator gives full coverage.** If `host.privileged` is
   false, say that checks were limited and suggest `sudo`. Never escalate on
   your own.
5. **In a container** (`host.container` is set), host-level checks are
   skipped by design. Tell the user to scan the host for those.
6. **Remediation is advice.** Show `remediation` text and apply it only when
   asked. sysctl, sshd and firewall changes can lock people out.
7. **Waivers are a human decision.** Never run `waive add` without the
   user's explicit agreement and a reason they gave you. Suggest an expiry.

## 1. Envelope, errors, exit codes

```json
{"ok": true,  "command": "vulns", "schema": "syssec/v1", "data": {...}, "warnings": ["..."]}
{"ok": false, "command": "report", "schema": "syssec/v1", "error": {"code": "no_data", "message": "...", "hint": "run `syssec scan --vulns --json` ..."}}
```

| `error.code` | What to do |
|---|---|
| `usage` | Fix flags or args using `hint`, or run `syssec help <cmd> --json` |
| `no_data` | Run the command in `hint` (usually a scan) |
| `not_found` | Check the ID; `syssec checks --json` lists check IDs |
| `network` | Intel source unreachable. Offline commands still work; mention mirrors (`SYSSEC_OSV_URL` …) |
| `runtime` | Report the message to the user |

Exit codes: `0` ok · `1` error · `2` usage · `3` `--fail-on` gate tripped
(the output is still valid JSON).

For self-discovery, `syssec describe --json` returns every command, flag,
error code, status and priority definition. `syssec <cmd> --help --json`
returns one command's schema.

## 2. Intent → command

| User intent | Command |
|---|---|
| Anything, first call | `syssec status --json` |
| "How secure is this box?" (no or stale baseline) | `syssec scan --vulns --json` |
| "What's the current state?" | `syssec report --json` |
| "What should I patch first?" | `syssec vulns --priority P1 --json` |
| "Anything actively exploited?" | `syssec vulns --kev --json` |
| "What can I patch right now?" | `syssec vulns --fixable --limit 0 --json` |
| "Are we affected by CVE-X?" | `syssec vulns --limit 0 --json`, search `id`/`aliases`; then `syssec explain CVE-X --json` |
| "Is package P vulnerable?" | `syssec vulns --package P --json` |
| "Why is check X failing / how to fix?" | `syssec explain X --json` |
| "What changed since last time?" | `syssec diff --json` |
| "Getting better or worse?" | `syssec history --json` → `trend.direction` |
| "When did X start failing?" | `syssec history --check X --json` |
| "That finding is expected here" | ask the user, then `syssec waive add X --reason "..." --expires 90d --json` |
| "Block this change if security regressed" | `syssec scan --vulns --fail-on P0 --json` (or `--fail-on high`) |
| Refresh threat intel | `syssec intel sync --json` |

## 3. Reading results

**Check statuses**:

| status | meaning |
|---|---|
| `pass` | compliant |
| `fail` | non-compliant |
| `warn` | likely issue, or could not be verified |
| `skip` | not applicable, not readable, or host-only inside a container |
| `error` | the probe itself failed |
| `waived` | accepted risk; see the `waiver` field for reason and expiry |

**Summary**:
- `score` (0–100) and `grade` measure configuration hardening only.
  Severity weights: critical 10, high 6, medium 3, low 1. A `warn` counts
  half. `skip`, `error` and `waived` are excluded.
- `failed_by_severity` is the best one-line summary of checks.
- Vulnerability counts are separate from the score: `vulns`,
  `vulns_by_priority`, `kev`, `fixable`. They exclude waived items, which
  are counted in `waived`.

**Vulnerability priority**: this is the order to work in, and it is not the
same as severity.

| priority | rule |
|---|---|
| `P0` | in CISA KEV: exploited in the wild. Patch now. |
| `P1` | EPSS ≥ 0.10 (likely to be exploited soon), or critical with a fix available |
| `P2` | high/critical severity, or EPSS ≥ 0.01 |
| `P3` | everything else |

- `epss` is the probability (0–1) of exploitation in the next 30 days.
- `fixed_in` empty means there is no distro fix yet. Say so, and do not
  claim that upgrading helps.
- `aliases` holds the other advisory IDs for the same CVE (USN, DSA, GHSA…).
  Duplicates are already merged.
- Kernel header and source packages (`linux-libc-dev`, `linux-headers-*`)
  are excluded from matching because they do not run. See
  `vuln_match.excluded`.

**Scan output extras**:
- `findings` contains only problems unless you pass `--all`.
- `top_vulns` holds at most 10 entries; use `vulns` for the rest.
- `diff` compares with the previous complete scan. `regression: true` means
  something got worse. `regressed[].from == ""` means a new check.
- `next_steps` lists ready-to-run follow-ups and is a sensible default plan.
- `partial: true` means only a subset ran (`--check`/`--category`). Partial
  scans are never saved.

## 4. Prioritising for the user

1. `P0` vulns, with the exact package and `fixed_in`.
2. `fail` checks with severity `critical`.
3. `P1` vulns.
4. `fail` checks with severity `high`.
5. Everything else, grouped by category.

Use context, not dogma. `NET-101` (IP forwarding) is expected on
Docker/Kubernetes hosts, which makes it a waiver candidate rather than a fix.
`NET-002` is an inventory of exposed services, not a defect.

## 5. Workflows

**Scheduled monitoring, driven by you or by cron**
```bash
syssec scan --vulns --json > /tmp/scan.json   # saved and diffed automatically
# alert the user only if data.diff.regression is true or data.summary.kev > 0
```

**Investigating a regression**
```bash
syssec diff --json                     # regressed[].id, vulns new/fixed
syssec history --check <ID> --json     # when it started
syssec explain <ID> --json             # why it matters, how to fix
```

**"Are we affected by X?"**
```bash
syssec explain CVE-XXXX-YYYY --json    # advisory, KEV entry, EPSS, fixed versions, first_seen
syssec vulns --limit 0 --json          # is it on this host? (match id or aliases)
syssec inventory --filter <pkg> --json # installed version
```
If `vuln_scanned` is false, scan with `--vulns` first. Matching covers
dpkg (Debian/Ubuntu), apk (Alpine) and rpm (Rocky/Alma). Other platforms are
inventory-only; `inventory` reports `vuln_matchable`.

## 6. Cost model

- Checks and inventory take well under a second.
- `scan --vulns`: the first run asks OSV about every installed package
  version (about 10 s for ~800 packages). Later runs reuse
  answers for unchanged versions (`SYSSEC_INTEL_TTL_HOURS`, default 6) and
  take about 1–2 s with no network calls. EPSS is cached for 24 h, and the
  KEV catalog is revalidated automatically when it is older than 24 h. Use
  `--refresh` or `intel sync` to force fresh OSV data.
- Network use happens only in `scan --vulns`, `intel sync`, and
  `explain <VULN>` on a cache miss.

## 7. Extending

- Drop JSON rule packs into `$SYSSEC_HOME/rules/` (or `SYSSEC_RULES_DIR`).
  Supported types: `sysctl`, `sshd`, `file_mode`, `file_regex`, `registry`,
  `command`. Add the tag `"host-only"` for host-level controls. Examples are
  in `examples/rules/`.
- Malformed rules show up in `warnings` and never stop a scan.

## 8. Don'ts

- Don't parse human output or query the SQLite file directly.
- Don't waive without the user's consent, and don't waive without an expiry
  unless the user insists.
- Don't run `prune` unless asked, and preview it with `--dry-run` first.
- Don't call a host "secure" from the score alone. Mention skipped checks,
  waivers and P0/P1 vulns.
