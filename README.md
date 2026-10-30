# syssec

**給 AI Agent 用的主機安全態勢與漏洞情資 CLI**：支援 Linux、macOS、Windows，是單一靜態二進位檔，不需要 cgo，也不依賴任何外部掃描器。

`syssec` 會稽核它所在的主機，涵蓋：
- **系統硬化**：SSH、kernel、網路、檔案系統、帳號、防火牆、磁碟加密、UAC/Defender…
- **已安裝套件**：dpkg/rpm/apk/pacman/Homebrew/Windows
- **已知漏洞**：用 OSV.dev 比對，再用 CISA KEV 和 FIRST EPSS 依「實際被利用的風險」排優先度

每次掃描都存進本地 SQLite，所以能回答「跟上週比哪裡變差了？」「這個 CVE 什麼時候出現的？」。

它只讀取系統、不修改設定，也不主動通知任何人。要不要通知、透過什麼管道，由驅動它的 agent 或排程器根據 `regression`、優先度和 exit code 決定。Agent 的操作手冊在 [`SKILLS.md`](SKILLS.md)，設計取捨記在 [`docs/DESIGN-REVIEW.md`](docs/DESIGN-REVIEW.md)。

```text
$ sudo syssec scan --vulns
vm  Ubuntu 24.04.5 LTS  scan #12  2026-10-30T08:54:09Z
Score 80/100 (B)  checks 51: 21 pass, 9 fail, 6 warn, 15 skip  vulns 560 (P0 1, P1 0, fixable 1)

!  high    SYS-001  A mandatory access control LSM is active   could not determine LSM state ...
✗  medium  KRN-006  Symlink protection is enabled               fs.protected_symlinks = 0 (expected 1)
...
Top vulnerabilities:
  P0  critical  epss 83%  CVE-2026-111497  brotli 1.1.0-2build2   fix: 1.1.0-2ubuntu0.1  A buffer overflow ...
  P2  high      epss 8%   CVE-2018-6952    patch 2.7.6-7build3    fix: -                 A double free ...
  … 550 more: syssec vulns

Next:
  syssec vulns --priority P0 --json  # 1 actively exploited (CISA KEV); e.g. CVE-2026-111497 in brotli, fixed in 1.1.0-2ubuntu0.1
```

## 安裝

```bash
go install github.com/Andy880828/syssec/cmd/syssec@latest
make build      # → bin/syssec
make cross      # → dist/ 下 linux/darwin/windows × amd64/arm64
```

需要 Go 1.24 以上。產出的二進位檔是 `CGO_ENABLED=0`，可以直接複製到目標主機執行。

## 指令

| 指令 | 用途 | 需要網路 |
|---|---|---|
| `status` | 一次看完：上次掃描、是否退步、情資新鮮度、例外狀態、下一步建議 | 否 |
| `scan` | 檢查、套件盤點（加 `--vulns` 會比對漏洞）、套用例外、存檔，並和前一次比較 | 只有 `--vulns` 且快取過期時 |
| `report` | 讀取已存的掃描（預設最新一次） | 否 |
| `vulns` | 依優先度列出漏洞；可用 `--priority`、`--kev`、`--fixable`、`--package` 篩選 | 否 |
| `diff` | 退步、修復、套件異動、新增或已修補的漏洞 | 否 |
| `history` | 分數走勢；`--check ID` 顯示單一檢查的時間軸 | 否 |
| `explain <ID>` | 檢查的原因與修法，或漏洞詳情（KEV、EPSS、修補版本、首次出現時間） | 漏洞不在快取時 |
| `checks` / `inventory` | 規則目錄 / 已安裝套件 | 否 |
| `waive add/rm/list` | 接受風險的例外（`waivers.json`） | 否 |
| `intel sync` | 更新 KEV，並強制重新查詢 OSV | 是 |
| `prune` | 清理舊掃描（可加 `--dry-run` 預覽） | 否 |
| `describe` / `help <cmd>` | 機器可讀的說明；加 `--json` 可取得單一指令的 schema | 否 |

`scan --fail-on` 可以接嚴重度（例如 `high`），也可以接優先度（例如 `P0`）。只要有任何沒被豁免的項目達到門檻，就會 exit 3，可直接當 CI 或變更的關卡。

### 輸出格式

```json
{"ok":true,"command":"vulns","schema":"syssec/v1","data":{...},"warnings":[]}
{"ok":false,"command":"report","schema":"syssec/v1","error":{"code":"no_data","message":"...","hint":"run `syssec scan --vulns --json` ..."}}
```

- `error.code` 是以下其中之一：`usage`、`no_data`、`not_found`、`network`、`runtime`。
- Exit code：`0` 成功 · `1` 錯誤 · `2` 用法錯誤 · `3` 達到 `--fail-on` 門檻。
- 輸出到 pipe 時是緊湊 JSON，輸出到終端機時會自動縮排。

## 漏洞優先度

嚴重度不等於修補順序。syssec 參考 Grype、Defender VM 這類工具的風險導向排序，但用的是公開、可以解釋的規則：

| 優先度 | 規則 |
|---|---|
| **P0** | 在 CISA KEV 清單上（已遭實際利用） |
| **P1** | EPSS ≥ 0.10（30 天內被利用機率高），或 critical 且已有修補版本 |
| **P2** | high/critical，或 EPSS ≥ 0.01 |
| **P3** | 其他 |

為了降低雜訊還做了兩件事：
- **同一個 CVE 只算一次**：發行版 advisory（USN/DSA/UBUNTU-CVE…）指向同一個 CVE 時會合併，其他 ID 收進 `aliases`。
- **排除不會執行的套件**：kernel headers 和 kernel source 不會在主機上執行，所以不拿去比對。

在 Ubuntu 24.04 實測，漏洞數從 3,775 降到 560，剩下的都是真正會執行的程式碼。

## 例外（waivers）

```bash
syssec waive add NET-101 --reason "Docker host: forwarding required" --expires 180d
syssec waive add CVE-2024-1234 --package openssl --reason "no TLS listener" --expires 2026-12-31
syssec waive list
```

- 被豁免的項目會保留證據，狀態標成 `waived` 並附上原因。
- 它們不計分、不觸發 `--fail-on`，預設也不會列出。
- 到期後自動失效，並在 `status` 裡提醒。
- `waivers.json` 可以放進 git，做成整個團隊共用的政策。

## 架構

```
cmd/syssec/            進入點
internal/
  core/                領域模型：Severity、Result、Vuln、Waiver、EPSS、Report；計分與優先度；零依賴
  sysenv/              主機抽象：FS / Runner / Registry / Host（含容器偵測）+ 測試用 fake
  checks/              檢查引擎：Check 介面、Registry、並行 Engine、宣告式 primitive、JSON 規則
    builtin/           內建 77 條規則（全部平台都會編譯，執行時依 Platforms 和 host-only tag 過濾）
  inventory/           直接讀取 dpkg/apk/pacman/Cellar/registry 資料庫
  intel/               OSV 查詢、CVSS v3、KEV、EPSS、CVE 合併、執行期套件過濾；定義 Cache 介面
  store/               SQLite（migration、歷史、情資快取），實作 intel.Cache
  waiver/              waivers.json 讀寫與套用
  diff/                兩次報告的差異（漏洞以 ID 或別名比對，改名不算變動）
  config/              SYSSEC_* 環境變數
  app/                 應用層：Scan / Diff / LoadReport
  cli/                 指令樹、輸出 envelope、錯誤分類、describe
```

依賴方向由外往內：`cli → app → {checks, inventory, intel, store, waiver, diff} → sysenv → core`。

### 設計重點

- **可擴充的檢查**：
  - 每條規則實作單一的 `Check` 介面，常見類型可直接用宣告式 primitive（`Sysctl`、`SSHDOption`、`FileMode`、`FileRegex`、`RegistryValue`、`CommandOutput`）組合。
  - 新增規則通常只要一行；也可以把 JSON 規則包放進 `$SYSSEC_HOME/rules/`，不用重新編譯（範例：[`examples/rules/org-baseline.json`](examples/rules/org-baseline.json)）。
  - 引擎並行執行，每條規則有獨立的 timeout 和 panic 隔離。
  - 標了 `host-only` 的規則在容器內自動 skip。
- **輕量的情資同步**：
  - 不鏡像任何資料庫，只拿這台主機實際安裝的套件版本去查 OSV。
  - 兩層快取：同一個套件版本的查詢結果保留 6 小時；advisory 依 `modified` 時間戳重新驗證，並以精簡格式儲存（kernel advisory 從約 1 MB 縮到幾 KB）。
  - KEV 用 ETag 重新驗證；EPSS 只查這台主機上出現的 CVE，快取 24 小時。
  - 實測（Ubuntu 24.04，837 個套件）：全新安裝第一次約 10 秒（含 KEV 和 EPSS），之後約 **1.5 秒**且完全離線。
- **歷史**：
  - 只有完整掃描會存檔並參與走勢；部分掃描不存，避免假的「已修復」。
  - 漏洞以「套件 + ID 或別名」比對，上游改名不會被算成一筆修復加一筆新漏洞。
  - 資料庫權限是 `0600`。

## 漏洞比對涵蓋範圍

| 平台 / 套件管理員 | 盤點 | OSV 比對 |
|---|---|---|
| Debian / Ubuntu（dpkg） | ✓ | ✓ |
| Alpine（apk） | ✓ | ✓ |
| Rocky / AlmaLinux（rpm） | ✓ | ✓ |
| RHEL / Fedora / SUSE、Arch | ✓ | – |
| macOS（Homebrew）、Windows | ✓ | – |

## 內建檢查（77 條）

- **Linux（51）**：SSH、kernel sysctl、網路 sysctl 和對外高風險服務（包含 socket 對應的 process）、關鍵檔案權限、掛載選項、world-writable、可疑 SUID、帳號、MAC LSM、Secure Boot、自動更新、防火牆、容器 runtime socket。
- **macOS（25）**：FileVault、Gatekeeper、SIP、Application Firewall、自動更新、訪客帳號、Remote Login、自動登入，再加上共用的 SSH 和檔案權限檢查。
- **Windows（16）**：UAC、防火牆、Defender、WDigest、LSA RunAsPPL、SAM、AutoRun、LLMNR、Windows Update、PowerShell 記錄、SMBv1、RDP NLA。

## 設定（只有環境變數）

所有狀態都放在 `SYSSEC_HOME` 這一個目錄裡：`syssec.db`、`rules/`、`waivers.json`。預設位置是 `~/.config/syssec`；macOS 是 `~/Library/Application Support/syssec`，Windows 是 `%AppData%\syssec`。

| 變數 | 用途 |
|---|---|
| `SYSSEC_HOME` | 資料目錄 |
| `SYSSEC_DB` | 資料庫路徑（也可以用 `--db` 指定） |
| `SYSSEC_RULES_DIR` | 額外的規則目錄 |
| `SYSSEC_OUTPUT=json` | 預設輸出 JSON |
| `SYSSEC_OSV_URL` / `SYSSEC_KEV_URL` / `SYSSEC_EPSS_URL` | 內部鏡像或 proxy |
| `SYSSEC_INTEL_TTL_HOURS` | OSV 查詢結果的快取時間，預設 6 |
| `SYSSEC_HTTP_TIMEOUT` | HTTP timeout（秒） |

### 排程範例（systemd timer）

```ini
# /etc/systemd/system/syssec.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/syssec scan --vulns --json

# /etc/systemd/system/syssec.timer
[Timer]
OnCalendar=*-*-* 03:17
Persistent=true
[Install]
WantedBy=timers.target
```

要不要通知、透過什麼管道，交給讀取結果的 agent 決定，例如：`syssec status --json` 裡 `last_scan.regression == true` 或出現 P0 漏洞時才發通知。

## 開發

```bash
make test     # go test -race ./...
make vet      # linux + darwin + windows 都會 vet
make cross
```
