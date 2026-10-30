# syssec 設計審視（v2）

這份文件記錄第二輪審視：拿 syssec 跟開源與商用工具比較，列出優缺點和實際改動，清掉過度設計，並對照 gh CLI、飛書 CLI 檢視 agent 友善度。最後附上還沒實作的功能構想。

## 1. 比較對象

| 類別 | 工具 | 值得借鏡 | 不採用的部分 |
|---|---|---|---|
| 主機硬化稽核 | [Lynis](https://cisofy.com/lynis/) | 硬化指數、`skip-test` 例外、只讀不改 | Shell 實作、純文字報告、沒有歷史紀錄 |
| 合規基準 | OpenSCAP / CIS-CAT | 規則與基準（benchmark）分離、profile | XCCDF/OVAL 太重，agent 用不到 |
| 主機遙測 | osquery | 把主機當成資料來查 | 常駐 daemon、要學 SQL schema |
| 合規 / 漏洞平台 | Wazuh SCA、Tenable、Qualys、Defender VM | 例外要有原因和到期日、風險導向的排序 | 需要 server 與 agent 架構，授權成本高 |
| 漏洞掃描 | [Grype](https://oss.anchore.com/docs/guides/vulnerability/interpreting-results/)、Trivy、osv-scanner | 結合 CVSS、EPSS、KEV 的風險排序；`--ignore-unfixed`；`.trivyignore` | 以容器映像和 SBOM 為主，不看主機設定 |
| 測試即程式碼 | Chef InSpec、Goss | waiver 帶 justification 和 expiration | 需要 Ruby 或自訂 DSL |
| CLI 設計 | [gh](https://cli.github.com/manual/)、[飛書 CLI (larksuite/cli)](https://github.com/larksuite/cli) | 見第 4 節 | — |

## 2. 第一版的問題與修正

### 2.1 漏洞雜訊太多，排序也不對（最嚴重）

**實測**：Ubuntu 24.04 上報出 3,775 個漏洞，其中 3,214 個來自 `linux`。問題出在 `linux-libc-dev`（kernel 標頭檔）的 source package 是 `linux`，所以從沒執行過那個 kernel 的主機（甚至容器）也被算進整個 kernel 的 CVE。Trivy 使用者常抱怨同一件事。

**另一個問題**：同一個漏洞會同時以 `USN-8956-1` 和 `UBUNTU-CVE-2026-111497` 出現，算成兩筆。

**修正**：
- `intel.Runtime()` 把只在編譯時用到的套件排除在比對外，包括 kernel headers、kernel source 和文件套件。正在執行的 kernel 仍然透過 `linux-image-*` 比對。
- `mergeByCVE` 把同一個套件上指向同一個 CVE 的 advisory 合併成一筆，以 CVE 為 ID，其餘 advisory ID 收進 `aliases`。
- **結果**：3,775 筆降到 560 筆，而且每一筆都是真正會執行的程式碼。全新安裝的第一次漏洞掃描也從 25 秒降到 10 秒，因為不用再分頁查詢 kernel 的 3,214 筆 advisory。
- **嚴重度不等於優先度**：參考 Grype 的作法加入 EPSS（FIRST 預測的 30 天內被利用機率），定出透明、可解釋的優先度：

  | 優先度 | 條件 |
  |---|---|
  | P0 | 在 CISA KEV 清單上（已遭實際利用） |
  | P1 | EPSS ≥ 0.1，或 critical 且已有修補版本 |
  | P2 | high/critical，或 EPSS ≥ 0.01 |
  | P3 | 其他 |

  Grype 的風險分數公式沒有公開。我們改用離散分級，因為 agent 能直接引用規則向使用者解釋原因，比一個 0 到 10 的黑盒分數有用。
- EPSS 只查詢這台主機上實際出現的 CVE（每批 100 個），快取 24 小時，延續「只問需要的」原則。

### 2.2 沒有例外機制，誤報無法消化

`NET-101`（IP forwarding）在 Docker 主機上本來就該開；第一版只能每次都報，或者整條規則關掉。Lynis 的 `skip-test` 會讓整條規則消失，也不理想。

**修正**：新增 `waive` 指令，例外存在 `waivers.json`，可以放進 git 管理。規則參考 InSpec 和 Trivy：
- `--reason` 必填，`--expires` 可選（日期或 `90d`），也能用 `--package` 只豁免特定套件上的漏洞。
- 被豁免的項目不會消失：狀態變成 `waived`，證據保留，但不計分、不觸發 `--fail-on`、預設不列出。
- 過期的例外會自動失效，並出現在 `warnings` 和 `status.next_steps`。
- `diff` 把 `fail → waived` 歸在 `changed`，不算「已修復」，避免被當成真的修好。

### 2.3 在容器裡誤判

在容器裡執行時，Secure Boot、LSM、kernel sysctl、`/tmp` 掛載選項這些檢查判斷的都是宿主機，容器自己改不了。

**修正**：
- `Host.Container` 會偵測 docker、podman、kubernetes、lxc。
- 只適用宿主機的規則加上 `host-only` tag，在容器內一律標成 `skip` 並說明原因。
- 這是引擎層的通用機制，自訂 JSON 規則也能加這個 tag。

### 2.4 漏洞改名被誤判成變動

上游資料改變 advisory 的主鍵時（例如 USN 換成 CVE，或新增 GHSA 別名），舊版 `diff` 會報「1 個修復加 1 個新漏洞」。

**修正**：`diff` 和 `first_seen` 都改成用「套件 + 任一 ID 或別名的交集」比對。

### 2.5 漏洞清單塞在 scan 輸出裡

第一版的 `scan` 和 `report` 共有 11 個漏洞相關的 flag（`--max-vulns`、`--fixable`、`--min-severity`、`--packages`…），而且兩個指令各自重複一份。

**修正**（參考 gh 一個名詞一個指令的作法）：
- 新增 `vulns` 指令，負責所有篩選：`--priority`、`--kev`、`--fixable`、`--package`、`--waived`、`--limit`。
- `scan` 和 `report` 只內嵌前 10 筆（`top_vulns`），其餘指向 `syssec vulns`。

## 3. 移除的過度設計

| 移除 | 原因 |
|---|---|
| Telegram 與 `notify` 模組 | 通知是協作 agent 或排程器的工作。syssec 提供 `diff.regression`、`status.last_scan.regression` 和 `--fail-on`（exit 3），呼叫端拿這些就能決定要不要通知、用什麼管道 |
| `config.json` 與 `--config` | 只有 Telegram 需要它。現在設定全部走 `SYSSEC_*` 環境變數，所有狀態都放在 `SYSSEC_HOME` 這一個目錄（資料庫、`rules/`、`waivers.json`） |
| `--save` 與 `--no-save` 三態邏輯 | 部分掃描一律不存，只保留 `--no-save` |
| `--no-inventory` | 盤點不到 0.1 秒，而且 diff 需要它 |
| `--packages`、`--max-vulns`、`--fixable`（在 scan 上） | 由 `inventory` 和 `vulns` 取代 |
| `intel status` | 併進 `status` |
| `explain --offline` | 有快取就直接用快取，沒有快取時這個 flag 也幫不上忙 |
| `RulePack` 型別 | 已被 `ParseRulePack` 取代，沒有任何地方用到 |
| `--fail-on` 只吃嚴重度 | 改成同時接受 `high` 和 `P0`：一個 flag 取代原本要新增的 `--fail-on-priority` |

刻意**保留**的抽象：
- `sysenv` 介面讓三個平台的規則能在任何機器上測試。
- 兩層 intel 快取讓第二次之後的掃描降到約 1.5 秒（第一次約 10 秒；最初版本 cached 時仍需 2 分 20 秒）。
- `intel.Cache` 這個 port 讓 intel 模組不必依賴 SQLite。

## 4. Agent 友善度：對照 gh CLI 和飛書 CLI

| 實踐 | gh / 飛書 CLI | syssec 現況 |
|---|---|---|
| 結構化輸出 | gh `--json fields` / `--jq`；飛書 `--format json` | 每個指令都支援 `--json`，輸出固定的 envelope；導到 pipe 時自動改成緊湊格式。不加 `--jq`，理由見下方 |
| 可自我描述 | gh `help` 和完整的 manual | `describe --json` 列出指令、flag、exit code、error code、狀態與優先度定義；**新增** `<cmd> --help --json` 可單獨取得一個指令的 schema，`help <cmd>` 也可用 |
| 分層指令 | 飛書：快捷指令 → API 指令 → raw API | 快捷層是 `status` 和 `scan`，資源層是 `vulns`、`checks`、`history`、`diff`，細節層是 `explain` 和 `report --all` |
| 預覽有副作用的操作 | 飛書 `--dry-run` | 唯一會刪資料的 `prune` 加了 `--dry-run`；`waive` 是可逆的檔案編輯 |
| 錯誤可以據以行動 | gh 給出明確訊息和 exit code | **新增**穩定的 `error.code`：`usage`、`no_data`、`not_found`、`network`、`runtime`，每一個都附 `hint`（例如 `no_data` 會直接給出 `syssec scan --vulns --json`） |
| 單一入口 | `gh status` | **新增** `syssec status`：離線執行，一次回傳上次掃描的時間、分數、是否退步、情資新鮮度、例外狀態和 `next_steps` |
| 隨工具附 Skill | 飛書 CLI 內附 agent skills | 根目錄的 `SKILLS.md` 帶 frontmatter，可直接當成 Claude Code skill 使用 |
| 不互動、可重複執行 | gh 偵測到非 TTY 時不會跳出提示 | 從來不會互動；除了 `scan`、`waive`、`prune` 之外都是唯讀 |
| 分頁 | gh `--limit` | `vulns`、`inventory`、`history` 統一用 `--limit`（0 代表全部），並回傳 `total` 和 `returned` |

**不採用 `--jq`**：gh 內建 jq 是因為使用者不一定有裝 jq。但 agent 本來就能 pipe 給 jq 或 python，而且 syssec 的預設輸出已經裁剪過。內建 gojq 會多一個依賴和一套查詢語法，划不來。

**不自動偵測 agent**（例如看到 `CLAUDECODE=1` 就自動輸出 JSON）：這種隱式行為會讓人類和 agent 看到不同結果，難以除錯。改用明確的 `--json` 或 `SYSSEC_OUTPUT=json`。

## 5. 新功能構想（未實作，依價值排序）

1. **執行期可達性（runtime reachability）**：讀 `/proc/*/maps` 和 dpkg/rpm 的檔案清單，判斷有漏洞的函式庫是否真的被某個執行中的 process 載入，並加上 `in_use: true` 和 process 名稱。這是 Defender VM 這類商用產品的賣點，在 Linux 上用純 Go 就能做到，而且成本很低。
2. **證據變化追蹤**：目前 `diff` 只看狀態轉換。`NET-002` 開了新的對外 port，或 `FS-021` 多了一個 SUID 檔案，狀態可能沒變但證據變了，對入侵偵測很有價值。
3. **執行中與已安裝的 kernel 比較**：已安裝較新的 `linux-image` 但還沒重開機時提出警告，可以跨發行版取代只有 Debian 系才有的 `reboot-required`。
4. **語言生態系 lockfile**：`syssec scan --path ./repo` 讀取 `go.sum`、`package-lock.json`、`poetry.lock`，用同一套 OSV 和 EPSS 流程比對。
5. **CIS profile**：在 meta 加上 `cis: ["5.2.10"]` 對照，並支援 `--profile cis-l1`；JSON 規則包也能定義自己的 profile。
6. **SBOM / VEX**：用 `inventory --format cyclonedx` 輸出 SBOM，並匯入 OpenVEX 當成機器產生的 waiver。
7. **MCP server 模式**：`syssec mcp` 把同一棵指令樹開放成 MCP tools，schema 直接從 `describe` 產生。
8. **多主機彙整**：用 `report --export` 和 `merge` 匯總多台主機的報告，產生 fleet 走勢。
