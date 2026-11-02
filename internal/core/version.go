package core

import "strings"

// CompareVersions 是跨生態系的啟發式版本比較，也是全專案唯一的版本比較實作。
// 把字串切成數字段與非數字段，數字段依數值比、非數字段依字典序比。一方是另一方的前綴時，剩餘部分以
// "-" 或 "~" 開頭視為 pre-release（較小），否則較大。
// 用於挑選公告內的修補版本、比較 kernel release 等；不是完整的 semver／dpkg／rpm 實作。
func CompareVersions(a, b string) int {
	ta, tb := versionTokens(strings.TrimPrefix(a, "v")), versionTokens(strings.TrimPrefix(b, "v"))
	for i := range min(len(ta), len(tb)) {
		if c := compareToken(ta[i], tb[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(ta) == len(tb):
		return 0
	case len(ta) > len(tb):
		return tailSign(ta[len(tb)])
	default:
		return -tailSign(tb[len(ta)])
	}
}

// tailSign 判斷較長版本多出來的部分讓它變大（1.2.1 > 1.2）還是變小（1.2-rc1 < 1.2）。
func tailSign(tok string) int {
	if strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "~") {
		return -1
	}
	return 1
}

func versionTokens(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		j := i
		digit := isDigit(s[i])
		for j < len(s) && isDigit(s[j]) == digit {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	return out
}

func compareToken(a, b string) int {
	if isDigit(a[0]) && isDigit(b[0]) {
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if len(a) != len(b) {
			return len(a) - len(b) // 長度先比，避免超長數字溢位
		}
	}
	return strings.Compare(a, b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
