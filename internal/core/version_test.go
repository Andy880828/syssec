package core

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.27.3", "1.27.1", 1},
		{"1.26.10", "1.27.1", -1},
		{"1.26.10", "1.26.9", 1}, // 數字段要依數值比，不能依字典序
		{"v0.44.0", "0.36.0", 1},
		{"1.27.0-0", "1.27.0", -1}, // Go 公告的 introduced 寫法，pre-release 較小
		{"1.2", "1.2.1", -1},
		{"1.1.0-2ubuntu0.1", "1.1.0-2build2", 1},
		{"2.0", "2.0", 0},
		// kernel release 字串（SYS-007 用）
		{"6.8.0-47-generic", "6.8.0-100-generic", -1},
		{"5.15.0-1", "6.1.0-1", -1},
		{"6.10.3-200.fc40.x86_64", "6.10.10-200.fc40.x86_64", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("CompareVersions(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}
