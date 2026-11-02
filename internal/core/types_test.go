package core

import "testing"

// 回歸：非 root 讀不到 sshd_config 時 SSH 檢查變 error，舊計分把它排除在分母外，分數反而升到 100。
func TestSummarizeErrorEarnsNoCredit(t *testing.T) {
	high := func(s Status) Result { return Result{ID: "X", Severity: SeverityHigh, Status: s} }
	pass := high(StatusPass)
	cases := []struct {
		name    string
		results []Result
		want    int
	}{
		{"all pass", []Result{pass, pass}, 100},
		{"one fail", []Result{pass, high(StatusFail)}, 50},
		{"one error scores like fail", []Result{pass, high(StatusError)}, 50},
		{"skip excluded", []Result{pass, high(StatusSkip)}, 100},
		{"waived excluded", []Result{pass, high(StatusWaived)}, 100},
		{"only errors", []Result{high(StatusError)}, 0},
	}
	for _, c := range cases {
		if got := Summarize(c.results, 0, nil).Score; got != c.want {
			t.Errorf("%s: score %d, want %d", c.name, got, c.want)
		}
	}
	// error 不計入 failed_by_severity：那是「確認不合規」的計數
	if s := Summarize([]Result{high(StatusError)}, 0, nil); len(s.Failed) != 0 || s.Status["error"] != 1 {
		t.Errorf("error counted as failure: %+v", s)
	}
}
