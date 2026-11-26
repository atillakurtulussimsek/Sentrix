package vuln

import "testing"

func TestCVSS3(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
	}
	for v, want := range cases {
		got, ok := CVSS3Score(v)
		if !ok || got != want {
			t.Errorf("%s = %v (%v), want %v", v, got, ok, want)
		}
	}
	if _, ok := CVSS3Score("AV:N/AC:L/Au:N/C:P/I:P/A:P"); ok {
		t.Error("v2 vector accepted")
	}
	if SeverityFromScore(9.8) != "critical" || SeverityFromScore(7.0) != "high" || SeverityFromScore(0) != "unknown" {
		t.Error("severity")
	}
	if NormalizeSeverity("Important") != "high" || NormalizeSeverity("unimportant") != "low" {
		t.Error("normalize")
	}
}
