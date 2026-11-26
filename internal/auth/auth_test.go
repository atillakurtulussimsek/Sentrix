package auth

import (
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPassword(h, "correct horse battery") != nil {
		t.Fatal("verify failed")
	}
	if VerifyPassword(h, "wrong") == nil {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
	if ValidatePassword("short") == nil || ValidatePassword("long enough pw") != nil {
		t.Fatal("policy")
	}
}

func TestTOTPRFC6238(t *testing.T) {
	// RFC 6238 Appendix B, SHA1 secret "12345678901234567890"
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range cases {
		got, err := TOTPCode(secret, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Errorf("t=%d got %s want %s (%v)", ts, got, want, err)
		}
	}
	if !VerifyTOTP(secret, "287082", time.Unix(59+25, 0)) || VerifyTOTP(secret, "287082", time.Unix(59+120, 0)) {
		t.Fatal("window")
	}
}

func TestSecretBox(t *testing.T) {
	k, err := LoadOrCreateKey(t.TempDir() + "/k")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSecretBox(k)
	s, _ := b.Seal("bot-token")
	if s == "bot-token" {
		t.Fatal("not sealed")
	}
	p, err := b.Open(s)
	if err != nil || p != "bot-token" {
		t.Fatal(err)
	}
	other, _ := NewSecretBox(make([]byte, 32))
	if _, err := other.Open(s); err == nil {
		t.Fatal("wrong key opened")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		l.Fail("ip")
	}
	if l.Allowed("ip") {
		t.Fatal("should block")
	}
	now = now.Add(2 * time.Minute)
	if !l.Allowed("ip") {
		t.Fatal("should reset after window")
	}
}
