package controlplane

import (
	"testing"
	"time"
)

func TestValidTOTPFromRFC6238(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	// RFC 6238 SHA-1 test at 59 seconds is 94287082; the six-digit profile keeps the suffix.
	if !validTOTP(secret, "287082", time.Unix(59, 0)) {
		t.Fatal("expected RFC vector to validate")
	}
	if validTOTP(secret, "287083", time.Unix(59, 0)) {
		t.Fatal("expected an incorrect code to fail")
	}
}
