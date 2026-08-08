package controlplane

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseDomainsSkipsIsolatedInvalidLines(t *testing.T) {
	input := "valid.example\na_1.bxfilm10.art\nvalid.example\nsecond.example.\n"
	domains, err := parseDomains(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || domains[0] != "valid.example" || domains[1] != "second.example" {
		t.Fatalf("unexpected domains: %#v", domains)
	}
}

func TestParseDomainsRejectsMostlyInvalidFeed(t *testing.T) {
	var input strings.Builder
	input.WriteString("valid.example\n")
	for i := 0; i < 7; i++ {
		fmt.Fprintf(&input, "bad_%d.example\n", i)
	}
	if _, err := parseDomains(strings.NewReader(input.String())); err == nil {
		t.Fatal("mostly invalid feed was accepted")
	}
}
