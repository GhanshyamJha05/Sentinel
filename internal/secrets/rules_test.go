package secrets

import (
	"strings"
	"testing"
)

func TestScanLine_AWSAccessKey(t *testing.T) {
	rules := DefaultRules()
	// Official AWS docs example key, assembled at runtime for scanner hygiene.
	akid := "AKIA" + "IOSFODNN7EXAMPLE"
	line := "AWS_ACCESS_KEY_ID=" + akid
	findings := ScanLine(rules, "test.env", 1, line)
	if len(findings) == 0 {
		t.Fatal("expected AWS access key finding")
	}
	found := false
	for _, f := range findings {
		if f.Rule == "aws-access-key" {
			found = true
			if !strings.Contains(f.Snippet, "****") && !strings.Contains(f.Snippet, "*") {
				t.Errorf("snippet should be redacted: %q", f.Snippet)
			}
		}
	}
	if !found {
		t.Fatal("aws-access-key rule not matched")
	}
}

func TestScanLine_PrivateKey(t *testing.T) {
	rules := DefaultRules()
	line := "-----BEGIN RSA " + "PRIVATE KEY-----"
	findings := ScanLine(rules, "key.pem", 1, line)
	if len(findings) == 0 {
		t.Fatal("expected private key finding")
	}
}

func TestScanLine_SlackToken(t *testing.T) {
	// Build at runtime so the full token never appears in the repository (push protection).
	rules := DefaultRules()
	token := "xox" + "b-" + "000000000000-" + "TESTONLYFAKESECRETXX"
	line := "token=" + token
	findings := ScanLine(rules, "cfg", 3, line)
	found := false
	for _, f := range findings {
		if f.Rule == "slack-token" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected slack-token finding")
	}
}

func TestScanLine_StripeKey(t *testing.T) {
	rules := DefaultRules()
	key := "sk_" + "test_" + "000000000000000000000001"
	line := "STRIPE_KEY=" + key
	findings := ScanLine(rules, "cfg", 1, line)
	found := false
	for _, f := range findings {
		if f.Rule == "stripe-key" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected stripe-key finding")
	}
}

func TestShannonEntropy(t *testing.T) {
	low := ShannonEntropy("aaaaaaaaaaaaaaaa")
	high := ShannonEntropy("a8f5f167f44f4964e6c998dee827110c")
	if low >= high {
		t.Fatalf("expected high entropy > low: low=%f high=%f", low, high)
	}
}

func TestRedact(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	line := "key=" + secret
	out := Redact(line, secret)
	if strings.Contains(out, secret) {
		t.Fatalf("secret still present: %q", out)
	}
	if !strings.Contains(out, "AKIA") {
		t.Fatalf("expected prefix preserved: %q", out)
	}
}

func TestScanFileFixture(t *testing.T) {
	findings, err := Scan(Options{Path: "../../testdata/secrets/leaked.env"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 5 {
		t.Fatalf("expected at least 5 findings from fixture, got %d", len(findings))
	}
}
