package secrets

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/GhanshyamJha05/Sentinel/internal/report"
)

// Rule is a regex-based secret detector.
type Rule struct {
	ID          string
	Description string
	Severity    report.Severity
	Pattern     *regexp.Regexp
	EntropyMin  float64 // if >0, matched capture must meet this entropy
	Confidence  float64
}

// DefaultRules returns built-in secret detection rules.
func DefaultRules() []Rule {
	return []Rule{
		{
			ID:          "aws-access-key",
			Description: "AWS Access Key ID",
			Severity:    report.SeverityCritical,
			Pattern:     regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
			Confidence:  0.95,
		},
		{
			ID:          "aws-secret-key",
			Description: "AWS Secret Access Key",
			Severity:    report.SeverityCritical,
			Pattern:     regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?`),
			EntropyMin:  3.5,
			Confidence:  0.85,
		},
		{
			ID:          "gcp-api-key",
			Description: "Google Cloud API Key",
			Severity:    report.SeverityHigh,
			Pattern:     regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`),
			Confidence:  0.9,
		},
		{
			ID:          "slack-token",
			Description: "Slack token",
			Severity:    report.SeverityHigh,
			Pattern:     regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z\-]{10,72})\b`),
			Confidence:  0.95,
		},
		{
			ID:          "github-token",
			Description: "GitHub personal access token",
			Severity:    report.SeverityCritical,
			Pattern:     regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b`),
			Confidence:  0.95,
		},
		{
			ID:          "generic-api-key",
			Description: "Generic API key assignment",
			Severity:    report.SeverityMedium,
			Pattern:     regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api_secret|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]`),
			EntropyMin:  3.2,
			Confidence:  0.7,
		},
		{
			ID:          "private-key",
			Description: "PEM private key header",
			Severity:    report.SeverityCritical,
			Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
			Confidence:  1.0,
		},
		{
			ID:          "jwt",
			Description: "JSON Web Token",
			Severity:    report.SeverityMedium,
			Pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
			EntropyMin:  3.0,
			Confidence:  0.8,
		},
		{
			ID:          "stripe-key",
			Description: "Stripe API key",
			Severity:    report.SeverityCritical,
			Pattern:     regexp.MustCompile(`\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b`),
			Confidence:  0.95,
		},
		{
			ID:          "high-entropy-string",
			Description: "High-entropy string that may be a secret",
			Severity:    report.SeverityLow,
			Pattern:     regexp.MustCompile(`(?i)(?:password|passwd|secret|token|credential)\s*[=:]\s*['\"]([^'\"]{20,})['\"]`),
			EntropyMin:  4.0,
			Confidence:  0.55,
		},
	}
}

// ScanLine runs all rules against a single line of text.
func ScanLine(rules []Rule, file string, lineNum int, line string) []report.Finding {
	var findings []report.Finding
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		// still scan comments — secrets often hide in comments; only skip empty
	}
	if strings.TrimSpace(line) == "" {
		return nil
	}

	for _, rule := range rules {
		matches := rule.Pattern.FindAllStringSubmatchIndex(line, -1)
		for _, idx := range matches {
			secret := line[idx[0]:idx[1]]
			if len(idx) >= 4 && idx[2] >= 0 {
				secret = line[idx[2]:idx[3]]
			}
			if rule.EntropyMin > 0 {
				ent := ShannonEntropy(secret)
				if ent < rule.EntropyMin {
					continue
				}
			}
			confidence := rule.Confidence
			if rule.EntropyMin > 0 {
				ent := ShannonEntropy(secret)
				confidence = math.Min(1.0, confidence+((ent-rule.EntropyMin)*0.05))
			}
			findings = append(findings, report.Finding{
				ID:         fmt.Sprintf("%s:%d:%s", file, lineNum, rule.ID),
				Category:   report.CategorySecret,
				Rule:       rule.ID,
				Severity:   rule.Severity,
				Confidence: confidence,
				File:       file,
				Line:       lineNum,
				Column:     idx[0] + 1,
				Message:    rule.Description,
				Snippet:    Redact(line, secret),
				Remediation: "Remove the secret, rotate credentials, and add the path to .sentinelignore if this is a false positive.",
			})
		}
	}
	return findings
}

// ShannonEntropy computes Shannon entropy of a string (bits per character).
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}
	var ent float64
	for _, c := range freq {
		p := float64(c) / float64(total)
		ent -= p * math.Log2(p)
	}
	return ent
}

// Redact replaces the secret portion of a line with a masked preview.
func Redact(line, secret string) string {
	masked := maskSecret(secret)
	return strings.Replace(line, secret, masked, 1)
}

func maskSecret(s string) string {
	r := []rune(s)
	n := utf8.RuneCountInString(s)
	if n <= 8 {
		return "********"
	}
	prefix := string(r[:4])
	suffix := string(r[n-4:])
	return prefix + strings.Repeat("*", n-8) + suffix
}
