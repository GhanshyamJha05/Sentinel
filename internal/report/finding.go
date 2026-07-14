package report

import "time"

// Severity levels used across all scanners.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Rank returns a numeric rank for severity comparisons (higher = worse).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// ParseSeverity converts a string to Severity (case-insensitive).
func ParseSeverity(s string) Severity {
	switch Severity(toUpper(s)) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	case SeverityInfo:
		return SeverityInfo
	default:
		return SeverityHigh
	}
}

func toUpper(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// Category identifies which scanner produced a finding.
type Category string

const (
	CategorySecret     Category = "secret"
	CategoryDependency Category = "dependency"
	CategoryMisconfig  Category = "misconfiguration"
)

// Finding is a single security finding from any scanner module.
type Finding struct {
	ID          string            `json:"id"`
	Category    Category          `json:"category"`
	Rule        string            `json:"rule"`
	Severity    Severity          `json:"severity"`
	Confidence  float64           `json:"confidence,omitempty"`
	File        string            `json:"file"`
	Line        int               `json:"line,omitempty"`
	Column      int               `json:"column,omitempty"`
	Message     string            `json:"message"`
	Snippet     string            `json:"snippet,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Report aggregates findings from one or more scanners.
type Report struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	ScannedAt time.Time `json:"scanned_at"`
	Target    string    `json:"target"`
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
}

// Summary counts findings by severity.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// BuildSummary computes Summary from findings.
func BuildSummary(findings []Finding) Summary {
	s := Summary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
	}
	return s
}

// HasFindingsAtOrAbove returns true if any finding meets or exceeds the threshold.
func HasFindingsAtOrAbove(findings []Finding, threshold Severity) bool {
	min := threshold.Rank()
	for _, f := range findings {
		if f.Severity.Rank() >= min {
			return true
		}
	}
	return false
}
