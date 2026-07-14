package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/GhanshyamJha05/Sentinel/pkg/version"
)

// Format is an output format name.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// Writer renders a Report.
type Writer struct {
	Out    io.Writer
	Format Format
	NoColor bool
}

// Write renders the report in the configured format.
func (w Writer) Write(r Report) error {
	if r.Tool == "" {
		r.Tool = "sentinel"
	}
	if r.Version == "" {
		r.Version = version.Version
	}
	if r.ScannedAt.IsZero() {
		r.ScannedAt = time.Now().UTC()
	}
	r.Summary = BuildSummary(r.Findings)

	switch w.Format {
	case FormatJSON:
		return writeJSON(w.Out, r)
	case FormatSARIF:
		return writeSARIF(w.Out, r)
	default:
		return writeTable(w.Out, r, w.NoColor)
	}
}

func writeJSON(out io.Writer, r Report) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeTable(out io.Writer, r Report, noColor bool) error {
	if noColor {
		color.NoColor = true
	}

	crit := color.New(color.FgRed, color.Bold).SprintFunc()
	high := color.New(color.FgHiRed).SprintFunc()
	med := color.New(color.FgYellow).SprintFunc()
	low := color.New(color.FgCyan).SprintFunc()
	info := color.New(color.FgBlue).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()
	dim := color.New(color.FgHiBlack).SprintFunc()

	colorize := func(s Severity) string {
		label := string(s)
		switch s {
		case SeverityCritical:
			return crit(label)
		case SeverityHigh:
			return high(label)
		case SeverityMedium:
			return med(label)
		case SeverityLow:
			return low(label)
		default:
			return info(label)
		}
	}

	fmt.Fprintf(out, "%s\n", bold("sentinel security scan"))
	fmt.Fprintf(out, "%s\n\n", dim(fmt.Sprintf("target=%s  findings=%d  at=%s", r.Target, r.Summary.Total, r.ScannedAt.Format(time.RFC3339))))

	if len(r.Findings) == 0 {
		fmt.Fprintf(out, "%s\n", color.GreenString("No findings."))
		return nil
	}

	for i, f := range r.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(out, "%s  %s  %s  [%s]\n", colorize(f.Severity), bold(f.Rule), loc, f.Category)
		fmt.Fprintf(out, "  %s\n", f.Message)
		if f.Snippet != "" {
			fmt.Fprintf(out, "  %s %s\n", dim("snippet:"), f.Snippet)
		}
		if f.Remediation != "" {
			fmt.Fprintf(out, "  %s %s\n", dim("fix:"), f.Remediation)
		}
		if i < len(r.Findings)-1 {
			fmt.Fprintln(out)
		}
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s  critical=%d high=%d medium=%d low=%d info=%d\n",
		bold("summary"), r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info)
	return nil
}

// NewReport creates a report shell for a target.
func NewReport(target string, findings []Finding) Report {
	return Report{
		Tool:      "sentinel",
		Version:   version.Version,
		ScannedAt: time.Now().UTC(),
		Target:    target,
		Findings:  findings,
		Summary:   BuildSummary(findings),
	}
}

// ParseFormat parses a format string.
func ParseFormat(s string) Format {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return FormatJSON
	case "sarif":
		return FormatSARIF
	default:
		return FormatTable
	}
}
