package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildSummaryAndThreshold(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityLow},
	}
	s := BuildSummary(findings)
	if s.Total != 3 || s.Critical != 1 || s.High != 1 || s.Low != 1 {
		t.Fatalf("unexpected summary: %+v", s)
	}
	if !HasFindingsAtOrAbove(findings, SeverityHigh) {
		t.Fatal("expected high threshold hit")
	}
	if HasFindingsAtOrAbove(findings[:0], SeverityInfo) {
		t.Fatal("empty should not hit")
	}
}

func TestWriteJSON(t *testing.T) {
	r := NewReport(".", []Finding{{
		Rule: "aws-access-key", Category: CategorySecret,
		Severity: SeverityCritical, File: "a.env", Line: 1, Message: "test",
	}})
	var buf bytes.Buffer
	w := Writer{Out: &buf, Format: FormatJSON}
	if err := w.Write(r); err != nil {
		t.Fatal(err)
	}
	var parsed Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Summary.Critical != 1 {
		t.Fatalf("summary=%+v", parsed.Summary)
	}
}

func TestWriteSARIF(t *testing.T) {
	r := NewReport(".", []Finding{{
		Rule: "debug-enabled", Category: CategoryMisconfig,
		Severity: SeverityMedium, File: "c.json", Line: 2, Message: "debug on",
	}})
	var buf bytes.Buffer
	w := Writer{Out: &buf, Format: FormatSARIF}
	if err := w.Write(r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"version": "2.1.0"`) {
		t.Fatalf("not sarif: %s", buf.String())
	}
}
