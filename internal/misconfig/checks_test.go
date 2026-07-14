package misconfig

import (
	"path/filepath"
	"testing"

	"github.com/GhanshyamJha05/Sentinel/internal/report"
)

func TestMisconfigFixture_MultipleTypes(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "misconfig")
	findings, err := Scan(Options{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{}
	for _, f := range findings {
		rules[f.Rule] = true
		if f.Category != report.CategoryMisconfig {
			t.Errorf("unexpected category %s", f.Category)
		}
	}
	want := []string{"env-file-exposed", "debug-enabled", "default-credentials", "missing-security-headers"}
	for _, id := range want {
		if !rules[id] {
			t.Errorf("expected finding for rule %s; got rules=%v findings=%d", id, rules, len(findings))
		}
	}
	if len(rules) < 3 {
		t.Fatalf("expected at least 3 distinct misconfig types, got %d", len(rules))
	}
}
