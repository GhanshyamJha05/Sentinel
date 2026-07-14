package misconfig

import (
	"path/filepath"
	"testing"
)

func TestTerraformIaCChecks(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "misconfig")
	findings, err := Scan(Options{Path: root})
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{}
	for _, f := range findings {
		rules[f.Rule] = true
	}
	for _, want := range []string{"terraform-public-expose", "terraform-hardcoded-secret"} {
		if !rules[want] {
			t.Fatalf("expected rule %s; got %v", want, rules)
		}
	}
}
