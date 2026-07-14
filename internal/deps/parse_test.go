package deps

import (
	"path/filepath"
	"testing"
)

func TestParseGoMod(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "deps", "go.mod")
	pkgs, err := parseGoMod(path, "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) < 2 {
		t.Fatalf("expected >=2 packages, got %d", len(pkgs))
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "github.com/gin-gonic/gin" && p.Version == "1.6.3" {
			found = true
		}
	}
	if !found {
		t.Fatal("gin-gonic/gin@1.6.3 not found")
	}
}

func TestParsePackageJSON(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "deps", "package.json")
	pkgs, err := parsePackageJSON(path, "package.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
}

func TestParseRequirements(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "deps", "requirements.txt")
	pkgs, err := parseRequirements(path, "requirements.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}
	for _, p := range pkgs {
		if p.Name == "django" && p.Version != "2.2.0" {
			t.Fatalf("django version = %s", p.Version)
		}
	}
}

func TestCleanNPMVersion(t *testing.T) {
	cases := map[string]string{
		"^4.17.20": "4.17.20",
		"~1.2.5":   "1.2.5",
		">=1.0.0":  "1.0.0",
	}
	for in, want := range cases {
		if got := cleanNPMVersion(in); got != want {
			t.Errorf("cleanNPMVersion(%q)=%q want %q", in, got, want)
		}
	}
}
