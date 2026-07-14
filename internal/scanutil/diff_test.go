package scanutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllowlistIgnoreKeepsParentDirs(t *testing.T) {
	a := NewAllowlistIgnore([]string{"cmd/scan.go", "internal/deps/scanner.go"})
	if a.Match("cmd/") {
		t.Fatal("should not skip parent dir cmd/")
	}
	if a.Match("cmd/scan.go") {
		t.Fatal("should not skip allowed file")
	}
	if !a.Match("README.md") {
		t.Fatal("should skip unrelated file")
	}
	if !a.Match("pkg/") {
		t.Fatal("should skip unrelated dir")
	}
}

func TestCombineIgnore(t *testing.T) {
	base := NewGlobIgnore([]string{"*.tmp"})
	ign := CombineIgnore(base, []string{"a.go"})
	if !ign.Match("b.go") {
		t.Fatal("expected b.go skipped by allowlist")
	}
	if ign.Match("a.go") {
		t.Fatal("a.go should be scanned")
	}
	if !ign.Match("x.tmp") {
		t.Fatal("*.tmp should still be ignored")
	}
}

func TestManifestTouched(t *testing.T) {
	if !ManifestTouched([]string{"src/main.go", "go.mod"}) {
		t.Fatal("expected go.mod touch")
	}
	if ManifestTouched([]string{"src/main.go", "README.md"}) {
		t.Fatal("no manifests")
	}
}

func TestGitDiffFilesSmoke(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Skip("not a git checkout")
	}
	files, err := GitDiffFiles(root, "HEAD~1")
	if err != nil {
		// shallow clone / single commit
		t.Skip(err)
	}
	_ = files
}
