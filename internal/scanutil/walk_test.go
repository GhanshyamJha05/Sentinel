package scanutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGlobIgnore(t *testing.T) {
	g := NewGlobIgnore([]string{"testdata/", "*.pem", "!keep.pem"})
	if !g.Match("testdata/secrets/x") {
		t.Fatal("expected testdata match")
	}
	if !g.Match("key.pem") {
		t.Fatal("expected *.pem match")
	}
}

func TestWalkFilesSkipsDirs(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "node_modules", "x"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "node_modules", "x", "a.js"), []byte("secret"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "ok.go"), []byte("package ok"), 0o644)

	var seen []string
	err := WalkFiles(WalkOptions{Root: dir, Workers: 2}, func(job FileJob) error {
		seen = append(seen, job.RelPath)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range seen {
		if filepath.ToSlash(s) == "node_modules/x/a.js" {
			t.Fatal("node_modules should be skipped")
		}
	}
	if len(seen) != 1 {
		t.Fatalf("seen=%v", seen)
	}
}
