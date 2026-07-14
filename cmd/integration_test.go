package cmd_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCLIHelp(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("help failed: %v\n%s", err, out)
	}
	s := string(out)
	for _, want := range []string{"scan", "secrets", "Available Commands"} {
		if !strings.Contains(s, want) {
			t.Fatalf("help missing %q:\n%s", want, s)
		}
	}
}

func TestIntegrationSecretsFixture(t *testing.T) {
	bin := buildBinary(t)
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata", "secrets")
	cmd := exec.Command(bin, "scan", "secrets", fixture, "--format", "json", "--fail-on", "none", "--no-color")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scan secrets: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), `"category": "secret"`) && !strings.Contains(string(out), `"category":"secret"`) {
		t.Fatalf("expected secret findings:\n%s", out)
	}
}

func TestIntegrationMisconfigFixture(t *testing.T) {
	bin := buildBinary(t)
	root := repoRoot(t)
	fixture := filepath.Join(root, "testdata", "misconfig")
	cmd := exec.Command(bin, "scan", "config", fixture, "--format", "json", "--fail-on", "none", "--no-color")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scan config: %v\n%s", err, out)
	}
	s := string(out)
	for _, rule := range []string{"env-file-exposed", "debug-enabled", "default-credentials"} {
		if !strings.Contains(s, rule) {
			t.Fatalf("expected rule %s in output:\n%s", rule, s)
		}
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	name := "sentinel-test"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = root
	cmd.Env = os.Environ()
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}
