package scanutil

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// MultiIgnore skips a path if any underlying matcher matches.
type MultiIgnore []IgnoreMatcher

// Match reports whether any matcher wants to skip relPath.
func (m MultiIgnore) Match(relPath string) bool {
	for _, ign := range m {
		if ign != nil && ign.Match(relPath) {
			return true
		}
	}
	return false
}

// AllowlistIgnore skips every path that is not in the allowlist (Match=true means skip).
type AllowlistIgnore struct {
	allowed map[string]struct{}
}

// NewAllowlistIgnore builds an allowlist from relative paths.
func NewAllowlistIgnore(paths []string) *AllowlistIgnore {
	a := &AllowlistIgnore{allowed: make(map[string]struct{}, len(paths))}
	for _, p := range paths {
		p = filepath.ToSlash(strings.TrimSpace(p))
		if p == "" || p == "." {
			continue
		}
		a.allowed[p] = struct{}{}
	}
	return a
}

// Match returns true when the path should be skipped (not in allowlist).
func (a *AllowlistIgnore) Match(relPath string) bool {
	if a == nil || len(a.allowed) == 0 {
		return false
	}
	relPath = filepath.ToSlash(relPath)
	isDir := strings.HasSuffix(relPath, "/")
	clean := strings.TrimSuffix(relPath, "/")
	if _, ok := a.allowed[clean]; ok {
		return false
	}
	for p := range a.allowed {
		if isDir {
			// Keep walking directories that contain an allowed file.
			if p == clean || strings.HasPrefix(p, clean+"/") {
				return false
			}
			continue
		}
		if strings.HasPrefix(relPath, p+"/") {
			return false
		}
	}
	return true
}

// CombineIgnore returns base, or base∪allowlist when onlyFiles is non-empty.
func CombineIgnore(base IgnoreMatcher, onlyFiles []string) IgnoreMatcher {
	if len(onlyFiles) == 0 {
		return base
	}
	return MultiIgnore{base, NewAllowlistIgnore(onlyFiles)}
}

// GitDiffFiles lists paths changed between baseRef and HEAD (ACMR only).
// baseRef examples: "origin/main", "HEAD~1", "main".
func GitDiffFiles(repoRoot, baseRef string) ([]string, error) {
	baseRef = strings.TrimSpace(baseRef)
	if baseRef == "" {
		return nil, fmt.Errorf("empty git diff base ref")
	}

	// Prefer three-dot merge-base style for PRs: base...HEAD
	out, err := runGit(repoRoot, "diff", "--name-only", "--diff-filter=ACMR", baseRef+"...HEAD")
	if err != nil {
		// Fall back to two-dot if base ref has no merge-base with HEAD.
		out, err = runGit(repoRoot, "diff", "--name-only", "--diff-filter=ACMR", baseRef, "HEAD")
		if err != nil {
			return nil, fmt.Errorf("git diff %s: %w", baseRef, err)
		}
	}

	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		files = append(files, filepath.ToSlash(line))
	}
	return files, nil
}

// ManifestTouched reports whether any dependency-manifest path appears in files.
func ManifestTouched(files []string) bool {
	for _, f := range files {
		base := filepath.Base(f)
		switch base {
		case "go.mod", "go.sum", "package.json", "package-lock.json", "yarn.lock",
			"pnpm-lock.yaml", "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock":
			return true
		}
	}
	return false
}

func runGit(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return out, nil
}
