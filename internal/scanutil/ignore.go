package scanutil

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// GlobIgnore matches paths against simple gitignore-like patterns.
type GlobIgnore struct {
	patterns []string
}

// NewGlobIgnore creates an IgnoreMatcher from patterns.
func NewGlobIgnore(patterns []string) *GlobIgnore {
	cleaned := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		cleaned = append(cleaned, filepath.ToSlash(p))
	}
	return &GlobIgnore{patterns: cleaned}
}

// LoadSentinelIgnore loads .sentinelignore from root (plus optional extra).
func LoadSentinelIgnore(root string, extraPatterns []string) *GlobIgnore {
	patterns := append([]string{}, extraPatterns...)
	path := filepath.Join(root, ".sentinelignore")
	f, err := os.Open(path)
	if err == nil {
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			patterns = append(patterns, line)
		}
	}
	return NewGlobIgnore(patterns)
}

// Match reports whether relPath matches any ignore pattern.
func (g *GlobIgnore) Match(relPath string) bool {
	if g == nil {
		return false
	}
	relPath = filepath.ToSlash(relPath)
	base := filepath.Base(relPath)
	for _, pat := range g.patterns {
		neg := false
		if strings.HasPrefix(pat, "!") {
			neg = true
			pat = pat[1:]
		}
		matched := matchOne(pat, relPath, base)
		if matched {
			return !neg
		}
	}
	return false
}

func matchOne(pat, path, base string) bool {
	pat = strings.TrimPrefix(pat, "/")
	if strings.HasSuffix(pat, "/") {
		dir := strings.TrimSuffix(pat, "/")
		return path == dir || strings.HasPrefix(path, dir+"/")
	}
	if strings.Contains(pat, "/") {
		ok, _ := filepath.Match(pat, path)
		if ok {
			return true
		}
		// prefix directory match: "testdata/**"
		if strings.HasSuffix(pat, "/**") {
			prefix := strings.TrimSuffix(pat, "/**")
			return path == prefix || strings.HasPrefix(path, prefix+"/")
		}
		return false
	}
	ok, _ := filepath.Match(pat, base)
	if ok {
		return true
	}
	ok, _ = filepath.Match(pat, path)
	return ok
}
