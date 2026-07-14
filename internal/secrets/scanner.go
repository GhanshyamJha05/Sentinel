package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/GhanshyamJha05/Sentinel/internal/report"
	"github.com/GhanshyamJha05/Sentinel/internal/scanutil"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Options configures a secrets scan.
type Options struct {
	Path        string
	Workers     int
	Ignore      scanutil.IgnoreMatcher
	GitHistory  bool
	Rules       []Rule
	RespectGitIgnore bool
}

// Scan walks the filesystem (and optionally git history) for secrets.
func Scan(opts Options) ([]report.Finding, error) {
	if opts.Rules == nil {
		opts.Rules = DefaultRules()
	}

	info, err := os.Stat(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("secrets scan: %w", err)
	}

	var (
		mu       sync.Mutex
		findings []report.Finding
	)

	add := func(fs []report.Finding) {
		if len(fs) == 0 {
			return
		}
		mu.Lock()
		findings = append(findings, fs...)
		mu.Unlock()
	}

	if !info.IsDir() {
		lines, err := scanutil.ReadLines(opts.Path)
		if err != nil {
			return nil, err
		}
		rel := filepath.Base(opts.Path)
		for i, line := range lines {
			add(ScanLine(opts.Rules, rel, i+1, line))
		}
		return findings, nil
	}

	var gitIgnore scanutil.IgnoreMatcher
	if opts.RespectGitIgnore {
		gitIgnore = scanutil.LoadGitIgnorePatterns(opts.Path)
	}

	err = scanutil.WalkFiles(scanutil.WalkOptions{
		Root:            opts.Path,
		Workers:         opts.Workers,
		Ignore:          opts.Ignore,
		FollowGitIgnore: opts.RespectGitIgnore,
		GitIgnore:       gitIgnore,
	}, func(job scanutil.FileJob) error {
		data, err := os.ReadFile(job.AbsPath)
		if err != nil {
			return nil
		}
		if scanutil.IsBinary(data) {
			return nil
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			add(ScanLine(opts.Rules, job.RelPath, i+1, line))
		}
		return nil
	})
	if err != nil {
		return findings, err
	}

	if opts.GitHistory {
		hist, histErr := ScanGitHistory(opts.Path, opts.Rules, opts.Ignore)
		if histErr != nil && !strings.Contains(histErr.Error(), "repository does not exist") {
			return findings, histErr
		}
		add(hist)
	}

	return findings, nil
}

// ScanGitHistory walks commits looking for secrets in file contents at each revision.
func ScanGitHistory(repoPath string, rules []Rule, ignore scanutil.IgnoreMatcher) ([]report.Finding, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}
	iter, err := repo.Log(&git.LogOptions{})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	seen := map[string]struct{}{}
	var findings []report.Finding

	err = iter.ForEach(func(c *object.Commit) error {
		files, err := c.Files()
		if err != nil {
			return nil
		}
		return files.ForEach(func(f *object.File) error {
			name := filepath.ToSlash(f.Name)
			if ignore != nil && ignore.Match(name) {
				return nil
			}
			if f.Size > 1<<20 {
				return nil
			}
			content, err := f.Contents()
			if err != nil {
				return nil
			}
			if scanutil.IsBinary([]byte(content)) {
				return nil
			}
			lines := strings.Split(content, "\n")
			for i, line := range lines {
				for _, finding := range ScanLine(rules, name, i+1, line) {
					key := finding.ID + ":" + c.Hash.String()[:8]
					if _, ok := seen[finding.ID]; ok {
						continue
					}
					seen[finding.ID] = struct{}{}
					finding.Message = fmt.Sprintf("%s (found in git history @ %s)", finding.Message, c.Hash.String()[:8])
					finding.Metadata = map[string]string{
						"commit": c.Hash.String(),
						"source": "git-history",
					}
					_ = key
					findings = append(findings, finding)
				}
			}
			return nil
		})
	})
	return findings, err
}
