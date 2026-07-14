package scanutil

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// DefaultSkipDirs are directories ignored during filesystem walks.
var DefaultSkipDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"vendor":       {},
	".venv":        {},
	"venv":         {},
	"__pycache__":  {},
	".tox":         {},
	"dist":         {},
	"build":        {},
	".next":        {},
	"target":       {},
	".cache":       {},
}

// IgnoreMatcher decides whether a relative path should be skipped.
type IgnoreMatcher interface {
	Match(relPath string) bool
}

// FileJob is a file discovered during a walk.
type FileJob struct {
	AbsPath string
	RelPath string
	Info    fs.FileInfo
}

// WalkOptions configures concurrent directory walking.
type WalkOptions struct {
	Root            string
	Workers         int
	SkipDirs        map[string]struct{}
	Ignore          IgnoreMatcher
	FollowGitIgnore bool
	GitIgnore       IgnoreMatcher
	MaxFileSize     int64 // skip files larger than this (0 = no limit)
}

// WalkFiles walks root concurrently and invokes handler for each regular file.
func WalkFiles(opts WalkOptions, handler func(FileJob) error) error {
	if opts.Workers <= 0 {
		opts.Workers = runtime.NumCPU()
	}
	if opts.SkipDirs == nil {
		opts.SkipDirs = DefaultSkipDirs
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 2 << 20 // 2 MiB
	}

	jobs := make(chan FileJob, opts.Workers*4)
	errCh := make(chan error, 1)
	var wg sync.WaitGroup

	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if err := handler(job); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}()
	}

	walkErr := filepath.WalkDir(opts.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		select {
		case walkErr := <-errCh:
			return walkErr
		default:
		}

		name := d.Name()
		rel, relErr := filepath.Rel(opts.Root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if _, skip := opts.SkipDirs[name]; skip && path != opts.Root {
				return filepath.SkipDir
			}
			if opts.Ignore != nil && opts.Ignore.Match(rel+"/") {
				return filepath.SkipDir
			}
			if opts.FollowGitIgnore && opts.GitIgnore != nil && opts.GitIgnore.Match(rel+"/") {
				return filepath.SkipDir
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}
		if opts.Ignore != nil && opts.Ignore.Match(rel) {
			return nil
		}
		if opts.FollowGitIgnore && opts.GitIgnore != nil && opts.GitIgnore.Match(rel) {
			return nil
		}

		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
			return nil
		}

		select {
		case jobs <- FileJob{AbsPath: path, RelPath: rel, Info: info}:
		case walkErr := <-errCh:
			return walkErr
		}
		return nil
	})

	close(jobs)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return walkErr
	}
}

// ReadLines reads a text file into lines.
func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// IsBinary reports whether content looks binary.
func IsBinary(data []byte) bool {
	n := len(data)
	if n > 8000 {
		n = 8000
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

// LoadGitIgnorePatterns loads basic .gitignore patterns from a repo root.
func LoadGitIgnorePatterns(root string) IgnoreMatcher {
	path := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var patterns []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return NewGlobIgnore(patterns)
}
