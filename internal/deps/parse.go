package deps

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GhanshyamJha05/Sentinel/internal/scanutil"
)

// Ecosystem identifies the package ecosystem for OSV.
type Ecosystem string

const (
	EcosystemGo     Ecosystem = "Go"
	EcosystemNPM    Ecosystem = "npm"
	EcosystemPyPI   Ecosystem = "PyPI"
)

// Package is a discovered dependency.
type Package struct {
	Name      string
	Version   string
	Ecosystem Ecosystem
	Manifest  string
}

// ParseManifests discovers and parses dependency manifests under root.
func ParseManifests(root string, ignore scanutil.IgnoreMatcher) ([]Package, error) {
	var pkgs []Package
	seen := map[string]struct{}{}

	add := func(p Package) {
		key := string(p.Ecosystem) + "|" + p.Name + "|" + p.Version
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, p)
	}

	err := scanutil.WalkFiles(scanutil.WalkOptions{
		Root:   root,
		Ignore: ignore,
	}, func(job scanutil.FileJob) error {
		base := filepath.Base(job.AbsPath)
		switch base {
		case "go.mod":
			parsed, err := parseGoMod(job.AbsPath, job.RelPath)
			if err == nil {
				for _, p := range parsed {
					add(p)
				}
			}
		case "package.json":
			parsed, err := parsePackageJSON(job.AbsPath, job.RelPath)
			if err == nil {
				for _, p := range parsed {
					add(p)
				}
			}
		case "package-lock.json":
			parsed, err := parsePackageLock(job.AbsPath, job.RelPath)
			if err == nil {
				for _, p := range parsed {
					add(p)
				}
			}
		case "requirements.txt":
			parsed, err := parseRequirements(job.AbsPath, job.RelPath)
			if err == nil {
				for _, p := range parsed {
					add(p)
				}
			}
		}
		return nil
	})
	return pkgs, err
}

func parseGoMod(path, rel string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	sc := bufio.NewScanner(f)
	inRequire := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "//") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			fields := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(fields) >= 2 {
				pkgs = append(pkgs, Package{
					Name: fields[0], Version: cleanVersion(fields[1]),
					Ecosystem: EcosystemGo, Manifest: rel,
				})
			}
			continue
		}
		if inRequire {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pkgs = append(pkgs, Package{
					Name: fields[0], Version: cleanVersion(fields[1]),
					Ecosystem: EcosystemGo, Manifest: rel,
				})
			}
		}
	}
	return pkgs, sc.Err()
}

func parsePackageJSON(path, rel string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var pkgs []Package
	for name, ver := range doc.Dependencies {
		pkgs = append(pkgs, Package{
			Name: name, Version: cleanNPMVersion(ver),
			Ecosystem: EcosystemNPM, Manifest: rel,
		})
	}
	for name, ver := range doc.DevDependencies {
		pkgs = append(pkgs, Package{
			Name: name, Version: cleanNPMVersion(ver),
			Ecosystem: EcosystemNPM, Manifest: rel,
		})
	}
	return pkgs, nil
}

func parsePackageLock(path, rel string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var pkgs []Package
	if len(doc.Packages) > 0 {
		for key, p := range doc.Packages {
			if key == "" || p.Version == "" {
				continue
			}
			name := strings.TrimPrefix(key, "node_modules/")
			if name == "" || strings.Contains(name, "node_modules/") {
				continue
			}
			pkgs = append(pkgs, Package{
				Name: name, Version: p.Version,
				Ecosystem: EcosystemNPM, Manifest: rel,
			})
		}
		return pkgs, nil
	}
	for name, p := range doc.Dependencies {
		pkgs = append(pkgs, Package{
			Name: name, Version: p.Version,
			Ecosystem: EcosystemNPM, Manifest: rel,
		})
	}
	return pkgs, nil
}

func parseRequirements(path, rel string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		line = strings.Split(line, "#")[0]
		line = strings.TrimSpace(line)
		name, ver := splitRequirement(line)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name: name, Version: ver,
			Ecosystem: EcosystemPyPI, Manifest: rel,
		})
	}
	return pkgs, sc.Err()
}

func splitRequirement(line string) (string, string) {
	for _, sep := range []string{"===", "==", ">=", "<=", "~=", "!=", ">", "<"} {
		if i := strings.Index(line, sep); i >= 0 {
			name := strings.TrimSpace(line[:i])
			ver := strings.TrimSpace(line[i+len(sep):])
			ver = strings.Split(ver, ",")[0]
			ver = strings.TrimSpace(ver)
			return name, ver
		}
	}
	return strings.TrimSpace(line), ""
}

func cleanVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}

func cleanNPMVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	v = strings.TrimPrefix(v, "<=")
	v = strings.TrimPrefix(v, ">")
	v = strings.TrimPrefix(v, "<")
	v = strings.TrimPrefix(v, "=")
	if i := strings.IndexAny(v, " ||"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// FormatPackageKey is used for caching lookups.
func FormatPackageKey(p Package) string {
	return fmt.Sprintf("%s|%s|%s", p.Ecosystem, p.Name, p.Version)
}
