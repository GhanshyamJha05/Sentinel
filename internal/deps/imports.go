package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const osvVulnURL = "https://api.osv.dev/v1/vulns/"

// UsedGoImports returns import paths reachable from ./... under moduleRoot.
// Returns nil when go is unavailable or the tree is not a usable Go module.
func UsedGoImports(ctx context.Context, moduleRoot string) map[string]struct{} {
	if _, err := exec.LookPath("go"); err != nil {
		return nil
	}
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-e", "-f", "{{.ImportPath}}", "./...")
	cmd.Dir = moduleRoot
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	used := make(map[string]struct{})
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		used[line] = struct{}{}
	}
	return used
}

// VulnApplies reports whether a vuln is relevant given used Go imports.
// Non-Go vulns, or vulns without import metadata, always apply.
func VulnApplies(v Vuln, ecosystem Ecosystem, used map[string]struct{}) bool {
	if ecosystem != EcosystemGo || len(v.Imports) == 0 || len(used) == 0 {
		return true
	}
	for _, imp := range v.Imports {
		if _, ok := used[imp]; ok {
			return true
		}
	}
	return false
}

type osvVulnDetail struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Affected []struct {
		EcosystemSpecific struct {
			Imports []struct {
				Path string `json:"path"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

func enrichVulnImports(ctx context.Context, client *http.Client, cache *fileCache, vulns []Vuln) []Vuln {
	out := make([]Vuln, len(vulns))
	copy(out, vulns)
	for i, v := range out {
		if len(v.Imports) > 0 {
			continue
		}
		cacheKey := "vulnmeta|" + v.ID
		if cached, ok := cache.Get(cacheKey); ok && len(cached) == 1 {
			out[i].Imports = cached[0].Imports
			if out[i].Summary == "" {
				out[i].Summary = cached[0].Summary
			}
			continue
		}
		detail, err := fetchOSVVuln(ctx, client, v.ID)
		if err != nil {
			continue
		}
		imps := extractImportPaths(detail)
		out[i].Imports = imps
		if out[i].Summary == "" {
			out[i].Summary = detail.Summary
		}
		_ = cache.Set(cacheKey, []Vuln{{ID: v.ID, Summary: detail.Summary, Imports: imps}})
	}
	return out
}

func fetchOSVVuln(ctx context.Context, client *http.Client, id string) (*osvVulnDetail, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvVulnURL+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv vuln %s: status %d", id, resp.StatusCode)
	}
	var detail osvVulnDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		return nil, err
	}
	return &detail, nil
}

func extractImportPaths(d *osvVulnDetail) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, a := range d.Affected {
		for _, im := range a.EcosystemSpecific.Imports {
			p := strings.TrimSpace(im.Path)
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// FindGoModuleRoot walks up from path looking for go.mod.
func FindGoModuleRoot(path string) string {
	dir := path
	info, err := os.Stat(path)
	if err == nil && !info.IsDir() {
		dir = filepath.Dir(path)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return path
		}
		dir = parent
	}
}
