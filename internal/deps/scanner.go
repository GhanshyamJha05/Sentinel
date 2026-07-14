package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GhanshyamJha05/Sentinel/internal/report"
	"github.com/GhanshyamJha05/Sentinel/internal/scanutil"
)

const osvQueryURL = "https://api.osv.dev/v1/querybatch"

// Vuln is a vulnerability returned by OSV (simplified).
type Vuln struct {
	ID       string
	Summary  string
	Severity report.Severity
	Fixed    string
}

// Options configures a dependency scan.
type Options struct {
	Path      string
	Ignore    scanutil.IgnoreMatcher
	CacheDir  string
	CacheTTL  time.Duration
	Client    *http.Client
	Offline   bool // if true, only use cache / skip network
}

// Scan parses manifests and queries OSV for vulnerabilities.
func Scan(ctx context.Context, opts Options) ([]report.Finding, error) {
	pkgs, err := ParseManifests(opts.Path, opts.Ignore)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, nil
	}

	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.CacheTTL == 0 {
		opts.CacheTTL = 24 * time.Hour
	}
	if opts.CacheDir == "" {
		home, _ := os.UserHomeDir()
		opts.CacheDir = filepath.Join(home, ".cache", "sentinel", "osv")
	}

	cache := newFileCache(opts.CacheDir, opts.CacheTTL)
	vulnsByPkg, err := lookupVulns(ctx, opts.Client, cache, pkgs, opts.Offline)
	if err != nil {
		return nil, err
	}

	var findings []report.Finding
	for _, p := range pkgs {
		for _, v := range vulnsByPkg[FormatPackageKey(p)] {
			sev := v.Severity
			if sev == "" {
				sev = report.SeverityMedium
			}
			msg := fmt.Sprintf("%s@%s has vulnerability %s", p.Name, p.Version, v.ID)
			if v.Summary != "" {
				msg = fmt.Sprintf("%s: %s", msg, v.Summary)
			}
			rem := "Upgrade to a non-vulnerable version."
			if v.Fixed != "" {
				rem = fmt.Sprintf("Upgrade to %s or later.", v.Fixed)
			}
			findings = append(findings, report.Finding{
				ID:          fmt.Sprintf("dep:%s:%s:%s", p.Name, p.Version, v.ID),
				Category:    report.CategoryDependency,
				Rule:        "vulnerable-dependency",
				Severity:    sev,
				Confidence:  0.9,
				File:        p.Manifest,
				Message:     msg,
				Remediation: rem,
				Metadata: map[string]string{
					"package":    p.Name,
					"version":    p.Version,
					"ecosystem":  string(p.Ecosystem),
					"vuln_id":    v.ID,
					"fixed":      v.Fixed,
				},
			})
		}
	}
	return findings, nil
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version,omitempty"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvVuln struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []osvVuln `json:"vulns"`
	} `json:"results"`
}

func lookupVulns(ctx context.Context, client *http.Client, cache *fileCache, pkgs []Package, offline bool) (map[string][]Vuln, error) {
	out := make(map[string][]Vuln)
	var missing []Package

	for _, p := range pkgs {
		if p.Version == "" {
			continue
		}
		key := FormatPackageKey(p)
		if cached, ok := cache.Get(key); ok {
			out[key] = cached
			continue
		}
		missing = append(missing, p)
	}

	if offline || len(missing) == 0 {
		return out, nil
	}

	const batchSize = 100
	for i := 0; i < len(missing); i += batchSize {
		end := i + batchSize
		if end > len(missing) {
			end = len(missing)
		}
		batch := missing[i:end]
		results, err := queryOSVBatch(ctx, client, batch)
		if err != nil {
			return out, err
		}
		for j, p := range batch {
			key := FormatPackageKey(p)
			vulns := results[j]
			out[key] = vulns
			_ = cache.Set(key, vulns)
		}
	}
	return out, nil
}

func queryOSVBatch(ctx context.Context, client *http.Client, pkgs []Package) ([][]Vuln, error) {
	reqBody := osvBatchRequest{Queries: make([]osvQuery, len(pkgs))}
	for i, p := range pkgs {
		reqBody.Queries[i].Package.Name = p.Name
		reqBody.Queries[i].Package.Ecosystem = string(p.Ecosystem)
		reqBody.Queries[i].Version = p.Version
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * 500 * time.Millisecond):
			}
		}

		payload, _ := json.Marshal(reqBody)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryURL, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("osv api status %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("osv api status %d: %s", resp.StatusCode, truncate(string(body), 200))
		}

		var parsed osvBatchResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, err
		}
		out := make([][]Vuln, len(pkgs))
		for i := range pkgs {
			if i >= len(parsed.Results) {
				continue
			}
			for _, v := range parsed.Results[i].Vulns {
				out[i] = append(out[i], Vuln{
					ID:       v.ID,
					Summary:  v.Summary,
					Severity: mapOSVSeverity(v),
					Fixed:    extractFixed(v),
				})
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("osv query failed after retries: %w", lastErr)
}

func mapOSVSeverity(v osvVuln) report.Severity {
	if ds, ok := v.DatabaseSpecific["severity"].(string); ok {
		switch strings.ToUpper(ds) {
		case "CRITICAL":
			return report.SeverityCritical
		case "HIGH":
			return report.SeverityHigh
		case "MODERATE", "MEDIUM":
			return report.SeverityMedium
		case "LOW":
			return report.SeverityLow
		}
	}
	for _, s := range v.Severity {
		if strings.Contains(strings.ToUpper(s.Type), "CVSS") {
			// crude CVSS mapping from score string prefix
			if strings.HasPrefix(s.Score, "9") || strings.HasPrefix(s.Score, "10") {
				return report.SeverityCritical
			}
			if strings.HasPrefix(s.Score, "7") || strings.HasPrefix(s.Score, "8") {
				return report.SeverityHigh
			}
			if strings.HasPrefix(s.Score, "4") || strings.HasPrefix(s.Score, "5") || strings.HasPrefix(s.Score, "6") {
				return report.SeverityMedium
			}
			return report.SeverityLow
		}
	}
	return report.SeverityMedium
}

func extractFixed(v osvVuln) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

type fileCache struct {
	dir string
	ttl time.Duration
	mu  sync.Mutex
}

func newFileCache(dir string, ttl time.Duration) *fileCache {
	_ = os.MkdirAll(dir, 0o755)
	return &fileCache{dir: dir, ttl: ttl}
}

func (c *fileCache) path(key string) string {
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, key)
	return filepath.Join(c.dir, safe+".json")
}

func (c *fileCache) Get(key string) ([]Vuln, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.path(key)
	info, err := os.Stat(p)
	if err != nil {
		return nil, false
	}
	if time.Since(info.ModTime()) > c.ttl {
		return nil, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var vulns []Vuln
	if err := json.Unmarshal(data, &vulns); err != nil {
		return nil, false
	}
	return vulns, true
}

func (c *fileCache) Set(key string, vulns []Vuln) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := json.Marshal(vulns)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path(key), data, 0o644)
}
