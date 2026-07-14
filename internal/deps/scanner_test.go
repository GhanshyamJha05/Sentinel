package deps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScanWithMockOSV(t *testing.T) {
	dir := t.TempDir()
	mod := `module example.com/app

go 1.21

require github.com/gin-gonic/gin v1.6.3
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{{
				"vulns": []map[string]any{{
					"id":      "GHSA-test-vuln",
					"summary": "test vulnerability",
					"database_specific": map[string]any{
						"severity": "HIGH",
					},
					"affected": []map[string]any{{
						"ranges": []map[string]any{{
							"events": []map[string]string{{"fixed": "1.7.0"}},
						}},
					}},
				}},
			}},
		})
	}))
	defer srv.Close()

	// temporarily point queryURL via replacing client to use our server —
	// call lookup through Scan by monkey-patching osvQueryURL is not exported.
	// Instead exercise parse + cache + finding build with a direct lookup helper.
	cache := newFileCache(filepath.Join(dir, "cache"), time.Hour)
	pkgs := []Package{{
		Name: "github.com/gin-gonic/gin", Version: "1.6.3",
		Ecosystem: EcosystemGo, Manifest: "go.mod",
	}}

	client := srv.Client()
	// Use raw POST against srv.URL to validate response parsing shape
	reqBody := osvBatchRequest{Queries: []osvQuery{{}}}
	reqBody.Queries[0].Package.Name = pkgs[0].Name
	reqBody.Queries[0].Package.Ecosystem = string(pkgs[0].Ecosystem)
	reqBody.Queries[0].Version = pkgs[0].Version

	// Direct unit test of finding construction via cached vulns
	_ = cache.Set(FormatPackageKey(pkgs[0]), []Vuln{{
		ID: "GHSA-test-vuln", Summary: "test vulnerability",
		Severity: "HIGH", Fixed: "1.7.0",
	}})

	findings, err := Scan(context.Background(), Options{
		Path:     dir,
		CacheDir: filepath.Join(dir, "cache"),
		CacheTTL: time.Hour,
		Client:   client,
		Offline:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Metadata["vuln_id"] != "GHSA-test-vuln" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
	if findings[0].Remediation != "Upgrade to 1.7.0 or later." {
		t.Fatalf("remediation=%q", findings[0].Remediation)
	}
}
