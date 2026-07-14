package deps

import (
	"testing"

	"github.com/GhanshyamJha05/Sentinel/internal/report"
)

func TestVulnApplies_ImportFilter(t *testing.T) {
	v := Vuln{
		ID:       "GO-2026-5932",
		Summary:  "openpgp unsafe",
		Severity: report.SeverityMedium,
		Imports: []string{
			"golang.org/x/crypto/openpgp",
			"golang.org/x/crypto/openpgp/packet",
		},
	}
	used := map[string]struct{}{
		"golang.org/x/crypto/ssh": {},
		"golang.org/x/net/http2":  {},
	}
	if VulnApplies(v, EcosystemGo, used) {
		t.Fatal("openpgp-only vuln should not apply when openpgp is unused")
	}
	used["golang.org/x/crypto/openpgp"] = struct{}{}
	if !VulnApplies(v, EcosystemGo, used) {
		t.Fatal("should apply when import is used")
	}
	if !VulnApplies(v, EcosystemNPM, used) {
		t.Fatal("non-Go ecosystem should not be filtered")
	}
	if !VulnApplies(Vuln{ID: "X"}, EcosystemGo, used) {
		t.Fatal("empty imports should apply")
	}
}
