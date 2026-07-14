package misconfig

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/GhanshyamJha05/Sentinel/internal/report"
	"github.com/GhanshyamJha05/Sentinel/internal/scanutil"
)

// TerraformPublicExpose finds common insecure Terraform patterns.
type TerraformPublicExpose struct{}

func (c *TerraformPublicExpose) ID() string { return "terraform-public-expose" }
func (c *TerraformPublicExpose) Description() string {
	return "Terraform resources exposed to the public internet"
}

var (
	tfCIDROpen            = regexp.MustCompile(`(?i)cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"[^\]]*\]`)
	tfIPv6Open            = regexp.MustCompile(`(?i)ipv6_cidr_blocks\s*=\s*\[[^\]]*"::/0"[^\]]*\]`)
	tfPublicACL           = regexp.MustCompile(`(?i)acl\s*=\s*"(public-read|public-read-write|website)"`)
	tfPublicBlockDisabled = regexp.MustCompile(`(?i)block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|ignore_public_acls\s*=\s*false|restrict_public_buckets\s*=\s*false`)
	tfDisableIMDSv2       = regexp.MustCompile(`(?i)http_tokens\s*=\s*"optional"`)
)

func (c *TerraformPublicExpose) Run(ctx CheckContext) ([]report.Finding, error) {
	var out []report.Finding
	for _, f := range ctx.Files {
		ext := strings.ToLower(filepath.Ext(f.RelPath))
		if ext != ".tf" && ext != ".tf.json" {
			continue
		}
		lines, err := scanutil.ReadLines(f.AbsPath)
		if err != nil {
			continue
		}
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
				continue
			}
			switch {
			case tfCIDROpen.MatchString(line) || tfIPv6Open.MatchString(line):
				out = append(out, finding(c.ID(), f.RelPath, i+1, report.SeverityHigh,
					"Security group / network rule allows traffic from the entire internet (0.0.0.0/0 or ::/0)",
					"Restrict cidr_blocks to known CIDRs; avoid opening management ports to the world.",
				))
			case tfPublicACL.MatchString(line):
				out = append(out, finding(c.ID(), f.RelPath, i+1, report.SeverityHigh,
					"S3 bucket ACL grants public access",
					"Use private ACLs and bucket policies with least privilege; enable Block Public Access.",
				))
			case tfPublicBlockDisabled.MatchString(line):
				out = append(out, finding(c.ID(), f.RelPath, i+1, report.SeverityMedium,
					"S3 Block Public Access setting is disabled",
					"Set block_public_* flags to true on aws_s3_bucket_public_access_block.",
				))
			case tfDisableIMDSv2.MatchString(line):
				out = append(out, finding(c.ID(), f.RelPath, i+1, report.SeverityMedium,
					"EC2 instance metadata allows IMDSv1 (http_tokens = optional)",
					`Set http_tokens = "required" to enforce IMDSv2.`,
				))
			}
		}
	}
	return out, nil
}

// TerraformHardcodedSecrets finds obvious secrets baked into Terraform.
type TerraformHardcodedSecrets struct{}

func (c *TerraformHardcodedSecrets) ID() string { return "terraform-hardcoded-secret" }
func (c *TerraformHardcodedSecrets) Description() string {
	return "Hardcoded credentials in Terraform files"
}

var tfSecretAssign = regexp.MustCompile(`(?i)(?:password|secret|access_key|secret_key|api_key|token)\s*=\s*"([^"]{8,})"`)

func (c *TerraformHardcodedSecrets) Run(ctx CheckContext) ([]report.Finding, error) {
	var out []report.Finding
	for _, f := range ctx.Files {
		if strings.ToLower(filepath.Ext(f.RelPath)) != ".tf" {
			continue
		}
		lines, err := scanutil.ReadLines(f.AbsPath)
		if err != nil {
			continue
		}
		for i, line := range lines {
			m := tfSecretAssign.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			val := m[1]
			lower := strings.ToLower(val)
			if strings.Contains(lower, "var.") || strings.HasPrefix(val, "${") ||
				lower == "changeme" || strings.Contains(lower, "example") {
				// still flag changeme/example as weak defaults via other checks; skip var refs
				if strings.Contains(lower, "var.") || strings.HasPrefix(val, "${") {
					continue
				}
			}
			out = append(out, finding(c.ID(), f.RelPath, i+1, report.SeverityCritical,
				fmt.Sprintf("Possible hardcoded secret assigned in Terraform (%s)", redactTF(val)),
				"Move secrets to a secret manager or Terraform variables marked sensitive; never commit real credentials.",
			))
		}
	}
	return out, nil
}

func redactTF(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	return s[:3] + strings.Repeat("*", len(s)-6) + s[len(s)-3:]
}
