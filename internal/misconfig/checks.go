package misconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/GhanshyamJha05/Sentinel/internal/report"
	"github.com/GhanshyamJha05/Sentinel/internal/scanutil"
)

// Check is a pluggable misconfiguration rule.
type Check interface {
	ID() string
	Description() string
	Run(ctx CheckContext) ([]report.Finding, error)
}

// CheckContext provides shared scan state to checks.
type CheckContext struct {
	Root   string
	Ignore scanutil.IgnoreMatcher
	Files  []scanutil.FileJob
}

// Options configures a misconfig scan.
type Options struct {
	Path   string
	Ignore scanutil.IgnoreMatcher
	Checks []Check
}

// DefaultChecks returns the built-in misconfiguration checks.
func DefaultChecks() []Check {
	return []Check{
		&EnvFileExposed{},
		&DebugFlagsEnabled{},
		&DefaultCredentials{},
		&WeakPermissions{},
		&MissingSecurityHeaders{},
	}
}

// Scan runs all checks against the target path.
func Scan(opts Options) ([]report.Finding, error) {
	if opts.Checks == nil {
		opts.Checks = DefaultChecks()
	}

	info, err := os.Stat(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("misconfig scan: %w", err)
	}

	var (
		mu    sync.Mutex
		files []scanutil.FileJob
	)
	if info.IsDir() {
		_ = scanutil.WalkFiles(scanutil.WalkOptions{
			Root:   opts.Path,
			Ignore: opts.Ignore,
		}, func(job scanutil.FileJob) error {
			mu.Lock()
			files = append(files, job)
			mu.Unlock()
			return nil
		})
	} else {
		files = append(files, scanutil.FileJob{
			AbsPath: opts.Path,
			RelPath: filepath.Base(opts.Path),
			Info:    info,
		})
	}

	ctx := CheckContext{Root: opts.Path, Ignore: opts.Ignore, Files: files}
	var findings []report.Finding
	for _, check := range opts.Checks {
		fs, err := check.Run(ctx)
		if err != nil {
			return findings, fmt.Errorf("check %s: %w", check.ID(), err)
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}

func finding(rule, file string, line int, sev report.Severity, msg, rem string) report.Finding {
	return report.Finding{
		ID:          fmt.Sprintf("misconfig:%s:%s:%d", rule, file, line),
		Category:    report.CategoryMisconfig,
		Rule:        rule,
		Severity:    sev,
		Confidence:  0.8,
		File:        file,
		Line:        line,
		Message:     msg,
		Remediation: rem,
	}
}

// EnvFileExposed flags .env / credential files present in the tree.
type EnvFileExposed struct{}

func (c *EnvFileExposed) ID() string          { return "env-file-exposed" }
func (c *EnvFileExposed) Description() string { return "Sensitive credential files present in the repository" }

var sensitiveNames = regexp.MustCompile(`(?i)(^|\.)(env|env\.local|env\.production|credentials|secrets?)(\.|$)|\.pem$|\.key$|id_rsa$|id_ed25519$`)

func (c *EnvFileExposed) Run(ctx CheckContext) ([]report.Finding, error) {
	var out []report.Finding
	for _, f := range ctx.Files {
		base := filepath.Base(f.RelPath)
		if base == ".env.example" || base == ".env.sample" || base == ".env.template" {
			continue
		}
		if sensitiveNames.MatchString(base) || base == ".env" {
			out = append(out, finding(c.ID(), f.RelPath, 0, report.SeverityHigh,
				fmt.Sprintf("Sensitive file %q may contain credentials and should not be committed", base),
				"Remove from the repository, rotate secrets, and add the filename to .gitignore.",
			))
		}
	}
	return out, nil
}

// DebugFlagsEnabled finds debug/dev mode left enabled.
type DebugFlagsEnabled struct{}

func (c *DebugFlagsEnabled) ID() string          { return "debug-enabled" }
func (c *DebugFlagsEnabled) Description() string { return "Debug or development flags left enabled" }

var debugPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*DEBUG\s*[=:]\s*(true|1|yes|on)\s*$`),
	regexp.MustCompile(`(?i)^\s*APP_DEBUG\s*[=:]\s*(true|1|yes|on)\s*$`),
	regexp.MustCompile(`(?i)^\s*debug\s*[:=]\s*true\b`),
	regexp.MustCompile(`(?i)"debug"\s*:\s*true`),
	regexp.MustCompile(`(?i)flask[_-]?env\s*[=:]\s*development`),
	regexp.MustCompile(`(?i)NODE_ENV\s*[=:]\s*development`),
}

func (c *DebugFlagsEnabled) Run(ctx CheckContext) ([]report.Finding, error) {
	var out []report.Finding
	for _, f := range ctx.Files {
		base := strings.ToLower(filepath.Base(f.RelPath))
		if !strings.Contains(base, "config") && !strings.Contains(base, ".env") &&
			!strings.HasSuffix(base, ".yml") && !strings.HasSuffix(base, ".yaml") &&
			!strings.HasSuffix(base, ".json") && !strings.HasSuffix(base, ".toml") &&
			!strings.HasSuffix(base, ".py") && !strings.HasSuffix(base, ".js") &&
			!strings.HasSuffix(base, ".ts") && !strings.HasSuffix(base, ".properties") {
			continue
		}
		lines, err := scanutil.ReadLines(f.AbsPath)
		if err != nil {
			continue
		}
		for i, line := range lines {
			for _, pat := range debugPatterns {
				if pat.MatchString(line) {
					out = append(out, finding(c.ID(), f.RelPath, i+1, report.SeverityMedium,
						"Debug/development mode appears enabled",
						"Disable debug flags in production configuration.",
					))
					break
				}
			}
		}
	}
	return out, nil
}

// DefaultCredentials finds example/default passwords in Dockerfiles and configs.
type DefaultCredentials struct{}

func (c *DefaultCredentials) ID() string          { return "default-credentials" }
func (c *DefaultCredentials) Description() string { return "Default or example credentials in configs" }

var defaultCredPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?(admin|password|pass|root|123456|changeme|secret)['\"]?`),
	regexp.MustCompile(`(?i)ENV\s+(?:\w*PASSWORD\w*|\w*PASS\w*)\s*=\s*(admin|password|root|123456|changeme)`),
	regexp.MustCompile(`(?i)--password[=\s]+(admin|password|root|changeme)`),
	regexp.MustCompile(`(?i)POSTGRES_PASSWORD\s*=\s*(postgres|password|admin)`),
	regexp.MustCompile(`(?i)MYSQL_ROOT_PASSWORD\s*=\s*(root|password|admin)`),
}

func (c *DefaultCredentials) Run(ctx CheckContext) ([]report.Finding, error) {
	var out []report.Finding
	for _, f := range ctx.Files {
		base := filepath.Base(f.RelPath)
		lower := strings.ToLower(base)
		if !strings.Contains(lower, "dockerfile") && !strings.Contains(lower, "docker-compose") &&
			!strings.Contains(lower, "config") && !strings.HasSuffix(lower, ".env") &&
			!strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") &&
			!strings.HasSuffix(lower, ".properties") {
			continue
		}
		lines, err := scanutil.ReadLines(f.AbsPath)
		if err != nil {
			continue
		}
		for i, line := range lines {
			for _, pat := range defaultCredPatterns {
				if pat.MatchString(line) {
					out = append(out, finding(c.ID(), f.RelPath, i+1, report.SeverityHigh,
						"Default or weak credential detected in configuration",
						"Replace with a strong secret from a secret manager; never commit real passwords.",
					))
					break
				}
			}
		}
	}
	return out, nil
}

// WeakPermissions flags world-readable/writable sensitive files (Unix only).
type WeakPermissions struct{}

func (c *WeakPermissions) ID() string          { return "weak-permissions" }
func (c *WeakPermissions) Description() string { return "Overly permissive file modes on sensitive files" }

func (c *WeakPermissions) Run(ctx CheckContext) ([]report.Finding, error) {
	if runtime.GOOS == "windows" {
		return nil, nil
	}
	var out []report.Finding
	for _, f := range ctx.Files {
		base := filepath.Base(f.RelPath)
		sensitive := base == ".env" || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") ||
			base == "id_rsa" || base == "id_ed25519" || strings.Contains(strings.ToLower(base), "credential")
		if !sensitive {
			continue
		}
		info := f.Info
		if info == nil {
			var err error
			info, err = os.Stat(f.AbsPath)
			if err != nil {
				continue
			}
		}
		mode := info.Mode().Perm()
		if mode&0o004 != 0 || mode&0o002 != 0 || mode&0o022 != 0 {
			out = append(out, finding(c.ID(), f.RelPath, 0, report.SeverityHigh,
				fmt.Sprintf("Sensitive file has overly permissive mode %04o", mode),
				"Restrict permissions (e.g. chmod 600) so only the owner can read the file.",
			))
		}
	}
	return out, nil
}

// MissingSecurityHeaders checks nginx/Apache configs for basic security headers.
type MissingSecurityHeaders struct{}

func (c *MissingSecurityHeaders) ID() string          { return "missing-security-headers" }
func (c *MissingSecurityHeaders) Description() string { return "Missing security headers in web server configs" }

var requiredHeaders = []string{
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Strict-Transport-Security",
	"Content-Security-Policy",
}

func (c *MissingSecurityHeaders) Run(ctx CheckContext) ([]report.Finding, error) {
	var out []report.Finding
	for _, f := range ctx.Files {
		base := strings.ToLower(filepath.Base(f.RelPath))
		if !strings.Contains(base, "nginx") && base != "httpd.conf" &&
			!strings.HasSuffix(base, ".conf") {
			continue
		}
		// only consider likely web server configs
		data, err := os.ReadFile(f.AbsPath)
		if err != nil {
			continue
		}
		content := string(data)
		lower := strings.ToLower(content)
		if !strings.Contains(lower, "server") && !strings.Contains(lower, "virtualhost") &&
			!strings.Contains(lower, "location") {
			continue
		}
		for _, h := range requiredHeaders {
			if !strings.Contains(content, h) {
				out = append(out, finding(c.ID(), f.RelPath, 0, report.SeverityLow,
					fmt.Sprintf("Web server config may be missing security header %s", h),
					fmt.Sprintf("Add the %s header to your server configuration.", h),
				))
			}
		}
	}
	return out, nil
}
