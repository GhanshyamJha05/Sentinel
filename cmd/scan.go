package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/GhanshyamJha05/Sentinel/internal/deps"
	"github.com/GhanshyamJha05/Sentinel/internal/misconfig"
	"github.com/GhanshyamJha05/Sentinel/internal/report"
	"github.com/GhanshyamJha05/Sentinel/internal/scanutil"
	"github.com/GhanshyamJha05/Sentinel/internal/secrets"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scans",
	Long:  "Run secret, dependency, and/or misconfiguration scans against a path.",
}

func init() {
	scanCmd.AddCommand(newSecretsCmd())
	scanCmd.AddCommand(newDepsCmd())
	scanCmd.AddCommand(newConfigCmd())
	scanCmd.AddCommand(newAllCmd())
}

func resolveTarget(args []string) (string, error) {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("path %q not found: %w", target, err)
	}
	return abs, nil
}

func ignoreFor(root string) scanutil.IgnoreMatcher {
	extra := viper.GetStringSlice("ignore")
	return scanutil.LoadSentinelIgnore(root, extra)
}

// scanScope resolves ignore matcher and optional changed-file list for --git-diff.
func scanScope(root string) (ignore scanutil.IgnoreMatcher, changed []string, err error) {
	base := ignoreFor(root)
	ref := viper.GetString("git-diff")
	if ref == "" {
		ref = gitDiff
	}
	if ref == "" {
		return base, nil, nil
	}
	changed, err = scanutil.GitDiffFiles(root, ref)
	if err != nil {
		return nil, nil, fmt.Errorf("--git-diff %q: %w", ref, err)
	}
	return scanutil.CombineIgnore(base, changed), changed, nil
}

func filterFindings(findings []report.Finding) []report.Finding {
	ignoreVulns := map[string]struct{}{}
	for _, id := range viper.GetStringSlice("ignore_vulns") {
		ignoreVulns[strings.TrimSpace(id)] = struct{}{}
	}
	ignoreRules := map[string]struct{}{}
	for _, id := range viper.GetStringSlice("ignore_rules") {
		ignoreRules[strings.TrimSpace(id)] = struct{}{}
	}
	if len(ignoreVulns) == 0 && len(ignoreRules) == 0 {
		return findings
	}
	out := make([]report.Finding, 0, len(findings))
	for _, f := range findings {
		if _, skip := ignoreRules[f.Rule]; skip {
			continue
		}
		if f.Metadata != nil {
			if vid := f.Metadata["vuln_id"]; vid != "" {
				if _, skip := ignoreVulns[vid]; skip {
					continue
				}
			}
		}
		out = append(out, f)
	}
	return out
}

func writeAndExit(target string, findings []report.Finding) error {
	findings = filterFindings(findings)
	fmtStr := viper.GetString("format")
	if fmtStr == "" {
		fmtStr = format
	}
	fail := viper.GetString("fail-on")
	if fail == "" {
		fail = failOn
	}
	nc := viper.GetBool("no-color") || noColor

	r := report.NewReport(target, findings)
	w := report.Writer{
		Out:     os.Stdout,
		Format:  report.ParseFormat(fmtStr),
		NoColor: nc,
	}
	if err := w.Write(r); err != nil {
		return err
	}

	if stringsEqualFold(fail, "none") {
		return nil
	}
	threshold := report.ParseSeverity(fail)
	if report.HasFindingsAtOrAbove(findings, threshold) {
		return errFailThreshold
	}
	return nil
}

var errFailThreshold = &exitError{code: 1, msg: "findings met or exceeded --fail-on threshold"}

type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }
func (e *exitError) ExitCode() int { return e.code }
func (e *exitError) Is(target error) bool {
	_, ok := target.(*exitError)
	return ok
}

func stringsEqualFold(a, b string) bool {
	return len(a) == len(b) && (a == b || equalFoldASCII(a, b))
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func newSecretsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "secrets [path]",
		Short: "Scan for leaked secrets",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget(args)
			if err != nil {
				return err
			}
			ignore, _, err := scanScope(target)
			if err != nil {
				return err
			}
			findings, err := secrets.Scan(secrets.Options{
				Path:             target,
				Workers:          viper.GetInt("workers"),
				Ignore:           ignore,
				GitHistory:       viper.GetBool("git-history") || gitHistory,
				RespectGitIgnore: true,
			})
			if err != nil {
				return err
			}
			return writeAndExit(target, findings)
		},
	}
}

func newDepsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deps [path]",
		Short: "Scan dependencies for known vulnerabilities",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget(args)
			if err != nil {
				return err
			}
			ignore, changed, err := scanScope(target)
			if err != nil {
				return err
			}
			if changed != nil && !scanutil.ManifestTouched(changed) {
				return writeAndExit(target, nil)
			}
			findings, err := deps.Scan(cmd.Context(), deps.Options{
				Path:   target,
				Ignore: ignoreFor(target), // always use project ignore for manifests; diff gates via ManifestTouched
			})
			if err != nil {
				return err
			}
			_ = ignore
			return writeAndExit(target, findings)
		},
	}
}

func newConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "config [path]",
		Short: "Scan for security misconfigurations",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget(args)
			if err != nil {
				return err
			}
			ignore, _, err := scanScope(target)
			if err != nil {
				return err
			}
			findings, err := misconfig.Scan(misconfig.Options{
				Path:   target,
				Ignore: ignore,
			})
			if err != nil {
				return err
			}
			return writeAndExit(target, findings)
		},
	}
}

func newAllCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "all [path]",
		Short: "Run all scanners concurrently",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := resolveTarget(args)
			if err != nil {
				return err
			}
			findings, err := runAll(cmd.Context(), target)
			if err != nil {
				return err
			}
			return writeAndExit(target, findings)
		},
	}
}

func runAll(ctx context.Context, target string) ([]report.Finding, error) {
	ignore, changed, err := scanScope(target)
	if err != nil {
		return nil, err
	}
	baseIgnore := ignoreFor(target)
	runDeps := changed == nil || scanutil.ManifestTouched(changed)

	var (
		mu       sync.Mutex
		findings []report.Finding
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	setErr := func(err error) {
		if err == nil {
			return
		}
		errOnce.Do(func() { firstErr = err })
	}
	appendFindings := func(fs []report.Finding) {
		mu.Lock()
		findings = append(findings, fs...)
		mu.Unlock()
	}

	workers := 2
	if runDeps {
		workers = 3
	}
	wg.Add(workers)
	go func() {
		defer wg.Done()
		fs, err := secrets.Scan(secrets.Options{
			Path:             target,
			Workers:          viper.GetInt("workers"),
			Ignore:           ignore,
			GitHistory:       viper.GetBool("git-history") || gitHistory,
			RespectGitIgnore: true,
		})
		setErr(err)
		appendFindings(fs)
	}()
	if runDeps {
		go func() {
			defer wg.Done()
			fs, err := deps.Scan(ctx, deps.Options{Path: target, Ignore: baseIgnore})
			setErr(err)
			appendFindings(fs)
		}()
	}
	go func() {
		defer wg.Done()
		fs, err := misconfig.Scan(misconfig.Options{Path: target, Ignore: ignore})
		setErr(err)
		appendFindings(fs)
	}()
	wg.Wait()
	return findings, firstErr
}
