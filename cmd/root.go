package cmd

import (
	"fmt"
	"strings"

	"github.com/GhanshyamJha05/Sentinel/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile    string
	format     string
	failOn     string
	noColor    bool
	workers    int
	gitHistory bool
	quiet      bool
)

// rootCmd is the base command.
var rootCmd = &cobra.Command{
	Use:   "sentinel",
	Short: "Unified security scanner for secrets, dependencies, and misconfigurations",
	Long: `sentinel detects leaked secrets, vulnerable dependencies, and common misconfigurations.

Use it locally, in CI as a build gate, or as a scheduled org-wide scanner.`,
	Version:       version.Version,
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: sentinel.yaml)")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "table", "output format: table, json, sarif")
	rootCmd.PersistentFlags().StringVar(&failOn, "fail-on", "high", "exit non-zero if findings at or above this severity (critical|high|medium|low|info|none)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colorized output")
	rootCmd.PersistentFlags().IntVar(&workers, "workers", 0, "concurrent file workers (default: NumCPU)")
	rootCmd.PersistentFlags().BoolVar(&gitHistory, "git-history", false, "also scan git history for secrets")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress non-essential output")

	_ = viper.BindPFlag("format", rootCmd.PersistentFlags().Lookup("format"))
	_ = viper.BindPFlag("fail-on", rootCmd.PersistentFlags().Lookup("fail-on"))
	_ = viper.BindPFlag("no-color", rootCmd.PersistentFlags().Lookup("no-color"))
	_ = viper.BindPFlag("workers", rootCmd.PersistentFlags().Lookup("workers"))
	_ = viper.BindPFlag("git-history", rootCmd.PersistentFlags().Lookup("git-history"))

	rootCmd.AddCommand(scanCmd)
	rootCmd.SetVersionTemplate(fmt.Sprintf("sentinel %s (commit=%s date=%s)\n", version.Version, version.Commit, version.Date))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("sentinel")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.config/sentinel")
	}
	viper.SetEnvPrefix("SENTINEL")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()
	_ = viper.ReadInConfig()
}
