package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/GhanshyamJha05/Sentinel/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		var fe interface{ ExitCode() int }
		if errors.As(err, &fe) {
			os.Exit(fe.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
