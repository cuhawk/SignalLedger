package main

import (
	"errors"
	"os"
	"os/exec"
)

func ruleCommand(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("usage: signalledger rule check [--rules DIR] [--fixture FILE]")
	}
	python := os.Getenv("SIGNALLEDGER_PYTHON")
	if python == "" {
		python = "python3"
	}
	cmd := exec.Command(python, append([]string{"-m", "analytics.rulecheck"}, args[1:]...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
