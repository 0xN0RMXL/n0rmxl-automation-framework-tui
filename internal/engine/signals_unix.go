//go:build !windows

package engine

import (
	"os"
	"syscall"
)

func pauseProcess(proc *os.Process) error {
	if proc == nil {
		return nil
	}
	return proc.Signal(syscall.SIGSTOP)
}

func resumeProcess(proc *os.Process) error {
	if proc == nil {
		return nil
	}
	return proc.Signal(syscall.SIGCONT)
}
