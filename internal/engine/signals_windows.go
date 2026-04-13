//go:build windows

package engine

import "os"

func pauseProcess(proc *os.Process) error {
	return nil
}

func resumeProcess(proc *os.Process) error {
	return nil
}
