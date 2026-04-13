package engine

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestJobHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	args := os.Args
	sep := -1
	for i, arg := range args {
		if arg == "--" {
			sep = i
			break
		}
	}
	if sep == -1 || sep >= len(args)-1 {
		os.Exit(2)
	}

	mode := args[sep+1]
	switch mode {
	case "sleep":
		if sep+2 >= len(args) {
			os.Exit(2)
		}
		d, err := time.ParseDuration(args[sep+2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		time.Sleep(d)
		fmt.Fprintln(os.Stdout, "slept")
	case "lines":
		fmt.Fprintln(os.Stdout, "alpha")
		fmt.Fprintln(os.Stdout, "beta")
	case "fail":
		fmt.Fprintln(os.Stderr, "intentional failure")
		os.Exit(1)
	default:
		os.Exit(2)
	}

	os.Exit(0)
}

func helperProcessCommand(args ...string) (string, []string, []string) {
	return os.Args[0], append([]string{"-test.run=TestJobHelperProcess", "--"}, args...), []string{"GO_WANT_HELPER_PROCESS=1"}
}

func TestNewJob(t *testing.T) {
	job := NewJob(3, "httpx", "httpx", []string{"-silent"})
	if job.ID != "3-httpx" {
		t.Fatalf("expected job ID 3-httpx, got %q", job.ID)
	}
	if job.Phase != 3 {
		t.Fatalf("expected phase 3, got %d", job.Phase)
	}
	if job.Status != JobPending {
		t.Fatalf("expected pending status, got %q", job.Status)
	}
}

func TestJobTimeout(t *testing.T) {
	binary, args, env := helperProcessCommand("sleep", "30s")
	job := NewJob(1, "helper-timeout", binary, args)
	job.Env = env
	job.Timeout = 100 * time.Millisecond

	err := job.Run(context.Background())
	if err == nil {
		t.Fatal("expected timeout to fail the job")
	}
	if job.Status != JobFailed {
		t.Fatalf("expected failed status, got %q", job.Status)
	}
	if job.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code, got %d", job.ExitCode)
	}
}

func TestJobOutputCapture(t *testing.T) {
	binary, args, env := helperProcessCommand("lines")
	job := NewJob(1, "helper-lines", binary, args)
	job.Env = env

	var lines []string
	job.OnLine = func(_ *Job, line string) {
		lines = append(lines, line)
	}

	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if got := strings.Join(lines, ","); got != "alpha,beta" {
		t.Fatalf("expected captured lines alpha,beta, got %q", got)
	}
}

func TestJobExitCodeNonZero(t *testing.T) {
	binary, args, env := helperProcessCommand("fail")
	job := NewJob(1, "helper-fail", binary, args)
	job.Env = env

	err := job.Run(context.Background())
	if err == nil {
		t.Fatal("expected failing helper process to return an error")
	}
	if job.ExitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", job.ExitCode)
	}
	if job.Status != JobFailed {
		t.Fatalf("expected failed status, got %q", job.Status)
	}
}

func TestJobKill(t *testing.T) {
	binary, args, env := helperProcessCommand("sleep", "30s")
	job := NewJob(1, "helper-kill", binary, args)
	job.Env = env

	done := make(chan error, 1)
	go func() {
		done <- job.Run(context.Background())
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job.mu.Lock()
		started := job.cmd != nil
		job.mu.Unlock()
		if started {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	job.Kill()

	err := <-done
	if err == nil {
		t.Fatal("expected killed job to return an error")
	}
	if job.Status != JobFailed {
		t.Fatalf("expected failed status after kill, got %q", job.Status)
	}
}
