package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type JobStatus string

const (
	JobPending JobStatus = "pending"
	JobRunning JobStatus = "running"
	JobDone    JobStatus = "done"
	JobFailed  JobStatus = "failed"
	JobSkipped JobStatus = "skipped"
)

type Job struct {
	ID          string
	Phase       int
	ToolName    string
	Description string
	Binary      string
	Args        []string
	Env         []string
	WorkDir     string
	OutputFile  string
	StdoutFile  string
	StderrFile  string
	Status      JobStatus
	StartedAt   time.Time
	FinishedAt  time.Time
	ExitCode    int
	ItemsFound  int
	ErrorMsg    string
	Timeout     time.Duration
	Required    bool
	DependsOn   []string
	OnStart     func(j *Job)
	OnLine      func(j *Job, line string)
	OnComplete  func(j *Job)
	OnError     func(j *Job, err error)
	Execute     func(ctx context.Context, j *Job) error
	ParseOutput func(j *Job) int

	mu     sync.Mutex
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

func NewJob(phase int, tool string, binary string, args []string) *Job {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		tool = "unknown"
	}
	return &Job{
		ID:       fmt.Sprintf("%d-%s", phase, tool),
		Phase:    phase,
		ToolName: tool,
		Binary:   strings.TrimSpace(binary),
		Args:     args,
		Status:   JobPending,
		Required: false,
	}
}

func (j *Job) Command() *exec.Cmd {
	cmd := exec.Command(j.Binary, j.Args...)
	if j.WorkDir != "" {
		cmd.Dir = j.WorkDir
	}
	if len(j.Env) > 0 {
		cmd.Env = append(os.Environ(), j.Env...)
	}
	return cmd
}

func (j *Job) Run(ctx context.Context) error {
	j.mu.Lock()
	j.Status = JobRunning
	j.StartedAt = time.Now().UTC()
	j.FinishedAt = time.Time{}
	j.ExitCode = 0
	j.ErrorMsg = ""
	j.mu.Unlock()
	if j.OnStart != nil {
		j.OnStart(j)
	}

	if strings.TrimSpace(j.Binary) != "" {
		if _, err := exec.LookPath(j.Binary); err != nil {
			warn := fmt.Sprintf("tool %s not found in PATH", j.Binary)
			j.LogLine("[WARN] " + warn)
			j.mu.Lock()
			j.Status = JobSkipped
			j.FinishedAt = time.Now().UTC()
			j.ExitCode = 127
			j.ErrorMsg = warn
			j.mu.Unlock()
			if j.OnComplete != nil {
				j.OnComplete(j)
			}
			return nil
		}
	}

	if j.Execute != nil {
		err := j.Execute(ctx, j)
		if err != nil {
			j.finishWithError(1)
			j.mu.Lock()
			j.ErrorMsg = err.Error()
			j.mu.Unlock()
			if j.OnError != nil {
				j.OnError(j, err)
			}
			return err
		}
		if j.ParseOutput != nil {
			j.ItemsFound = j.ParseOutput(j)
		}
		j.mu.Lock()
		if j.Status != JobSkipped {
			j.Status = JobDone
			j.ExitCode = 0
		}
		j.FinishedAt = time.Now().UTC()
		j.mu.Unlock()
		if j.OnComplete != nil {
			j.OnComplete(j)
		}
		return nil
	}

	if strings.TrimSpace(j.Binary) == "" {
		if j.ParseOutput != nil {
			j.ItemsFound = j.ParseOutput(j)
		}
		j.mu.Lock()
		if j.Status != JobSkipped {
			j.Status = JobDone
			j.ExitCode = 0
		}
		j.FinishedAt = time.Now().UTC()
		j.mu.Unlock()
		if j.OnComplete != nil {
			j.OnComplete(j)
		}
		return nil
	}

	runCtx := ctx
	if runCtx == nil {
		runCtx = context.Background()
	}
	if j.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(runCtx, j.Timeout)
		j.cancel = cancel
	} else {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithCancel(runCtx)
		j.cancel = cancel
	}
	defer func() {
		if j.cancel != nil {
			j.cancel()
		}
	}()

	cmd := exec.CommandContext(runCtx, j.Binary, j.Args...)
	if j.WorkDir != "" {
		cmd.Dir = j.WorkDir
	}
	if len(j.Env) > 0 {
		cmd.Env = append(os.Environ(), j.Env...)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		j.finishWithError(1)
		runErr := fmt.Errorf("failed to create stdout pipe for %s: %w", j.ToolName, err)
		if j.OnError != nil {
			j.OnError(j, runErr)
		}
		return runErr
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		j.finishWithError(1)
		runErr := fmt.Errorf("failed to create stderr pipe for %s: %w", j.ToolName, err)
		if j.OnError != nil {
			j.OnError(j, runErr)
		}
		return runErr
	}

	stdoutWriter, stderrWriter, closers, err := j.prepareOutputWriters()
	if err != nil {
		j.finishWithError(1)
		if j.OnError != nil {
			j.OnError(j, err)
		}
		return err
	}
	defer func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}()

	if err := cmd.Start(); err != nil {
		j.finishWithError(1)
		runErr := fmt.Errorf("failed to start job %s: %w", j.ToolName, err)
		if j.OnError != nil {
			j.OnError(j, runErr)
		}
		return runErr
	}
	j.mu.Lock()
	j.cmd = cmd
	j.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		j.consumeStream(stdoutPipe, stdoutWriter)
	}()
	go func() {
		defer wg.Done()
		j.consumeStream(stderrPipe, stderrWriter)
	}()

	waitErr := cmd.Wait()
	wg.Wait()

	if waitErr != nil {
		exitCode := 1
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		j.finishWithError(exitCode)
		runErr := fmt.Errorf("job %s failed: %w", j.ToolName, waitErr)
		j.mu.Lock()
		j.ErrorMsg = runErr.Error()
		j.mu.Unlock()
		if j.OnError != nil {
			j.OnError(j, runErr)
		}
		return runErr
	}

	if j.ParseOutput != nil {
		j.ItemsFound = j.ParseOutput(j)
	}
	j.mu.Lock()
	if j.Status != JobSkipped {
		j.Status = JobDone
		j.ExitCode = 0
	}
	j.FinishedAt = time.Now().UTC()
	j.mu.Unlock()
	if j.OnComplete != nil {
		j.OnComplete(j)
	}
	return nil
}

func (j *Job) Kill() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cancel != nil {
		j.cancel()
	}
	if j.cmd != nil && j.cmd.Process != nil {
		_ = j.cmd.Process.Kill()
	}
}

func (j *Job) Duration() time.Duration {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.StartedAt.IsZero() {
		return 0
	}
	if j.FinishedAt.IsZero() {
		return time.Since(j.StartedAt)
	}
	return j.FinishedAt.Sub(j.StartedAt)
}

func (j *Job) LogLine(line string) {
	if j.OnLine != nil {
		j.OnLine(j, line)
	}
}

func (j *Job) consumeStream(reader io.Reader, writer io.Writer) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		j.LogLine(line)
		if writer != nil {
			_, _ = io.WriteString(writer, line+"\n")
		}
	}
}

func (j *Job) prepareOutputWriters() (io.Writer, io.Writer, []io.Closer, error) {
	closers := make([]io.Closer, 0, 3)
	shared := make([]io.Writer, 0, 1)
	stdoutWriters := make([]io.Writer, 0, 2)
	stderrWriters := make([]io.Writer, 0, 2)

	if j.OutputFile != "" {
		f, err := openAppendFile(j.OutputFile)
		if err != nil {
			return nil, nil, nil, err
		}
		closers = append(closers, f)
		shared = append(shared, f)
	}
	if j.StdoutFile != "" {
		f, err := openAppendFile(j.StdoutFile)
		if err != nil {
			return nil, nil, nil, err
		}
		closers = append(closers, f)
		stdoutWriters = append(stdoutWriters, f)
	}
	if j.StderrFile != "" {
		f, err := openAppendFile(j.StderrFile)
		if err != nil {
			return nil, nil, nil, err
		}
		closers = append(closers, f)
		stderrWriters = append(stderrWriters, f)
	}

	stdoutWriters = append(stdoutWriters, shared...)
	stderrWriters = append(stderrWriters, shared...)
	if len(stdoutWriters) == 0 {
		stdoutWriters = append(stdoutWriters, io.Discard)
	}
	if len(stderrWriters) == 0 {
		stderrWriters = append(stderrWriters, io.Discard)
	}
	return io.MultiWriter(stdoutWriters...), io.MultiWriter(stderrWriters...), closers, nil
}

func (j *Job) finishWithError(exitCode int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Status = JobFailed
	j.ExitCode = exitCode
	if j.ErrorMsg == "" {
		j.ErrorMsg = "job failed"
	}
	j.FinishedAt = time.Now().UTC()
}

func openAppendFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory for %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open output file %s: %w", path, err)
	}
	return f, nil
}
