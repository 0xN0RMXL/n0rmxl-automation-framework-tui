package engine

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

func TestPhaseRunnerEmpty(t *testing.T) {
	runner := NewPhaseRunner(1, nil, nil)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("empty runner should succeed, got %v", err)
	}
}

func TestPhaseRunnerSingleJob(t *testing.T) {
	runner := NewPhaseRunner(1, nil, nil)
	executed := false

	job := NewJob(1, "single", "", nil)
	job.Execute = func(ctx context.Context, j *Job) error {
		executed = true
		return nil
	}

	runner.AddJob(job)
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !executed {
		t.Fatal("expected single job to execute")
	}
	if job.Status != JobDone {
		t.Fatalf("expected job done, got %q", job.Status)
	}
}

func TestPhaseRunnerDependency(t *testing.T) {
	runner := NewPhaseRunner(1, nil, nil)
	var (
		mu    sync.Mutex
		order []string
	)

	jobA := NewJob(1, "a", "", nil)
	jobA.Execute = func(ctx context.Context, j *Job) error {
		mu.Lock()
		order = append(order, "a")
		mu.Unlock()
		return nil
	}

	jobB := NewJob(1, "b", "", nil)
	jobB.DependsOn = []string{jobA.ID}
	jobB.Execute = func(ctx context.Context, j *Job) error {
		mu.Lock()
		order = append(order, "b")
		mu.Unlock()
		return nil
	}

	runner.AddJob(jobA)
	runner.AddJob(jobB)

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !reflect.DeepEqual(order, []string{"a", "b"}) {
		t.Fatalf("expected dependency order [a b], got %v", order)
	}
}

func TestPhaseRunnerCancelContext(t *testing.T) {
	runCfg := config.NewRunConfig(models.Normal, config.DefaultConfig())
	runner := NewPhaseRunner(1, &runCfg, nil)

	job := NewJob(1, "blocking", "", nil)
	job.Required = true
	job.Execute = func(ctx context.Context, j *Job) error {
		<-ctx.Done()
		return ctx.Err()
	}
	runner.AddJob(job)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err := runner.Run(ctx)
	if err == nil {
		t.Fatal("expected cancelled run to return an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
}

func TestPhaseRunnerCheckpointSkip(t *testing.T) {
	checkpoint, err := NewCheckpoint(t.TempDir())
	if err != nil {
		t.Fatalf("NewCheckpoint failed: %v", err)
	}
	defer checkpoint.Close()

	if err := checkpoint.SetToolStatus(1, "skip-me", models.ToolResult{ToolName: "skip-me", Status: models.PhaseDone}); err != nil {
		t.Fatalf("SetToolStatus failed: %v", err)
	}

	runner := NewPhaseRunner(1, nil, checkpoint)
	skipped := NewJob(1, "skip-me", "", nil)
	skipped.Execute = func(ctx context.Context, j *Job) error {
		t.Fatal("checkpointed job should not execute")
		return nil
	}

	ran := false
	followUp := NewJob(1, "run-me", "", nil)
	followUp.DependsOn = []string{skipped.ID}
	followUp.Execute = func(ctx context.Context, j *Job) error {
		ran = true
		return nil
	}

	runner.AddJob(skipped)
	runner.AddJob(followUp)

	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if skipped.Status != JobSkipped {
		t.Fatalf("expected skip-me to be skipped, got %q", skipped.Status)
	}
	if !ran || followUp.Status != JobDone {
		t.Fatalf("expected follow-up job to run successfully, ran=%t status=%q", ran, followUp.Status)
	}
}

