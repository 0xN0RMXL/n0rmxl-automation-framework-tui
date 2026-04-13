package phase5

import (
	"testing"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/testutil"
)

func phase5Jobs(t *testing.T) []*engine.Job {
	t.Helper()
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}
	return Jobs(target, workspace, runCfg)
}

func TestPhase5Jobs(t *testing.T) {
	if jobs := phase5Jobs(t); len(jobs) == 0 {
		t.Fatal("expected non-empty phase 5 job list")
	}
}

func TestPhase5JobIDs(t *testing.T) {
	if err := testutil.ValidateJobIDs(phase5Jobs(t)); err != nil {
		t.Fatalf("phase 5 job IDs invalid: %v", err)
	}
}

func TestPhase5Dependencies(t *testing.T) {
	if err := testutil.ValidateDependencies(phase5Jobs(t)); err != nil {
		t.Fatalf("phase 5 dependencies invalid: %v", err)
	}
}

