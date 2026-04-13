package phase1

import (
	"testing"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/testutil"
)

func phase1Jobs(t *testing.T) []*engine.Job {
	t.Helper()
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}
	return Jobs(target, workspace, runCfg)
}

func TestPhase1Jobs(t *testing.T) {
	if jobs := phase1Jobs(t); len(jobs) == 0 {
		t.Fatal("expected non-empty phase 1 job list")
	}
}

func TestPhase1JobIDs(t *testing.T) {
	if err := testutil.ValidateJobIDs(phase1Jobs(t)); err != nil {
		t.Fatalf("phase 1 job IDs invalid: %v", err)
	}
}

func TestPhase1Dependencies(t *testing.T) {
	if err := testutil.ValidateDependencies(phase1Jobs(t)); err != nil {
		t.Fatalf("phase 1 dependencies invalid: %v", err)
	}
}

