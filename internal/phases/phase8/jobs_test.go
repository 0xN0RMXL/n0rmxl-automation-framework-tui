package phase8

import (
	"testing"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/testutil"
)

func phase8Jobs(t *testing.T) []*engine.Job {
	t.Helper()
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}
	return Jobs(target, workspace, runCfg)
}

func TestPhase8Jobs(t *testing.T) {
	if jobs := phase8Jobs(t); len(jobs) == 0 {
		t.Fatal("expected non-empty phase 8 job list")
	}
}

func TestPhase8JobIDs(t *testing.T) {
	if err := testutil.ValidateJobIDs(phase8Jobs(t)); err != nil {
		t.Fatalf("phase 8 job IDs invalid: %v", err)
	}
}

func TestPhase8Dependencies(t *testing.T) {
	if err := testutil.ValidateDependencies(phase8Jobs(t)); err != nil {
		t.Fatalf("phase 8 dependencies invalid: %v", err)
	}
}

