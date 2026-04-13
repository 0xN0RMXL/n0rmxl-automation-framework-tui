package phase7

import (
	"testing"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/testutil"
)

func phase7Jobs(t *testing.T) []*engine.Job {
	t.Helper()
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}
	return Jobs(target, workspace, runCfg)
}

func TestPhase7Jobs(t *testing.T) {
	if jobs := phase7Jobs(t); len(jobs) == 0 {
		t.Fatal("expected non-empty phase 7 job list")
	}
}

func TestPhase7JobIDs(t *testing.T) {
	if err := testutil.ValidateJobIDs(phase7Jobs(t)); err != nil {
		t.Fatalf("phase 7 job IDs invalid: %v", err)
	}
}

func TestPhase7Dependencies(t *testing.T) {
	if err := testutil.ValidateDependencies(phase7Jobs(t)); err != nil {
		t.Fatalf("phase 7 dependencies invalid: %v", err)
	}
}

