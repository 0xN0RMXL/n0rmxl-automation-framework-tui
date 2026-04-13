package phase4

import (
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/phases/testutil"
)

func phase4Jobs(t *testing.T) []*engine.Job {
	t.Helper()
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}
	return Jobs(target, workspace, runCfg)
}

func TestPhase4Jobs(t *testing.T) {
	if jobs := phase4Jobs(t); len(jobs) == 0 {
		t.Fatal("expected non-empty phase 4 job list")
	}
}

func TestPhase4JobIDs(t *testing.T) {
	if err := testutil.ValidateJobIDs(phase4Jobs(t)); err != nil {
		t.Fatalf("phase 4 job IDs invalid: %v", err)
	}
}

func TestPhase4Dependencies(t *testing.T) {
	if err := testutil.ValidateDependencies(phase4Jobs(t)); err != nil {
		t.Fatalf("phase 4 dependencies invalid: %v", err)
	}
}
