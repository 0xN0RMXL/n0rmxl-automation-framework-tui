package phase2

import (
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/phases/testutil"
)

func phase2Jobs(t *testing.T) []*engine.Job {
	t.Helper()
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}
	return Jobs(target, workspace, runCfg)
}

func TestPhase2Jobs(t *testing.T) {
	if jobs := phase2Jobs(t); len(jobs) == 0 {
		t.Fatal("expected non-empty phase 2 job list")
	}
}

func TestPhase2JobIDs(t *testing.T) {
	if err := testutil.ValidateJobIDs(phase2Jobs(t)); err != nil {
		t.Fatalf("phase 2 job IDs invalid: %v", err)
	}
}

func TestPhase2Dependencies(t *testing.T) {
	if err := testutil.ValidateDependencies(phase2Jobs(t)); err != nil {
		t.Fatalf("phase 2 dependencies invalid: %v", err)
	}
}
