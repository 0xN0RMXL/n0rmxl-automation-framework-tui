package phase3

import (
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/phases/testutil"
)

func phase3Jobs(t *testing.T) []*engine.Job {
	t.Helper()
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}
	return Jobs(target, workspace, runCfg)
}

func TestPhase3Jobs(t *testing.T) {
	if jobs := phase3Jobs(t); len(jobs) == 0 {
		t.Fatal("expected non-empty phase 3 job list")
	}
}

func TestPhase3JobIDs(t *testing.T) {
	if err := testutil.ValidateJobIDs(phase3Jobs(t)); err != nil {
		t.Fatalf("phase 3 job IDs invalid: %v", err)
	}
}

func TestPhase3Dependencies(t *testing.T) {
	if err := testutil.ValidateDependencies(phase3Jobs(t)); err != nil {
		t.Fatalf("phase 3 dependencies invalid: %v", err)
	}
}
