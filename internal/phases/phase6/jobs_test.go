package phase6

import (
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/phases/testutil"
)

func phase6Jobs(t *testing.T) []*engine.Job {
	t.Helper()
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}
	return Jobs(target, workspace, runCfg)
}

func TestPhase6Jobs(t *testing.T) {
	if jobs := phase6Jobs(t); len(jobs) == 0 {
		t.Fatal("expected non-empty phase 6 job list")
	}
}

func TestPhase6JobIDs(t *testing.T) {
	if err := testutil.ValidateJobIDs(phase6Jobs(t)); err != nil {
		t.Fatalf("phase 6 job IDs invalid: %v", err)
	}
}

func TestPhase6Dependencies(t *testing.T) {
	if err := testutil.ValidateDependencies(phase6Jobs(t)); err != nil {
		t.Fatalf("phase 6 dependencies invalid: %v", err)
	}
}
