package phase9

import (
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/phases/testutil"
)

func phase9Jobs(t *testing.T) []*engine.Job {
	t.Helper()
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}
	return Jobs(target, workspace, runCfg)
}

func TestPhase9Jobs(t *testing.T) {
	if jobs := phase9Jobs(t); len(jobs) == 0 {
		t.Fatal("expected non-empty phase 9 job list")
	}
}

func TestPhase9JobIDs(t *testing.T) {
	if err := testutil.ValidateJobIDs(phase9Jobs(t)); err != nil {
		t.Fatalf("phase 9 job IDs invalid: %v", err)
	}
}

func TestPhase9Dependencies(t *testing.T) {
	if err := testutil.ValidateDependencies(phase9Jobs(t)); err != nil {
		t.Fatalf("phase 9 dependencies invalid: %v", err)
	}
}
