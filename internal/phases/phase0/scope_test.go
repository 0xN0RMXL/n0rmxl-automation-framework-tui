package phase0

import (
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/phases/testutil"
)

func phase0Jobs(t *testing.T) int {
	t.Helper()
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}
	jobs := Jobs(target, workspace, runCfg)
	if len(jobs) == 0 {
		t.Fatal("expected non-empty phase 0 job list")
	}
	return len(jobs)
}

func TestPhase0Jobs(t *testing.T) {
	if got := phase0Jobs(t); got == 0 {
		t.Fatal("expected phase 0 jobs")
	}
}

func TestPhase0NoNilJobs(t *testing.T) {
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}
	jobs := Jobs(target, workspace, runCfg)
	for idx, job := range jobs {
		if job == nil {
			t.Fatalf("job %d is nil", idx)
		}
	}
}
