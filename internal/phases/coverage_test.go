package phases

import (
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/phases/testutil"
)

func TestPhaseJobCounts(t *testing.T) {
	target, workspace, runCfg, err := testutil.SampleRunContext(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("SampleRunContext failed: %v", err)
	}

	expectedMinJobs := map[int]int{
		0: 3,
		1: 15,
		2: 10,
		3: 8,
		4: 12,
		5: 10,
		6: 5,
		7: 4,
		8: 6,
		9: 4,
	}

	total := 0
	for phase, minJobs := range expectedMinJobs {
		jobs, err := JobsForPhase(phase, target, workspace, runCfg)
		if err != nil {
			t.Fatalf("JobsForPhase(%d) failed: %v", phase, err)
		}
		if len(jobs) < minJobs {
			t.Fatalf("phase %d expected at least %d jobs, got %d", phase, minJobs, len(jobs))
		}
		if err := testutil.ValidateJobIDs(jobs); err != nil {
			t.Fatalf("phase %d job IDs invalid: %v", phase, err)
		}
		if err := testutil.ValidateDependencies(jobs); err != nil {
			t.Fatalf("phase %d dependencies invalid: %v", phase, err)
		}
		total += len(jobs)
	}

	if total <= 200 {
		t.Fatalf("expected total phase jobs to exceed 200, got %d", total)
	}
}
