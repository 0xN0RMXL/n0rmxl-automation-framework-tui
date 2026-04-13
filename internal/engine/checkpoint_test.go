package engine

import (
	"testing"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

func TestCheckpointRoundTrip(t *testing.T) {
	checkpoint, err := NewCheckpoint(t.TempDir())
	if err != nil {
		t.Fatalf("NewCheckpoint failed: %v", err)
	}
	defer checkpoint.Close()

	if err := checkpoint.SetPhaseStatus(3, models.PhaseDone); err != nil {
		t.Fatalf("SetPhaseStatus failed: %v", err)
	}

	status, err := checkpoint.GetPhaseStatus(3)
	if err != nil {
		t.Fatalf("GetPhaseStatus failed: %v", err)
	}
	if status != models.PhaseDone {
		t.Fatalf("expected phase done, got %q", status)
	}
}

func TestCheckpointToolStatus(t *testing.T) {
	checkpoint, err := NewCheckpoint(t.TempDir())
	if err != nil {
		t.Fatalf("NewCheckpoint failed: %v", err)
	}
	defer checkpoint.Close()

	started := time.Now().UTC().Add(-time.Minute)
	finished := time.Now().UTC()
	input := models.ToolResult{
		ToolName:   "httpx",
		Status:     models.PhaseDone,
		OutputFile: "/tmp/httpx.txt",
		StartedAt:  started,
		FinishedAt: finished,
		ItemsFound: 42,
	}
	if err := checkpoint.SetToolStatus(2, "httpx", input); err != nil {
		t.Fatalf("SetToolStatus failed: %v", err)
	}

	got, err := checkpoint.GetToolStatus(2, "httpx")
	if err != nil {
		t.Fatalf("GetToolStatus failed: %v", err)
	}
	if got.Status != models.PhaseDone || got.ItemsFound != 42 {
		t.Fatalf("unexpected tool status: %+v", got)
	}
}

func TestCheckpointIsToolDone(t *testing.T) {
	checkpoint, err := NewCheckpoint(t.TempDir())
	if err != nil {
		t.Fatalf("NewCheckpoint failed: %v", err)
	}
	defer checkpoint.Close()

	if checkpoint.IsToolDone(1, "nuclei") {
		t.Fatal("expected unknown tool to be incomplete")
	}
	if err := checkpoint.SetToolStatus(1, "nuclei", models.ToolResult{ToolName: "nuclei", Status: models.PhaseFailed}); err != nil {
		t.Fatalf("SetToolStatus failed: %v", err)
	}
	if checkpoint.IsToolDone(1, "nuclei") {
		t.Fatal("expected failed tool not to count as done")
	}
	if err := checkpoint.SetToolStatus(1, "nuclei", models.ToolResult{ToolName: "nuclei", Status: models.PhaseDone}); err != nil {
		t.Fatalf("SetToolStatus failed: %v", err)
	}
	if !checkpoint.IsToolDone(1, "nuclei") {
		t.Fatal("expected done tool to count as complete")
	}
}

func TestCheckpointReset(t *testing.T) {
	checkpoint, err := NewCheckpoint(t.TempDir())
	if err != nil {
		t.Fatalf("NewCheckpoint failed: %v", err)
	}
	defer checkpoint.Close()

	if err := checkpoint.SetPhaseStatus(4, models.PhaseDone); err != nil {
		t.Fatalf("SetPhaseStatus failed: %v", err)
	}
	if err := checkpoint.Reset(4); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	status, err := checkpoint.GetPhaseStatus(4)
	if err != nil {
		t.Fatalf("GetPhaseStatus failed: %v", err)
	}
	if status != models.PhasePending {
		t.Fatalf("expected phase pending after reset, got %q", status)
	}
}

