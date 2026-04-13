package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/models"
)

func TestDefaultTextValue(t *testing.T) {
	if got := defaultTextValue("  ", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback, got %q", got)
	}
	if got := defaultTextValue("ready", "fallback"); got != "ready" {
		t.Fatalf("expected ready, got %q", got)
	}
}

func TestApplyCampaignRunStateToSummaries(t *testing.T) {
	summaries := []campaignSummary{
		{Target: "alpha.example", Status: models.PhasePending},
		{Target: "beta.example", Status: models.PhaseDone},
	}
	state := &campaignRunState{
		Targets: map[string]campaignTargetState{
			"alpha.example": {Status: campaignTargetSucceeded},
			"beta.example":  {Status: campaignTargetFailed},
		},
	}

	updated := applyCampaignRunStateToSummaries(summaries, state)
	if updated[0].RunStatus != "succeeded" {
		t.Fatalf("expected alpha run status succeeded, got %q", updated[0].RunStatus)
	}
	if updated[1].RunStatus != "failed" {
		t.Fatalf("expected beta run status failed, got %q", updated[1].RunStatus)
	}
}

func TestSummarizeCampaignRunState(t *testing.T) {
	started := time.Now().UTC().Add(-5 * time.Minute)
	updated := started.Add(3 * time.Minute)
	state := &campaignRunState{
		PhaseSpec: "6,7",
		StartedAt: started,
		UpdatedAt: updated,
		Targets: map[string]campaignTargetState{
			"a": {Status: campaignTargetPending},
			"b": {Status: campaignTargetSucceeded},
			"c": {Status: campaignTargetFailed},
			"d": {Status: campaignTargetMissing},
		},
	}

	phaseSpec, gotUpdated, pending, succeeded, failed, missing := summarizeCampaignRunState(state)
	if phaseSpec != "6,7" {
		t.Fatalf("expected phase spec 6,7, got %q", phaseSpec)
	}
	if !gotUpdated.Equal(updated) {
		t.Fatalf("expected updated time %v, got %v", updated, gotUpdated)
	}
	if pending != 1 || succeeded != 1 || failed != 1 || missing != 1 {
		t.Fatalf("unexpected counts: pending=%d succeeded=%d failed=%d missing=%d", pending, succeeded, failed, missing)
	}
}

func TestLoadCampaignRunStateNotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-state.json")
	_, err := loadCampaignRunState(path)
	if err == nil {
		t.Fatal("expected error for missing campaign state file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected not-exist semantics, got %v", err)
	}
}

func TestSaveLoadCampaignRunStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := &campaignRunState{
		ID:            "campaign-test",
		WorkspaceRoot: "/tmp/workspace",
		PhaseSpec:     "6",
		StartedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
		Targets: map[string]campaignTargetState{
			"alpha.example": {
				Status:          campaignTargetSucceeded,
				LastError:       "",
				UpdatedAt:       time.Now().UTC(),
				DurationSeconds: 3,
			},
		},
	}

	if err := saveCampaignRunState(path, state); err != nil {
		t.Fatalf("saveCampaignRunState failed: %v", err)
	}

	loaded, err := loadCampaignRunState(path)
	if err != nil {
		t.Fatalf("loadCampaignRunState failed: %v", err)
	}

	if loaded.ID != state.ID {
		t.Fatalf("expected ID %q, got %q", state.ID, loaded.ID)
	}
	if loaded.PhaseSpec != state.PhaseSpec {
		t.Fatalf("expected phase spec %q, got %q", state.PhaseSpec, loaded.PhaseSpec)
	}
	alpha, ok := loaded.Targets["alpha.example"]
	if !ok {
		t.Fatal("expected alpha.example in loaded state")
	}
	if alpha.Status != campaignTargetSucceeded {
		t.Fatalf("expected alpha status succeeded, got %q", alpha.Status)
	}
}

func TestParsePhaseList(t *testing.T) {
	got, err := parsePhaseList("0,1,2,3,4,5,6,7,8,9")
	if err != nil {
		t.Fatalf("parsePhaseList returned error: %v", err)
	}
	want := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestParsePhaseListInvalid(t *testing.T) {
	if _, err := parsePhaseList("0,99"); err == nil {
		t.Fatal("expected invalid phase list to return an error")
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path := defaultConfigPath()
	if strings.TrimSpace(path) == "" {
		t.Fatal("default config path should not be empty")
	}
	if !strings.Contains(strings.ToLower(filepath.ToSlash(path)), "n0rmxl") {
		t.Fatalf("expected default config path to contain n0rmxl, got %q", path)
	}
}

func TestVersionCommand(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "n0rmxl")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	buildCmd := exec.Command("go", "build", "-o", bin, ".")
	buildCmd.Dir = "."
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, string(buildOutput))
	}

	versionCmd := exec.Command(bin, "version")
	output, err := versionCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v\n%s", err, string(output))
	}
	if !strings.Contains(string(output), "n0rmxl") {
		t.Fatalf("expected version output to mention n0rmxl, got %q", string(output))
	}
}
