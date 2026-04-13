package screens

import "testing"

func hasArg(args []string, needle string) bool {
	for _, arg := range args {
		if arg == needle {
			return true
		}
	}
	return false
}

func indexOfArg(args []string, needle string) int {
	for i, arg := range args {
		if arg == needle {
			return i
		}
	}
	return -1
}

func TestBuildCampaignCommandArgsRunAllDefaultsToAllPhases(t *testing.T) {
	args := buildCampaignCommandArgs("/tmp/ws", "/tmp/state.json", "", false)
	if hasArg(args, "--resume") {
		t.Fatal("did not expect --resume in run-all mode")
	}
	phaseFlagIdx := indexOfArg(args, "--phases")
	if phaseFlagIdx < 0 || phaseFlagIdx+1 >= len(args) {
		t.Fatalf("expected --phases flag with value, got %v", args)
	}
	if args[phaseFlagIdx+1] != "0,1,2,3,4,5,6,7,8,9" {
		t.Fatalf("unexpected default phase spec: %q", args[phaseFlagIdx+1])
	}
}

func TestBuildCampaignCommandArgsResumeOmitsPhases(t *testing.T) {
	args := buildCampaignCommandArgs("/tmp/ws", "/tmp/state.json", "5,6", true)
	if !hasArg(args, "--resume") {
		t.Fatalf("expected --resume flag, got %v", args)
	}
	if hasArg(args, "--phases") {
		t.Fatalf("did not expect --phases flag in resume mode, got %v", args)
	}
}

func TestDefaultCampaignRunPhaseSpec(t *testing.T) {
	if got := defaultCampaignRunPhaseSpec(" "); got != "0,1,2,3,4,5,6,7,8,9" {
		t.Fatalf("unexpected default phase spec: %q", got)
	}
	if got := defaultCampaignRunPhaseSpec("6"); got != "6" {
		t.Fatalf("expected explicit phase spec preserved, got %q", got)
	}
}

func TestValidateCampaignAction(t *testing.T) {
	if got := validateCampaignAction(false, true, 2, true); got == "" {
		t.Fatal("expected warning for in-progress campaign run")
	}
	if got := validateCampaignAction(false, false, 0, true); got == "" {
		t.Fatal("expected warning for empty campaign target list")
	}
	if got := validateCampaignAction(true, false, 2, false); got == "" {
		t.Fatal("expected warning for resume without state")
	}
	if got := validateCampaignAction(false, false, 2, false); got != "" {
		t.Fatalf("expected no warning for valid run-all action, got %q", got)
	}
	if got := validateCampaignAction(true, false, 2, true); got != "" {
		t.Fatalf("expected no warning for valid resume action, got %q", got)
	}
}

func TestSummarizeCampaignRunOutputPrefersCampaignSummary(t *testing.T) {
	output := "line one\n[n0rmxl] campaign run complete: 2 succeeded, 1 failed\nline tail"
	got := summarizeCampaignRunOutput(output)
	want := "[n0rmxl] campaign run complete: 2 succeeded, 1 failed"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestSummarizeCampaignRunOutputFallsBackToLastLine(t *testing.T) {
	output := "first\nsecond\nfinal message"
	got := summarizeCampaignRunOutput(output)
	if got != "final message" {
		t.Fatalf("expected final message, got %q", got)
	}
}

func TestSummarizeCampaignRunOutputEmpty(t *testing.T) {
	if got := summarizeCampaignRunOutput("   \n\t"); got != "" {
		t.Fatalf("expected empty summary, got %q", got)
	}
}

func TestNormalizeCampaignRunStatus(t *testing.T) {
	cases := map[string]string{
		"succeeded": "succeeded",
		"failed":    "failed",
		"missing":   "missing",
		"pending":   "pending",
		"queued":    "pending",
		"running":   "pending",
		"unknown":   "pending",
	}
	for input, want := range cases {
		if got := normalizeCampaignRunStatus(input); got != want {
			t.Fatalf("input %q: expected %q, got %q", input, want, got)
		}
	}
}
