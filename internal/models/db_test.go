package models

import "testing"

func TestInitFindingsDB(t *testing.T) {
	db, err := InitFindingsDB(t.TempDir())
	if err != nil {
		t.Fatalf("InitFindingsDB failed: %v", err)
	}
	defer db.Close()
}

func TestSaveAndGetFinding(t *testing.T) {
	db, err := InitFindingsDB(t.TempDir())
	if err != nil {
		t.Fatalf("InitFindingsDB failed: %v", err)
	}
	defer db.Close()

	input := Finding{
		Phase:       5,
		VulnClass:   "xss",
		Target:      "example.com",
		Host:        "app.example.com",
		URL:         "https://app.example.com/search?q=test",
		Severity:    High,
		Title:       "Reflected XSS in search",
		Description: "Reflected input reaches HTML sink.",
		Tool:        "dalfox",
		Confirmed:   true,
	}
	if err := SaveFinding(db, input); err != nil {
		t.Fatalf("SaveFinding failed: %v", err)
	}

	findings, err := GetFindings(db, FindingFilter{})
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Title != input.Title {
		t.Fatalf("expected title %q, got %q", input.Title, findings[0].Title)
	}
}

func TestFindingFilterBySeverity(t *testing.T) {
	db, err := InitFindingsDB(t.TempDir())
	if err != nil {
		t.Fatalf("InitFindingsDB failed: %v", err)
	}
	defer db.Close()

	if err := SaveFinding(db, Finding{Phase: 4, VulnClass: "xss", Target: "example.com", Host: "a.example.com", URL: "https://a.example.com", Severity: High, Title: "high"}); err != nil {
		t.Fatalf("SaveFinding high failed: %v", err)
	}
	if err := SaveFinding(db, Finding{Phase: 4, VulnClass: "info-disclosure", Target: "example.com", Host: "b.example.com", URL: "https://b.example.com", Severity: Low, Title: "low"}); err != nil {
		t.Fatalf("SaveFinding low failed: %v", err)
	}

	sev := High
	findings, err := GetFindings(db, FindingFilter{Severity: &sev})
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 high severity finding, got %d", len(findings))
	}
	if findings[0].Severity != High {
		t.Fatalf("expected high severity, got %q", findings[0].Severity)
	}
}

func TestFindingDedup(t *testing.T) {
	db, err := InitFindingsDB(t.TempDir())
	if err != nil {
		t.Fatalf("InitFindingsDB failed: %v", err)
	}
	defer db.Close()

	first := Finding{
		ID:          "first",
		Phase:       5,
		VulnClass:   "sqli",
		Target:      "example.com",
		Host:        "app.example.com",
		URL:         "https://app.example.com/item?id=1",
		Method:      "GET",
		Parameter:   "id",
		Payload:     "'",
		Severity:    High,
		Title:       "SQL injection",
		Description: "first write",
		Tool:        "sqlmap",
	}
	second := first
	second.ID = "second"
	second.Description = "updated write"

	if err := SaveFinding(db, first); err != nil {
		t.Fatalf("SaveFinding first failed: %v", err)
	}
	if err := SaveFinding(db, second); err != nil {
		t.Fatalf("SaveFinding second failed: %v", err)
	}

	findings, err := GetFindings(db, FindingFilter{})
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected deduped single finding, got %d", len(findings))
	}
	if findings[0].Description != "updated write" {
		t.Fatalf("expected conflict update to retain latest description, got %q", findings[0].Description)
	}
}
