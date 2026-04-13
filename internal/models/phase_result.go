package models

import "time"

type PhaseStatus string

const (
	PhasePending PhaseStatus = "pending"
	PhaseRunning PhaseStatus = "running"
	PhaseDone    PhaseStatus = "done"
	PhaseFailed  PhaseStatus = "failed"
	PhaseSkipped PhaseStatus = "skipped"
)

type ToolResult struct {
	ToolName   string
	Status     PhaseStatus
	OutputFile string
	StartedAt  time.Time
	FinishedAt time.Time
	ItemsFound int
	Error      string
}

type PhaseResult struct {
	Phase      int
	Status     PhaseStatus
	StartedAt  time.Time
	FinishedAt time.Time
	Tools      []ToolResult
	Findings   []Finding
	Summary    string
}
