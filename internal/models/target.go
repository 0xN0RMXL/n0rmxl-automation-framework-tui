package models

import "time"

type Target struct {
	Domain       string
	Wildcards    []string
	Explicit     []string
	IPRanges     []string
	OutOfScope   []string
	Platform     string
	ProgramURL   string
	WorkspaceDir string
	StartedAt    time.Time
	Profile      StealthProfile
}
