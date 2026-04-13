package models

import "time"

type CampaignStatus string

const (
	CampaignPending CampaignStatus = "pending"
	CampaignRunning CampaignStatus = "running"
	CampaignDone    CampaignStatus = "done"
	CampaignFailed  CampaignStatus = "failed"
)

type Campaign struct {
	ID        string
	Name      string
	Targets   []Target
	Status    CampaignStatus
	StartedAt time.Time
	CreatedAt time.Time
}
