package models

import "time"

type StealthProfile string

const (
	Slow       StealthProfile = "slow"
	Normal     StealthProfile = "normal"
	Aggressive StealthProfile = "aggressive"
)

type ProfileSettings struct {
	Threads        int
	RateLimit      int
	DNSResolvers   string
	NucleiRate     int
	NmapTiming     string
	DelayBetween   time.Duration
	RotateUA       bool
	RandomizeOrder bool
}

func GetProfile(p StealthProfile) ProfileSettings {
	switch p {
	case Slow:
		return ProfileSettings{
			Threads:        5,
			RateLimit:      10,
			DNSResolvers:   "trusted",
			NucleiRate:     5,
			NmapTiming:     "T1",
			DelayBetween:   5 * time.Second,
			RotateUA:       true,
			RandomizeOrder: true,
		}
	case Aggressive:
		return ProfileSettings{
			Threads:        200,
			RateLimit:      0,
			DNSResolvers:   "all",
			NucleiRate:     150,
			NmapTiming:     "T4",
			DelayBetween:   0,
			RotateUA:       false,
			RandomizeOrder: false,
		}
	default:
		return ProfileSettings{
			Threads:        50,
			RateLimit:      100,
			DNSResolvers:   "all",
			NucleiRate:     50,
			NmapTiming:     "T3",
			DelayBetween:   1 * time.Second,
			RotateUA:       true,
			RandomizeOrder: false,
		}
	}
}
