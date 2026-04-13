package config

import (
	"strings"

	"github.com/n0rmxl/n0rmxl/internal/models"
)

type ToolOverrides struct {
	NucleiTemplates []string          `yaml:"nuclei_templates"`
	NucleiExclude   []string          `yaml:"nuclei_exclude"`
	SkipTools       []string          `yaml:"skip_tools"`
	ExtraFlags      map[string]string `yaml:"extra_flags"`
}

type RunConfig struct {
	Profile   models.StealthProfile
	Settings  models.ProfileSettings
	Overrides ToolOverrides
	UseBurp   bool
	Scope     *Scope
}

func NewRunConfig(profile models.StealthProfile, cfg *Config) RunConfig {
	normalized := normalizeProfile(profile, cfg)
	return RunConfig{
		Profile:  normalized,
		Settings: models.GetProfile(normalized),
		Overrides: ToolOverrides{
			NucleiTemplates: []string{"cves", "exposures", "misconfiguration"},
			ExtraFlags:      make(map[string]string),
		},
		UseBurp: cfg != nil && cfg.Burp.Enabled,
		Scope:   &Scope{},
	}
}

func normalizeProfile(profile models.StealthProfile, cfg *Config) models.StealthProfile {
	if profile == models.Slow || profile == models.Normal || profile == models.Aggressive {
		return profile
	}
	if cfg != nil {
		switch strings.ToLower(strings.TrimSpace(cfg.StealthProfile)) {
		case string(models.Slow):
			return models.Slow
		case string(models.Aggressive):
			return models.Aggressive
		default:
			return models.Normal
		}
	}
	return models.Normal
}
