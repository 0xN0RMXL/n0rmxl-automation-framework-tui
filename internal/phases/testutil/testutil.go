package testutil

import (
	"fmt"
	"strings"

	"github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

func SampleRunContext(root string, domain string) (*models.Target, models.Workspace, *config.RunConfig, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		domain = "example.com"
	}

	workspace := models.NewWorkspace(root, domain)
	if err := workspace.EnsureAll(); err != nil {
		return nil, workspace, nil, err
	}

	cfg := config.DefaultConfig()
	cfg.WorkspaceRoot = root
	runCfgValue := config.NewRunConfig(models.Normal, cfg)
	runCfgValue.Scope = &config.Scope{
		Wildcards: []string{"*." + domain},
	}

	target := &models.Target{
		Domain:       domain,
		WorkspaceDir: root,
		Wildcards:    []string{"*." + domain},
		Profile:      models.Normal,
	}
	return target, workspace, &runCfgValue, nil
}

func ValidateJobIDs(jobs []*engine.Job) error {
	if len(jobs) == 0 {
		return fmt.Errorf("job list is empty")
	}
	seen := make(map[string]struct{}, len(jobs))
	for idx, job := range jobs {
		if job == nil {
			return fmt.Errorf("job %d is nil", idx)
		}
		if strings.TrimSpace(job.ID) == "" {
			return fmt.Errorf("job %d has empty ID", idx)
		}
		if _, ok := seen[job.ID]; ok {
			return fmt.Errorf("duplicate job ID %q", job.ID)
		}
		seen[job.ID] = struct{}{}
	}
	return nil
}

func ValidateDependencies(jobs []*engine.Job) error {
	if len(jobs) == 0 {
		return fmt.Errorf("job list is empty")
	}
	ids := make(map[string]struct{}, len(jobs))
	toolNames := make(map[string]struct{}, len(jobs))
	for idx, job := range jobs {
		if job == nil {
			return fmt.Errorf("job %d is nil", idx)
		}
		ids[job.ID] = struct{}{}
		if strings.TrimSpace(job.ToolName) != "" {
			toolNames[job.ToolName] = struct{}{}
		}
	}
	for _, job := range jobs {
		for _, dep := range job.DependsOn {
			dep = strings.TrimSpace(dep)
			if dep == "" {
				continue
			}
			if _, ok := ids[dep]; ok {
				continue
			}
			if _, ok := toolNames[dep]; ok {
				continue
			}
			return fmt.Errorf("job %q references missing dependency %q", job.ID, dep)
		}
	}
	return nil
}
