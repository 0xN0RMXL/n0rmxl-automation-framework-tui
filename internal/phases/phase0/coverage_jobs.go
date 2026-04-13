package phase0

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

func buildCoverageJobs(target *models.Target, ws models.Workspace, runCfg *config.RunConfig, workspaceInitID string) []*engine.Job {
	specs := []struct {
		name        string
		description string
		output      string
		execute     func(context.Context, *engine.Job) error
	}{
		{
			name:        "workspace-layout-audit",
			description: "Verify the full workspace layout exists for the target",
			output:      filepath.Join(ws.Hidden, "phase0_workspace_layout.txt"),
			execute: func(_ context.Context, j *engine.Job) error {
				paths := []string{ws.Root, ws.ReconSubs, ws.ReconIPs, ws.ReconURLs, ws.ReconJS, ws.ReconParams, ws.Scans, ws.Vulns, ws.Reports, ws.Loot}
				lines := make([]string, 0, len(paths))
				for _, path := range paths {
					status := "missing"
					if info, err := os.Stat(path); err == nil && info.IsDir() {
						status = "ready"
					}
					lines = append(lines, fmt.Sprintf("%s | %s", status, path))
				}
				sort.Strings(lines)
				return os.WriteFile(j.OutputFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
			},
		},
		{
			name:        "env-alias-manifest",
			description: "Record exported environment aliases for provider-backed tools",
			output:      filepath.Join(ws.Hidden, "phase0_env_aliases.txt"),
			execute: func(_ context.Context, j *engine.Job) error {
				keys := collectAPIKeys()
				lines := make([]string, 0, len(keys))
				for alias, value := range map[string]string{
					"VT_API_KEY":         keys["virustotal"],
					"SHODAN_API_KEY":     keys["shodan"],
					"CENSYS_API_ID":      keys["censys_id"],
					"CENSYS_API_SECRET":  keys["censys_secret"],
					"PDCP_API_KEY":       keys["chaos"],
					"GITHUB_TOKEN":       keys["github"],
					"SECURITYTRAILS_KEY": keys["securitytrails"],
				} {
					state := "empty"
					if strings.TrimSpace(value) != "" {
						state = "set"
					}
					lines = append(lines, fmt.Sprintf("%s=%s", alias, state))
				}
				sort.Strings(lines)
				return os.WriteFile(j.OutputFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
			},
		},
		{
			name:        "amass-config-audit",
			description: "Audit amass provider configuration placement",
			output:      filepath.Join(ws.Hidden, "phase0_amass_config_audit.txt"),
			execute: func(_ context.Context, j *engine.Job) error {
				path := filepath.Join(expandHome("~"), ".config", "amass", "config.yaml")
				status := "missing"
				if fileInfo, err := os.Stat(path); err == nil && !fileInfo.IsDir() {
					status = "ready"
				}
				content := fmt.Sprintf("%s | %s\n", status, path)
				return os.WriteFile(j.OutputFile, []byte(content), 0o644)
			},
		},
		{
			name:        "scope-format-manifest",
			description: "Generate methodology-aligned scope summary sections",
			output:      filepath.Join(ws.Hidden, "phase0_scope_manifest.txt"),
			execute: func(_ context.Context, j *engine.Job) error {
				lines := []string{
					"DOMAIN=" + safeTargetDomain(target),
					"WILDCARD=" + strings.Join(normalizeList(target.Wildcards), ","),
					"EXPLICIT=" + strings.Join(normalizeList(target.Explicit), ","),
					"IP_RANGES=" + strings.Join(normalizeList(target.IPRanges), ","),
					"OOS=" + strings.Join(normalizeList(target.OutOfScope), ","),
				}
				return os.WriteFile(j.OutputFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
			},
		},
		{
			name:        "hacker-scoper-manifest",
			description: "Generate hacker-scoper compatible scope filter expression",
			output:      filepath.Join(ws.Hidden, "phase0_hacker_scoper.txt"),
			execute: func(_ context.Context, j *engine.Job) error {
				scope := &config.Scope{}
				if runCfg != nil && runCfg.Scope != nil {
					scope = runCfg.Scope
				} else if target != nil {
					scope = &config.Scope{
						Wildcards:  append([]string{}, target.Wildcards...),
						Explicit:   append([]string{}, target.Explicit...),
						IPRanges:   append([]string{}, target.IPRanges...),
						OutOfScope: append([]string{}, target.OutOfScope...),
					}
				}
				return os.WriteFile(j.OutputFile, []byte(scope.ToHackerScopeFilter()+"\n"), 0o644)
			},
		},
		{
			name:        "path-validation",
			description: "Record PATH and GOPATH validation summary for the current run",
			output:      filepath.Join(ws.Hidden, "phase0_path_validation.txt"),
			execute: func(_ context.Context, j *engine.Job) error {
				lines := []string{
					"PATH=" + strings.TrimSpace(os.Getenv("PATH")),
					"GOPATH=" + strings.TrimSpace(os.Getenv("GOPATH")),
					"GO_BIN=" + filepath.Join(expandHome("~"), "go", "bin"),
				}
				return os.WriteFile(j.OutputFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
			},
		},
		{
			name:        "provider-key-summary",
			description: "Summarize configured provider-backed integrations",
			output:      filepath.Join(ws.Hidden, "phase0_provider_key_summary.txt"),
			execute: func(_ context.Context, j *engine.Job) error {
				keys := collectAPIKeys()
				lines := make([]string, 0, len(keys))
				for name, value := range keys {
					state := "empty"
					if strings.TrimSpace(value) != "" {
						state = "set"
					}
					lines = append(lines, fmt.Sprintf("%s=%s", name, state))
				}
				sort.Strings(lines)
				return os.WriteFile(j.OutputFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
			},
		},
		{
			name:        "nuclei-update-manifest",
			description: "Record nuclei update command and expected artifact locations",
			output:      filepath.Join(ws.Hidden, "phase0_nuclei_update_manifest.txt"),
			execute: func(_ context.Context, j *engine.Job) error {
				content := "command=nuclei -update-templates -silent\ncache=$HOME/.local/share/nuclei-templates\n"
				return os.WriteFile(j.OutputFile, []byte(content), 0o644)
			},
		},
		{
			name:        "api-key-export-check",
			description: "Check key export names required by methodology jobs",
			output:      filepath.Join(ws.Hidden, "phase0_export_check.txt"),
			execute: func(_ context.Context, j *engine.Job) error {
				required := []string{"GITHUB_TOKEN", "SHODAN_API_KEY", "PDCP_API_KEY", "VT_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET"}
				lines := make([]string, 0, len(required))
				for _, key := range required {
					value := "empty"
					if strings.TrimSpace(os.Getenv(key)) != "" {
						value = "set"
					}
					lines = append(lines, fmt.Sprintf("%s=%s", key, value))
				}
				return os.WriteFile(j.OutputFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
			},
		},
		{
			name:        "workspace-ready-marker",
			description: "Emit final phase-0 readiness marker for later smoke checks",
			output:      filepath.Join(ws.Hidden, "phase0_ready.txt"),
			execute: func(_ context.Context, j *engine.Job) error {
				content := fmt.Sprintf("target=%s\nready_at=%s\n", safeTargetDomain(target), time.Now().UTC().Format(time.RFC3339))
				return os.WriteFile(j.OutputFile, []byte(content), 0o644)
			},
		},
	}

	jobs := make([]*engine.Job, 0, len(specs))
	for _, spec := range specs {
		spec := spec
		job := engine.NewJob(0, spec.name, "", nil)
		job.Description = spec.description
		job.OutputFile = spec.output
		job.DependsOn = []string{workspaceInitID}
		job.Timeout = 30 * time.Second
		job.Execute = spec.execute
		job.ParseOutput = func(j *engine.Job) int { return countFileLinesCompat(j.OutputFile) }
		jobs = append(jobs, job)
	}
	return jobs
}

func normalizeList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func safeTargetDomain(target *models.Target) string {
	if target == nil || strings.TrimSpace(target.Domain) == "" {
		return "unknown"
	}
	return strings.TrimSpace(target.Domain)
}

func countFileLinesCompat(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	total := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			total++
		}
	}
	return total
}
