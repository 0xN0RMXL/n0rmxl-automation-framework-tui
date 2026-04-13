package phase0

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	"gopkg.in/yaml.v3"
)

func Jobs(target *models.Target, ws models.Workspace, runCfg *config.RunConfig) []*engine.Job {
	workspaceInit := engine.NewJob(0, "workspace-init", "", nil)
	workspaceInit.Description = "Initialize workspace, scope, and provider config files"
	workspaceInit.Required = true
	workspaceInit.OutputFile = filepath.Join(ws.Hidden, "phase0_workspace_init.log")
	workspaceInit.Execute = func(ctx context.Context, j *engine.Job) error {
		return runWorkspaceInit(ctx, j, target, ws, runCfg)
	}
	workspaceInit.ParseOutput = func(_ *engine.Job) int { return 1 }

	nucleiUpdate := engine.NewJob(0, "nuclei-update", "nuclei", []string{"-update-templates", "-silent"})
	nucleiUpdate.Description = "Update nuclei templates"
	nucleiUpdate.Required = true
	nucleiUpdate.WorkDir = ws.Root
	nucleiUpdate.Timeout = 5 * time.Minute
	nucleiUpdate.OutputFile = filepath.Join(ws.Hidden, "phase0_nuclei_update.log")
	nucleiUpdate.DependsOn = []string{workspaceInit.ID}
	if runCfg != nil && runCfg.UseBurp {
		nucleiUpdate.Env = append(nucleiUpdate.Env,
			"HTTP_PROXY=http://127.0.0.1:8080",
			"HTTPS_PROXY=http://127.0.0.1:8080",
		)
	}

	subfinderConfig := engine.NewJob(0, "subfinder-config", "", nil)
	subfinderConfig.Description = "Validate subfinder provider config and list configured keys"
	subfinderConfig.Required = true
	subfinderConfig.OutputFile = filepath.Join(ws.Hidden, "phase0_subfinder_config.log")
	subfinderConfig.DependsOn = []string{workspaceInit.ID}
	subfinderConfig.Execute = func(ctx context.Context, j *engine.Job) error {
		return verifySubfinderConfig(ctx, j)
	}
	subfinderConfig.ParseOutput = func(_ *engine.Job) int { return 1 }

	scopeValidate := engine.NewJob(0, "scope-validate", "", nil)
	scopeValidate.Description = "Validate and summarize scope definition"
	scopeValidate.Required = true
	scopeValidate.OutputFile = filepath.Join(ws.Hidden, "phase0_scope_validate.log")
	scopeValidate.DependsOn = []string{workspaceInit.ID}
	scopeValidate.Execute = func(ctx context.Context, j *engine.Job) error {
		return validateScope(ctx, j, ws, target)
	}
	scopeValidate.ParseOutput = func(_ *engine.Job) int { return 1 }

	jobs := []*engine.Job{workspaceInit, nucleiUpdate, subfinderConfig, scopeValidate}
	jobs = append(jobs, buildCoverageJobs(target, ws, runCfg, workspaceInit.ID)...)
	return jobs
}

func runWorkspaceInit(ctx context.Context, job *engine.Job, target *models.Target, ws models.Workspace, runCfg *config.RunConfig) error {
	if target == nil {
		return fmt.Errorf("target is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ws.EnsureAll(); err != nil {
		return err
	}
	appendJobLog(job, "[INFO] workspace directories ensured")

	if err := writeScopeFile(filepath.Join(ws.Root, "scope.txt"), target); err != nil {
		return err
	}
	appendJobLog(job, "[INFO] wrote scope file")

	keys := collectAPIKeys()
	if err := writeSubfinderProviderConfig(keys); err != nil {
		return err
	}
	appendJobLog(job, "[INFO] wrote subfinder provider-config.yaml")

	if err := writeAmassProviderConfig(keys); err != nil {
		return err
	}
	appendJobLog(job, "[INFO] wrote amass config.yaml")

	if runCfg != nil && runCfg.Scope != nil {
		appendJobLog(job, "[INFO] run profile scope is loaded")
	}

	ensureCommonEnvAliases(keys)
	ensureGoBinInPath(job)
	return nil
}

func verifySubfinderConfig(ctx context.Context, job *engine.Job) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	providerPath := filepath.Join(expandHome("~"), ".config", "subfinder", "provider-config.yaml")
	raw, err := os.ReadFile(providerPath)
	if err != nil {
		return fmt.Errorf("failed to read subfinder provider config: %w", err)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("invalid subfinder provider config yaml: %w", err)
	}

	expected := []string{"virustotal", "shodan", "censys", "chaos", "github", "securitytrails", "binaryedge", "hunter"}
	configured := make([]string, 0, len(expected))
	missing := make([]string, 0, len(expected))
	for _, key := range expected {
		if _, ok := parsed[key]; ok {
			configured = append(configured, key)
		} else {
			missing = append(missing, key)
		}
	}
	sort.Strings(configured)
	sort.Strings(missing)

	appendJobLog(job, "[INFO] configured provider keys: "+strings.Join(configured, ", "))
	appendJobLog(job, "[INFO] missing provider keys: "+strings.Join(missing, ", "))
	return nil
}

func validateScope(ctx context.Context, job *engine.Job, ws models.Workspace, target *models.Target) error {
	if target == nil {
		return fmt.Errorf("target is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	warnings := make([]string, 0, 8)
	for _, wildcard := range target.Wildcards {
		wildcard = strings.TrimSpace(wildcard)
		if wildcard == "" {
			continue
		}
		if !strings.HasPrefix(wildcard, "*.") {
			warnings = append(warnings, "wildcard without *.: "+wildcard)
		}
		if wildcard == "*.com" || wildcard == "*.net" || wildcard == "*.org" || wildcard == "*.io" {
			warnings = append(warnings, "wildcard appears overly broad: "+wildcard)
		}
	}

	summary := make([]string, 0, 16)
	summary = append(summary, "N0RMXL Scope Validation Summary")
	summary = append(summary, "Target: "+target.Domain)
	summary = append(summary, fmt.Sprintf("Wildcards: %d", len(target.Wildcards)))
	summary = append(summary, fmt.Sprintf("Explicit: %d", len(target.Explicit)))
	summary = append(summary, fmt.Sprintf("IP ranges: %d", len(target.IPRanges)))
	summary = append(summary, fmt.Sprintf("Out-of-scope: %d", len(target.OutOfScope)))
	if len(warnings) == 0 {
		summary = append(summary, "Warnings: none")
		appendJobLog(job, "[INFO] scope validation passed with no warnings")
	} else {
		summary = append(summary, "Warnings:")
		for _, warning := range warnings {
			summary = append(summary, "- "+warning)
			appendJobLog(job, "[WARN] "+warning)
		}
	}

	summaryPath := filepath.Join(ws.Hidden, "scope_summary.txt")
	if err := os.MkdirAll(filepath.Dir(summaryPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(summaryPath, []byte(strings.Join(summary, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	appendJobLog(job, "[INFO] scope summary written to "+summaryPath)
	return nil
}

func writeScopeFile(path string, target *models.Target) error {
	if target == nil {
		return fmt.Errorf("target is nil")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	sections := []struct {
		title string
		rows  []string
	}{
		{title: "# Domain", rows: []string{target.Domain}},
		{title: "# Wildcards", rows: target.Wildcards},
		{title: "# Explicit", rows: target.Explicit},
		{title: "# IP Ranges", rows: target.IPRanges},
		{title: "# Out of Scope", rows: target.OutOfScope},
	}

	var b strings.Builder
	for _, section := range sections {
		b.WriteString(section.title + "\n")
		for _, row := range section.rows {
			row = strings.TrimSpace(row)
			if row == "" {
				continue
			}
			b.WriteString(row + "\n")
		}
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func collectAPIKeys() map[string]string {
	pairs := map[string][]string{
		"virustotal":     {"VT_API_KEY", "VIRUSTOTAL_API_KEY"},
		"shodan":         {"SHODAN_API_KEY"},
		"censys_id":      {"CENSYS_API_ID"},
		"censys_secret":  {"CENSYS_API_SECRET"},
		"chaos":          {"PDCP_API_KEY", "CHAOS_KEY"},
		"github":         {"GITHUB_TOKEN"},
		"securitytrails": {"SECURITYTRAILS_API_KEY"},
		"binaryedge":     {"BINARYEDGE_API_KEY"},
		"hunter":         {"HUNTER_API_KEY"},
	}
	out := make(map[string]string, len(pairs))
	for key, envs := range pairs {
		for _, envKey := range envs {
			value := strings.TrimSpace(os.Getenv(envKey))
			if value != "" {
				out[key] = value
				break
			}
		}
	}
	return out
}

func writeSubfinderProviderConfig(keys map[string]string) error {
	providerPath := filepath.Join(expandHome("~"), ".config", "subfinder", "provider-config.yaml")
	if err := os.MkdirAll(filepath.Dir(providerPath), 0o700); err != nil {
		return err
	}

	cfg := make(map[string]any)
	if key := strings.TrimSpace(keys["virustotal"]); key != "" {
		cfg["virustotal"] = []string{key}
	}
	if key := strings.TrimSpace(keys["shodan"]); key != "" {
		cfg["shodan"] = []string{key}
	}
	if id := strings.TrimSpace(keys["censys_id"]); id != "" {
		if secret := strings.TrimSpace(keys["censys_secret"]); secret != "" {
			cfg["censys"] = []map[string]string{{"apiID": id, "apiSecret": secret}}
		}
	}
	if key := strings.TrimSpace(keys["chaos"]); key != "" {
		cfg["chaos"] = []string{key}
	}
	if key := strings.TrimSpace(keys["github"]); key != "" {
		cfg["github"] = []string{key}
	}
	if key := strings.TrimSpace(keys["securitytrails"]); key != "" {
		cfg["securitytrails"] = []string{key}
	}
	if key := strings.TrimSpace(keys["binaryedge"]); key != "" {
		cfg["binaryedge"] = []string{key}
	}
	if key := strings.TrimSpace(keys["hunter"]); key != "" {
		cfg["hunter"] = []string{key}
	}

	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(providerPath, raw, 0o600)
}

func writeAmassProviderConfig(keys map[string]string) error {
	amassPath := filepath.Join(expandHome("~"), ".config", "amass", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(amassPath), 0o700); err != nil {
		return err
	}
	cfg := map[string]any{"datasources": map[string]any{}}
	datasources := cfg["datasources"].(map[string]any)
	if key := strings.TrimSpace(keys["virustotal"]); key != "" {
		datasources["Virustotal"] = map[string]string{"apikey": key}
	}
	if key := strings.TrimSpace(keys["shodan"]); key != "" {
		datasources["Shodan"] = map[string]string{"apikey": key}
	}
	if id := strings.TrimSpace(keys["censys_id"]); id != "" {
		if secret := strings.TrimSpace(keys["censys_secret"]); secret != "" {
			datasources["Censys"] = map[string]string{"id": id, "secret": secret}
		}
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(amassPath, raw, 0o600)
}

func ensureCommonEnvAliases(keys map[string]string) {
	for key, value := range map[string]string{
		"VT_API_KEY":         keys["virustotal"],
		"SHODAN_API_KEY":     keys["shodan"],
		"CENSYS_API_ID":      keys["censys_id"],
		"CENSYS_API_SECRET":  keys["censys_secret"],
		"PDCP_API_KEY":       keys["chaos"],
		"GITHUB_TOKEN":       keys["github"],
		"SECURITYTRAILS_KEY": keys["securitytrails"],
		"BINARYEDGE_API_KEY": keys["binaryedge"],
		"HUNTER_API_KEY":     keys["hunter"],
	} {
		if strings.TrimSpace(value) != "" {
			_ = os.Setenv(key, value)
		}
	}
}

func ensureGoBinInPath(job *engine.Job) {
	home := expandHome("~")
	goBin := filepath.Join(home, "go", "bin")
	if _, err := os.Stat(goBin); err != nil {
		return
	}
	pathValue := os.Getenv("PATH")
	for _, entry := range filepath.SplitList(pathValue) {
		if strings.EqualFold(filepath.Clean(entry), filepath.Clean(goBin)) {
			appendJobLog(job, "[INFO] ~/go/bin already present in PATH")
			return
		}
	}
	newPath := pathValue
	if strings.TrimSpace(newPath) == "" {
		newPath = goBin
	} else {
		newPath = goBin + string(os.PathListSeparator) + newPath
	}
	_ = os.Setenv("PATH", newPath)
	appendJobLog(job, "[INFO] prepended ~/go/bin to PATH for this run")
}

func appendJobLog(job *engine.Job, line string) {
	if job != nil {
		job.LogLine(line)
		if strings.TrimSpace(job.OutputFile) != "" {
			if err := os.MkdirAll(filepath.Dir(job.OutputFile), 0o755); err == nil {
				if f, openErr := os.OpenFile(job.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); openErr == nil {
					_, _ = f.WriteString(line + "\n")
					_ = f.Close()
				}
			}
		}
	}
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/"))
}

