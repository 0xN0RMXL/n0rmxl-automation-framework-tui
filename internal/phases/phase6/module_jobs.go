package phase6

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases/phase6/exploits"
)

func buildModuleJobs(ctx phase6Context, loadJobID string) []*engine.Job {
	modules := exploits.DefaultModules()
	jobs := make([]*engine.Job, 0, len(modules))
	for _, module := range modules {
		module := module
		className := strings.TrimSpace(module.VulnClass())
		if className == "" || className == "generic" {
			continue
		}
		outPath := filepath.Join(ctx.ws.Notes, "phase6_modules", sanitizeModuleFileName(className)+".md")
		job := engine.NewJob(6, "phase6-module-"+className, "", nil)
		job.Description = "Generate methodology playbook for " + className
		job.OutputFile = outPath
		job.DependsOn = []string{loadJobID}
		job.Timeout = 90 * time.Second
		job.Execute = func(execCtx context.Context, j *engine.Job) error {
			_ = execCtx
			findings := readFindingsFile(ctx.findingsRaw)
			relevant := firstFindingForClass(findings, className)
			steps := module.Steps(ctx.domain, relevant, ctx.runCfg)
			if len(steps) == 0 {
				markSkipped(j, "no exploit steps registered for "+className)
				return nil
			}
			var b strings.Builder
			b.WriteString("# Phase 6 Module Playbook\n\n")
			b.WriteString(fmt.Sprintf("- Class: %s\n", className))
			b.WriteString(fmt.Sprintf("- Severity: %s\n", strings.ToUpper(string(module.Severity()))))
			b.WriteString(fmt.Sprintf("- Description: %s\n\n", module.Description()))
			if relevant != nil {
				b.WriteString("## Example Finding\n\n")
				b.WriteString(fmt.Sprintf("- Target: %s\n", safeString(relevant.Host, safeString(relevant.Target, ctx.domain))))
				b.WriteString(fmt.Sprintf("- URL: %s\n", safeString(relevant.URL, "n/a")))
				b.WriteString(fmt.Sprintf("- Parameter: %s\n\n", safeString(relevant.Parameter, "n/a")))
			}
			b.WriteString("## Steps\n\n")
			for idx, step := range steps {
				b.WriteString(fmt.Sprintf("%d. **%s** - %s\n", idx+1, step.Name, step.Description))
				b.WriteString("```bash\n")
				b.WriteString(strings.TrimSpace(step.Command) + "\n")
				b.WriteString("```\n\n")
			}
			return writeText(j.OutputFile, b.String())
		}
		job.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
		jobs = append(jobs, job)
	}
	return jobs
}

func firstFindingForClass(findings []models.Finding, vulnClass string) *models.Finding {
	needle := strings.TrimSpace(vulnClass)
	for _, finding := range findings {
		if exploits.SelectModule(finding.VulnClass, nil).VulnClass() == needle {
			findingCopy := finding
			return &findingCopy
		}
	}
	return nil
}

func sanitizeModuleFileName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "module"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_")
	return replacer.Replace(value)
}

func ensureDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o755)
}

