package phase8

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
)

func buildThickClientJobs(ctx phase8Context) []*engine.Job {
	job := engine.NewJob(8, "thick-client-guide", "", nil)
	job.ID = "phase8-thick-client-guide"
	job.Description = "Generate thick client testing guide based on observed tech stack"
	job.OutputFile = filepath.Join(ctx.ws.Scans, "thick_client", "testing_guide.md")
	job.Timeout = 1 * time.Minute
	job.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		techHints := collectTechHints(ctx.whatwebOutput)
		var b strings.Builder
		b.WriteString("# Thick Client Testing Guide\n\n")
		b.WriteString("## Observed Indicators\n")
		if len(techHints) == 0 {
			b.WriteString("- No explicit thick-client indicators auto-detected from current scan artifacts\n")
		} else {
			for _, hint := range techHints {
				b.WriteString("- " + hint + "\n")
			}
		}
		b.WriteString("\n## Methodology\n")
		b.WriteString("- Java clients: inspect serialized object handling and network APIs\n")
		b.WriteString("- Electron apps: verify contextIsolation, preload boundaries, and IPC exposure\n")
		b.WriteString("- .NET clients: decompile assemblies and inspect auth token handling\n")
		b.WriteString("\n## Tooling\n")
		b.WriteString("- Burp proxy + native app proxy settings\n")
		b.WriteString("- dnSpy/ILSpy for .NET\n")
		b.WriteString("- jadx/fernflower for Java artifacts\n")
		b.WriteString("- Process monitor and TLS interception workflow\n")
		return writeText(j.OutputFile, b.String())
	}
	job.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
	return []*engine.Job{job}
}

func collectTechHints(path string) []string {
	rows := readNonEmptyLines(path)
	if len(rows) == 0 {
		return []string{}
	}
	hints := make([]string, 0, 8)
	for _, row := range rows {
		lower := strings.ToLower(row)
		switch {
		case strings.Contains(lower, "electron"):
			hints = append(hints, "Electron indicators in web fingerprint output")
		case strings.Contains(lower, "java") || strings.Contains(lower, "jsp") || strings.Contains(lower, "spring"):
			hints = append(hints, "Java technology indicators detected")
		case strings.Contains(lower, ".net") || strings.Contains(lower, "asp.net"):
			hints = append(hints, ".NET technology indicators detected")
		case strings.Contains(lower, "citrix"):
			hints = append(hints, "Citrix-related indicator detected")
		}
	}
	return sortUnique(hints)
}

