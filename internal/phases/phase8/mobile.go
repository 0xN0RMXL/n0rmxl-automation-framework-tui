package phase8

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
)

func buildMobileJobs(ctx phase8Context) []*engine.Job {
	jobs := make([]*engine.Job, 0, 2)

	endpoints := engine.NewJob(8, "mobile-endpoints", "", nil)
	endpoints.ID = "phase8-mobile-endpoints"
	endpoints.Description = "Extract mobile API endpoints from discovered URL corpus"
	endpoints.OutputFile = filepath.Join(ctx.ws.ReconURLs, "mobile_endpoints.txt")
	endpoints.Timeout = 2 * time.Minute
	endpoints.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		if !fileExists(ctx.urlsDeduped) || countNonEmptyLines(ctx.urlsDeduped) == 0 {
			markSkipped(j, "deduped URL corpus missing")
			return nil
		}
		rows := readNonEmptyLines(ctx.urlsDeduped)
		mobile := make([]string, 0, len(rows)/10)
		for _, row := range rows {
			lower := strings.ToLower(row)
			if strings.Contains(lower, "/mobile") || strings.Contains(lower, "/app") || strings.Contains(lower, "/ios") || strings.Contains(lower, "/android") || strings.Contains(lower, "x-device-id") || strings.Contains(lower, "x-app-version") {
				mobile = append(mobile, row)
			}
		}
		mobile = sortUnique(mobile)
		if len(mobile) == 0 {
			markSkipped(j, "no mobile endpoints identified")
			return nil
		}
		return writeLines(j.OutputFile, mobile)
	}
	endpoints.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
	jobs = append(jobs, endpoints)

	guide := engine.NewJob(8, "mobile-guide", "", nil)
	guide.ID = "phase8-mobile-guide"
	guide.Description = "Generate mobile testing guide from discovered endpoints"
	guide.OutputFile = filepath.Join(ctx.ws.Scans, "mobile", "testing_guide.md")
	guide.DependsOn = []string{endpoints.ID}
	guide.Timeout = 1 * time.Minute
	guide.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		rows := readNonEmptyLines(filepath.Join(ctx.ws.ReconURLs, "mobile_endpoints.txt"))
		var b strings.Builder
		b.WriteString("# Mobile Testing Guide\n\n")
		b.WriteString("## Setup\n")
		b.WriteString("- Configure Burp mobile proxy and trusted CA cert on device/emulator\n")
		b.WriteString("- Use adb reverse and mitmproxy/Burp interception for traffic capture\n")
		b.WriteString("- Validate certificate pinning behavior before test execution\n\n")
		b.WriteString("## Discovered Mobile Endpoints\n")
		if len(rows) == 0 {
			b.WriteString("- No mobile-specific endpoints were automatically identified\n")
		} else {
			for _, row := range rows {
				b.WriteString("- " + row + "\n")
			}
		}
		b.WriteString("\n## Checklist\n")
		b.WriteString("- Certificate pinning bypass (Frida/objection)\n")
		b.WriteString("- Exported activities and intent injection\n")
		b.WriteString("- Insecure local storage (SharedPreferences/SQLite/keychain)\n")
		b.WriteString("- Token leakage via logs or insecure network transport\n")
		return writeText(j.OutputFile, b.String())
	}
	guide.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
	jobs = append(jobs, guide)

	return jobs
}
