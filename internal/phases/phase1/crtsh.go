package phase1

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
)

func buildCRTSHJobs(ctx phase1Context, asnmapIPsID string) []*engine.Job {
	jobs := make([]*engine.Job, 0, 3)

	crtsh := engine.NewJob(1, "crtsh", "", nil)
	crtsh.Description = "Certificate transparency lookup via crt.sh"
	crtsh.OutputFile = filepath.Join(ctx.subsDir, "crtsh.txt")
	crtsh.Timeout = 4 * time.Minute
	crtsh.Execute = func(execCtx context.Context, j *engine.Job) error {
		query := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", ctx.domain)
		body, err := httpGetRetry(execCtx, query, nil, 3)
		if err != nil {
			return err
		}
		type crtRow struct {
			NameValue string `json:"name_value"`
		}
		rows := make([]crtRow, 0)
		if err := json.Unmarshal(body, &rows); err != nil {
			return err
		}
		found := make([]string, 0, len(rows))
		for _, row := range rows {
			for _, part := range strings.Split(row.NameValue, "\n") {
				normalized := normalizeSubdomain(strings.TrimSpace(part), ctx.domain)
				if normalized != "" {
					found = append(found, normalized)
				}
			}
		}
		return writeUniqueLines(j.OutputFile, found)
	}
	crtsh.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, crtsh)

	certspotter := engine.NewJob(1, "certspotter", "", nil)
	certspotter.Description = "Certificate lookup via certspotter API"
	certspotter.OutputFile = filepath.Join(ctx.subsDir, "certspotter.txt")
	certspotter.Timeout = 4 * time.Minute
	certspotter.Execute = func(execCtx context.Context, j *engine.Job) error {
		query := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", ctx.domain)
		body, err := httpGetRetry(execCtx, query, nil, 2)
		if err != nil {
			return err
		}
		var rows []map[string]any
		if err := json.Unmarshal(body, &rows); err != nil {
			return err
		}
		found := make([]string, 0, len(rows))
		for _, row := range rows {
			raw, ok := row["dns_names"]
			if !ok {
				continue
			}
			names, ok := raw.([]any)
			if !ok {
				continue
			}
			for _, item := range names {
				normalized := normalizeSubdomain(fmt.Sprint(item), ctx.domain)
				if normalized != "" {
					found = append(found, normalized)
				}
			}
		}
		return writeUniqueLines(j.OutputFile, found)
	}
	certspotter.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, certspotter)

	tlsx := engine.NewJob(1, "tlsx", "tlsx", nil)
	tlsx.Description = "Extract SAN/CN hostnames from discovered IP ranges"
	tlsx.OutputFile = filepath.Join(ctx.subsDir, "tlsx.txt")
	if strings.TrimSpace(asnmapIPsID) != "" {
		tlsx.DependsOn = []string{asnmapIPsID}
	}
	tlsx.Timeout = 10 * time.Minute
	tlsx.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.ipRangesOut) || countFileLines(ctx.ipRangesOut) == 0 {
			markSkipped(j, "ip_ranges.txt missing or empty, skipping tlsx")
			return nil
		}
		if err := runCommand(execCtx, ctx.runCfg, "tlsx", []string{"-l", ctx.ipRangesOut, "-san", "-cn", "-silent", "-o", j.OutputFile}); err != nil {
			return err
		}
		rows := readNonEmptyLines(j.OutputFile)
		filtered := make([]string, 0, len(rows))
		for _, row := range rows {
			normalized := normalizeSubdomain(hostFromAny(row), ctx.domain)
			if normalized != "" {
				filtered = append(filtered, normalized)
			}
		}
		if len(filtered) == 0 {
			markSkipped(j, "tlsx produced no in-scope domains")
			return nil
		}
		return writeUniqueLines(j.OutputFile, filtered)
	}
	tlsx.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, tlsx)

	return jobs
}
