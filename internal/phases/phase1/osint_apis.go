package phase1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
)

func buildOSINTAPIJobs(ctx phase1Context) []*engine.Job {
	jobs := make([]*engine.Job, 0, 6)

	wayback := engine.NewJob(1, "wayback-subs", "", nil)
	wayback.Description = "Historical host extraction from Wayback"
	wayback.OutputFile = filepath.Join(ctx.subsDir, "wayback_subs.txt")
	wayback.Timeout = 4 * time.Minute
	wayback.Execute = func(execCtx context.Context, j *engine.Job) error {
		query := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey", ctx.domain)
		body, err := httpGetRetry(execCtx, query, nil, 2)
		if err != nil {
			return err
		}
		lines := strings.Split(string(body), "\n")
		found := make([]string, 0, len(lines))
		for _, line := range lines {
			host := hostFromAny(line)
			normalized := normalizeSubdomain(host, ctx.domain)
			if normalized != "" {
				found = append(found, normalized)
			}
		}
		return writeUniqueLines(j.OutputFile, found)
	}
	wayback.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, wayback)

	vt := engine.NewJob(1, "virustotal-subs", "", nil)
	vt.Description = "Virustotal passive subdomain API"
	vt.OutputFile = filepath.Join(ctx.subsDir, "virustotal_subs.txt")
	vt.Timeout = 3 * time.Minute
	vt.Execute = func(execCtx context.Context, j *engine.Job) error {
		apiKey := firstNonEmptyEnv("VT_API_KEY", "VIRUSTOTAL_API_KEY")
		if apiKey == "" {
			markSkipped(j, "VT_API_KEY not set, skipping virustotal")
			return nil
		}
		query := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", url.QueryEscape(apiKey), url.QueryEscape(ctx.domain))
		body, err := httpGetRetry(execCtx, query, nil, 2)
		if err != nil {
			return err
		}
		var payload struct {
			Subdomains []string `json:"subdomains"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return err
		}
		found := make([]string, 0, len(payload.Subdomains))
		for _, item := range payload.Subdomains {
			normalized := normalizeSubdomain(item, ctx.domain)
			if normalized != "" {
				found = append(found, normalized)
			}
		}
		return writeUniqueLines(j.OutputFile, found)
	}
	vt.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, vt)

	otx := engine.NewJob(1, "otx", "", nil)
	otx.Description = "Passive DNS extraction from OTX"
	otx.OutputFile = filepath.Join(ctx.subsDir, "otx.txt")
	otx.Timeout = 3 * time.Minute
	otx.Execute = func(execCtx context.Context, j *engine.Job) error {
		query := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", url.PathEscape(ctx.domain))
		body, err := httpGetRetry(execCtx, query, nil, 2)
		if err != nil {
			return err
		}
		var payload struct {
			PassiveDNS []struct {
				Hostname string `json:"hostname"`
			} `json:"passive_dns"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return err
		}
		found := make([]string, 0, len(payload.PassiveDNS))
		for _, item := range payload.PassiveDNS {
			normalized := normalizeSubdomain(item.Hostname, ctx.domain)
			if normalized != "" {
				found = append(found, normalized)
			}
		}
		return writeUniqueLines(j.OutputFile, found)
	}
	otx.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, otx)

	urlscanJob := engine.NewJob(1, "urlscan", "", nil)
	urlscanJob.Description = "Host extraction from urlscan.io search"
	urlscanJob.OutputFile = filepath.Join(ctx.subsDir, "urlscan.txt")
	urlscanJob.Timeout = 3 * time.Minute
	urlscanJob.Execute = func(execCtx context.Context, j *engine.Job) error {
		query := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", url.QueryEscape(ctx.domain))
		headers := map[string]string{"User-Agent": "n0rmxl/1.0"}
		body, err := httpGetRetry(execCtx, query, headers, 2)
		if err != nil {
			return err
		}
		var payload struct {
			Results []struct {
				Page struct {
					Domain string `json:"domain"`
				} `json:"page"`
			} `json:"results"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return err
		}
		found := make([]string, 0, len(payload.Results))
		for _, row := range payload.Results {
			normalized := normalizeSubdomain(row.Page.Domain, ctx.domain)
			if normalized != "" {
				found = append(found, normalized)
			}
		}
		return writeUniqueLines(j.OutputFile, found)
	}
	urlscanJob.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, urlscanJob)

	hackertarget := engine.NewJob(1, "hackertarget", "", nil)
	hackertarget.Description = "Host extraction from Hackertarget"
	hackertarget.OutputFile = filepath.Join(ctx.subsDir, "hackertarget.txt")
	hackertarget.Timeout = 2 * time.Minute
	hackertarget.Execute = func(execCtx context.Context, j *engine.Job) error {
		query := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(ctx.domain))
		body, err := httpGetRetry(execCtx, query, nil, 2)
		if err != nil {
			return err
		}
		found := make([]string, 0, 1024)
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			host := strings.TrimSpace(strings.Split(line, ",")[0])
			normalized := normalizeSubdomain(host, ctx.domain)
			if normalized != "" {
				found = append(found, normalized)
			}
		}
		return writeUniqueLines(j.OutputFile, found)
	}
	hackertarget.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, hackertarget)

	commoncrawl := engine.NewJob(1, "commoncrawl", "", nil)
	commoncrawl.Description = "Historical URL host extraction from CommonCrawl"
	commoncrawl.OutputFile = filepath.Join(ctx.subsDir, "commoncrawl.txt")
	commoncrawl.Timeout = 3 * time.Minute
	commoncrawl.Execute = func(execCtx context.Context, j *engine.Job) error {
		query := fmt.Sprintf("https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.%s&output=json", ctx.domain)
		body, err := httpGetRetry(execCtx, query, nil, 2)
		if err != nil {
			return err
		}
		found := make([]string, 0, 2048)
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || !strings.HasPrefix(line, "{") {
				continue
			}
			var row struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				continue
			}
			normalized := normalizeSubdomain(hostFromAny(row.URL), ctx.domain)
			if normalized != "" {
				found = append(found, normalized)
			}
		}
		return writeUniqueLines(j.OutputFile, found)
	}
	commoncrawl.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, commoncrawl)

	return jobs
}

