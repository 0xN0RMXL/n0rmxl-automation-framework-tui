package phase2

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
)

func buildCoverageJobs(ctx phase2Context, httpxProbeID string, extractLiveID string, naabuID string, gowitnessID string) []*engine.Job {
	specs := []struct {
		name        string
		description string
		output      string
		deps        []string
		exec        func(context.Context, *engine.Job) error
	}{
		{
			name:        "extract-alive-200",
			description: "Extract HTTP 200 hosts for follow-on workflows",
			output:      filepath.Join(ctx.ws.ScansHTTP, "alive_200.txt"),
			deps:        []string{httpxProbeID},
			exec: func(_ context.Context, j *engine.Job) error {
				return writeStatusFilteredHosts(ctx.httpxJSON, j.OutputFile, 200)
			},
		},
		{
			name:        "extract-forbidden",
			description: "Extract 401/403 hosts for bypass workflows",
			output:      filepath.Join(ctx.ws.ScansHTTP, "forbidden.txt"),
			deps:        []string{httpxProbeID},
			exec: func(_ context.Context, j *engine.Job) error {
				return writeStatusFilteredHosts(ctx.httpxJSON, j.OutputFile, 401, 403)
			},
		},
		{
			name:        "waf-strategy-note",
			description: "Generate WAF strategy note per phase-2 methodology",
			output:      filepath.Join(ctx.ws.ScansHTTP, "waf_strategy.txt"),
			deps:        []string{extractLiveID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := "Run wafw00f against live hosts and treat Cloudflare/Akamai targets as stealth-first.\n"
				return os.WriteFile(j.OutputFile, []byte(content), 0o644)
			},
		},
		{
			name:        "cdn-detection-note",
			description: "Generate CDN detection command note",
			output:      filepath.Join(ctx.ws.ScansHTTP, "cdn_detection.txt"),
			deps:        []string{extractLiveID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := "cdncheck -l scans/http/live_hosts.txt\n"
				return os.WriteFile(j.OutputFile, []byte(content), 0o644)
			},
		},
		{
			name:        "gowitness-report-note",
			description: "Record gowitness report serving command",
			output:      filepath.Join(ctx.ws.Screenshots, "gowitness_report.txt"),
			deps:        []string{gowitnessID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := fmt.Sprintf("gowitness report server --db-path %s\n", filepath.Join(ctx.ws.Screenshots, "gowitness.sqlite3"))
				return os.WriteFile(j.OutputFile, []byte(content), 0o644)
			},
		},
		{
			name:        "visual-overview-note",
			description: "Record aquatone and EyeWitness visual overview coverage",
			output:      filepath.Join(ctx.ws.Screenshots, "visual_overview.txt"),
			deps:        []string{gowitnessID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := "Preferred: gowitness. Fallbacks: EyeWitness and aquatone for visual clustering.\n"
				return os.WriteFile(j.OutputFile, []byte(content), 0o644)
			},
		},
		{
			name:        "origin-ip-note",
			description: "Generate origin IP discovery action plan",
			output:      filepath.Join(ctx.ws.ScansPorts, "origin_ip_discovery.txt"),
			deps:        []string{naabuID},
			exec: func(_ context.Context, j *engine.Job) error {
				lines := []string{
					"originiphunter -l scans/http/live_hosts.txt",
					"uncover -q 'ssl:" + ctx.domain + "' -engine censys",
					"Verify direct IP responses with Host header injection.",
				}
				return os.WriteFile(j.OutputFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
			},
		},
		{
			name:        "direct-ip-host-header-note",
			description: "Record direct origin validation with Host header injection",
			output:      filepath.Join(ctx.ws.ScansHTTP, "direct_ip_host_header.txt"),
			deps:        []string{naabuID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := "curl -isk https://ORIGIN_IP/ -H 'Host: " + ctx.domain + "'\n"
				return os.WriteFile(j.OutputFile, []byte(content), 0o644)
			},
		},
		{
			name:        "interesting-ports-note",
			description: "Record the interesting service ports methodology requires",
			output:      filepath.Join(ctx.ws.ScansPorts, "interesting_ports.txt"),
			deps:        []string{naabuID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := "21,22,23,25,3306,5432,27017,6379,9200,5601,11211\n"
				return os.WriteFile(j.OutputFile, []byte(content), 0o644)
			},
		},
		{
			name:        "port-scan-strategy-note",
			description: "Record masscan/naabu/rustscan strategy notes",
			output:      filepath.Join(ctx.ws.ScansPorts, "port_scan_strategy.txt"),
			deps:        []string{naabuID},
			exec: func(_ context.Context, j *engine.Job) error {
				lines := []string{
					"masscan full sweep at methodology rate when authorized",
					"naabu + nmap for service confirmation",
					"rustscan only in aggressive profile",
				}
				return os.WriteFile(j.OutputFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
			},
		},
	}

	jobs := make([]*engine.Job, 0, len(specs))
	for _, spec := range specs {
		spec := spec
		job := engine.NewJob(2, spec.name, "", nil)
		job.Description = spec.description
		job.OutputFile = spec.output
		job.DependsOn = append([]string{}, spec.deps...)
		job.Timeout = 20 * time.Second
		job.Execute = spec.exec
		job.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
		jobs = append(jobs, job)
	}
	return jobs
}

func writeStatusFilteredHosts(httpxJSON string, output string, codes ...int) error {
	if !fileExists(httpxJSON) {
		return os.WriteFile(output, []byte(""), 0o644)
	}
	records, err := parseHTTPXLines(httpxJSON)
	if err != nil {
		return err
	}
	set := make(map[int]struct{}, len(codes))
	for _, code := range codes {
		set[code] = struct{}{}
	}
	rows := make([]string, 0, len(records)/4)
	for _, record := range records {
		if _, ok := set[record.StatusCode]; ok && strings.TrimSpace(record.URL) != "" {
			rows = append(rows, record.URL)
		}
	}
	sort.Strings(rows)
	return writeLines(output, dedupSorted(rows))
}
