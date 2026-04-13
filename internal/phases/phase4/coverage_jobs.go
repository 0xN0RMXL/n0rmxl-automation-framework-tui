package phase4

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
)

func buildCoverageJobs(ctx phase4Context, mergeJobID string, gfJobID string) []*engine.Job {
	jobs := make([]*engine.Job, 0, 20)
	jobs = append(jobs, buildURLClassificationJobs(ctx, mergeJobID)...)
	jobs = append(jobs, buildGFManifestJobs(ctx, gfJobID)...)
	return jobs
}

func buildURLClassificationJobs(ctx phase4Context, mergeJobID string) []*engine.Job {
	type classifier struct {
		name        string
		description string
		output      string
		match       func(string) bool
	}

	digitRE := regexp.MustCompile(`\d{4,}`)
	classifiers := []classifier{
		{name: "classify-js-files", description: "Extract JavaScript asset URLs", output: filepath.Join(ctx.interestingDir, "js_files.txt"), match: func(v string) bool { return strings.Contains(strings.ToLower(v), ".js") }},
		{name: "classify-api-endpoints", description: "Extract likely API endpoints", output: filepath.Join(ctx.interestingDir, "api_endpoints.txt"), match: func(v string) bool {
			lower := strings.ToLower(v)
			return strings.Contains(lower, ".json") || strings.Contains(lower, ".xml") || strings.Contains(lower, ".graphql") || strings.Contains(lower, ".gql") || strings.Contains(lower, "/api/") || strings.Contains(lower, "/graphql")
		}},
		{name: "classify-backend", description: "Extract backend implementation paths", output: filepath.Join(ctx.interestingDir, "backend.txt"), match: func(v string) bool {
			lower := strings.ToLower(v)
			for _, ext := range []string{".php", ".asp", ".aspx", ".jsp", ".cfm", ".cgi"} {
				if strings.Contains(lower, ext) {
					return true
				}
			}
			return false
		}},
		{name: "classify-login-flows", description: "Extract login and authentication flows", output: filepath.Join(ctx.interestingDir, "login_flows.txt"), match: func(v string) bool {
			lower := strings.ToLower(v)
			for _, needle := range []string{"login", "signin", "auth", "oauth", "reset", "password"} {
				if strings.Contains(lower, needle) {
					return true
				}
			}
			return false
		}},
		{name: "classify-uploads", description: "Extract upload and file workflow URLs", output: filepath.Join(ctx.interestingDir, "uploads.txt"), match: func(v string) bool {
			lower := strings.ToLower(v)
			for _, needle := range []string{"upload", "file", "download", "image", "media", "import"} {
				if strings.Contains(lower, needle) {
					return true
				}
			}
			return false
		}},
		{name: "classify-admin-panels", description: "Extract admin and internal panel URLs", output: filepath.Join(ctx.interestingDir, "admin_panels.txt"), match: func(v string) bool {
			lower := strings.ToLower(v)
			for _, needle := range []string{"admin", "dashboard", "internal", "manage", "config", "panel"} {
				if strings.Contains(lower, needle) {
					return true
				}
			}
			return false
		}},
		{name: "classify-param-urls", description: "Extract URLs with query parameters", output: filepath.Join(ctx.interestingDir, "param_urls.txt"), match: func(v string) bool { return strings.Contains(v, "=") }},
		{name: "classify-idor-targets", description: "Extract likely IDOR candidate URLs", output: filepath.Join(ctx.interestingDir, "idor_targets.txt"), match: func(v string) bool { return digitRE.MatchString(v) }},
		{name: "classify-cloud-leaks", description: "Extract cloud secret leak candidates", output: filepath.Join(ctx.interestingDir, "cloud_leaks.txt"), match: func(v string) bool {
			lower := strings.ToLower(v)
			for _, needle := range []string{"aws", "s3", "bucket", "azure", "gcp", "token", "apikey", "secret"} {
				if strings.Contains(lower, needle) {
					return true
				}
			}
			return false
		}},
		{name: "classify-ssrf-candidates", description: "Extract SSRF-style callback and URL parameters", output: filepath.Join(ctx.interestingDir, "ssrf_candidates.txt"), match: func(v string) bool {
			lower := strings.ToLower(v)
			for _, needle := range []string{"webhook", "callback", "fetch", "proxy", "redirect", "ssrf", "url=", "uri="} {
				if strings.Contains(lower, needle) {
					return true
				}
			}
			return false
		}},
		{name: "classify-sensitive-files", description: "Extract sensitive file exposure candidates", output: filepath.Join(ctx.interestingDir, "sensitive_files.txt"), match: func(v string) bool {
			lower := strings.ToLower(v)
			for _, ext := range []string{".xls", ".xlsx", ".sql", ".bak", ".zip", ".env", ".log", ".config", ".pem", ".key"} {
				if strings.Contains(lower, ext) {
					return true
				}
			}
			return false
		}},
	}

	jobs := make([]*engine.Job, 0, len(classifiers))
	for _, classifier := range classifiers {
		classifier := classifier
		job := engine.NewJob(4, classifier.name, "", nil)
		job.Description = classifier.description
		job.OutputFile = classifier.output
		job.DependsOn = []string{mergeJobID}
		job.Timeout = 45 * time.Second
		job.Execute = func(_ context.Context, j *engine.Job) error {
			if !fileExists(ctx.urlsDeduped) {
				markSkipped(j, "deduped URL corpus missing")
				return nil
			}
			rows := readNonEmptyLines(ctx.urlsDeduped)
			matches := make([]string, 0, len(rows)/4)
			for _, row := range rows {
				if classifier.match(row) {
					matches = append(matches, row)
				}
			}
			sort.Strings(matches)
			return writeLines(j.OutputFile, dedupSorted(matches))
		}
		job.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
		jobs = append(jobs, job)
	}
	return jobs
}

func buildGFManifestJobs(ctx phase4Context, gfJobID string) []*engine.Job {
	patterns := []string{"sqli", "xss", "lfi", "ssrf", "redirect", "rce", "idor", "ssti", "cors"}
	jobs := make([]*engine.Job, 0, len(patterns))
	for _, pattern := range patterns {
		pattern := pattern
		out := filepath.Join(ctx.interestingDir, "gf_"+pattern+"_manifest.txt")
		job := engine.NewJob(4, "gf-"+pattern+"-manifest", "", nil)
		job.Description = "Record gf coverage for " + pattern
		job.OutputFile = out
		job.DependsOn = []string{gfJobID}
		job.Timeout = 20 * time.Second
		job.Execute = func(_ context.Context, j *engine.Job) error {
			source := filepath.Join(ctx.interestingDir, pattern+".txt")
			lines := []string{
				"pattern=" + pattern,
				"source=" + source,
				fmt.Sprintf("matches=%d", countFileLines(source)),
				"command=gf " + pattern + " < recon/urls/all_urls_deduped.txt",
			}
			return os.WriteFile(j.OutputFile, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
		}
		job.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
		jobs = append(jobs, job)
	}
	return jobs
}
