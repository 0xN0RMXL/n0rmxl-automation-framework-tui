package phase8

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

func buildCloudJobs(ctx phase8Context) []*engine.Job {
	jobs := make([]*engine.Job, 0, 8)

	s3Candidates := engine.NewJob(8, "s3-candidates", "", nil)
	s3Candidates.ID = "phase8-s3-candidates"
	s3Candidates.Description = "Generate potential S3 bucket names from target"
	s3Candidates.OutputFile = ctx.s3Candidates
	s3Candidates.Timeout = 1 * time.Minute
	s3Candidates.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		base := strings.ReplaceAll(ctx.rootDomain, ".", "-")
		candidates := []string{base, base + "-backup", base + "-dev", base + "-staging", base + "-uploads", base + "-media", base + "-assets", base + "-public", base + "-private"}
		return writeLines(j.OutputFile, sortUnique(candidates))
	}
	s3Candidates.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
	jobs = append(jobs, s3Candidates)

	s3Scan := engine.NewJob(8, "s3-scan", "s3scanner", nil)
	s3Scan.ID = "phase8-s3-scan"
	s3Scan.Description = "Enumerate S3 bucket misconfigurations"
	s3Scan.OutputFile = filepath.Join(ctx.ws.VulnDir("cloud"), "s3_buckets.json")
	s3Scan.DependsOn = []string{s3Candidates.ID}
	s3Scan.Timeout = 25 * time.Minute
	s3Scan.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.s3Candidates) {
			markSkipped(j, "S3 candidate list missing")
			return nil
		}
		args := []string{"-bucket-file", ctx.s3Candidates, "-threads", fmt.Sprintf("%d", maxInt(10, ctx.threads)), "-json"}
		if err := runStdoutToFile(execCtx, ctx.runCfg, "s3scanner", args, j.OutputFile); err != nil {
			markSkipped(j, "s3scanner failed: "+err.Error())
			return nil
		}
		return nil
	}
	s3Scan.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
	jobs = append(jobs, s3Scan)

	cloudEnum := engine.NewJob(8, "cloud-enum", "", nil)
	cloudEnum.ID = "phase8-cloud-enum"
	cloudEnum.Description = "Run cloud_enum for cloud asset discovery"
	cloudEnum.OutputFile = filepath.Join(ctx.ws.VulnDir("cloud"), "cloud_enum.txt")
	cloudEnum.Timeout = 20 * time.Minute
	cloudEnum.Execute = func(execCtx context.Context, j *engine.Job) error {
		pythonBin := "python3"
		if _, err := exec.LookPath(pythonBin); err != nil {
			if _, pyErr := exec.LookPath("python"); pyErr == nil {
				pythonBin = "python"
			}
		}
		if _, err := exec.LookPath(pythonBin); err != nil {
			markSkipped(j, "python runtime not found")
			return nil
		}
		script := filepath.Join(os.Getenv("HOME"), ".local", "share", "n0rmxl", "tools", "cloud_enum", "cloud_enum.py")
		if !fileExists(script) {
			script = filepath.Join(os.Getenv("USERPROFILE"), ".local", "share", "n0rmxl", "tools", "cloud_enum", "cloud_enum.py")
		}
		if !fileExists(script) {
			markSkipped(j, "cloud_enum.py not found")
			return nil
		}
		args := []string{script, "-k", ctx.rootDomain, "-l", j.OutputFile, "--threads", fmt.Sprintf("%d", maxInt(10, ctx.threads))}
		if err := runCommand(execCtx, ctx.runCfg, pythonBin, args); err != nil {
			markSkipped(j, "cloud_enum failed: "+err.Error())
			return nil
		}
		return nil
	}
	cloudEnum.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
	jobs = append(jobs, cloudEnum)

	azureBlob := engine.NewJob(8, "azure-blob", "", nil)
	azureBlob.ID = "phase8-azure-blob"
	azureBlob.Description = "Check public Azure Blob endpoint exposure"
	azureBlob.OutputFile = filepath.Join(ctx.ws.VulnDir("cloud"), "azure_blob.txt")
	azureBlob.Timeout = 2 * time.Minute
	azureBlob.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		client := httpClientForRun(ctx.runCfg)
		endpoints := []string{
			"https://" + ctx.rootDomain + ".blob.core.windows.net/?comp=list",
			"https://" + strings.ReplaceAll(ctx.rootDomain, ".", "") + ".blob.core.windows.net/?comp=list",
		}
		results := make([]string, 0, len(endpoints))
		for _, endpoint := range endpoints {
			req, _ := http.NewRequestWithContext(execCtx, http.MethodGet, endpoint, nil)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_ = resp.Body.Close()
			results = append(results, fmt.Sprintf("%s -> %d", endpoint, resp.StatusCode))
		}
		if len(results) == 0 {
			markSkipped(j, "no Azure blob endpoints responded")
			return nil
		}
		return writeLines(j.OutputFile, results)
	}
	azureBlob.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
	jobs = append(jobs, azureBlob)

	gcpBuckets := engine.NewJob(8, "gcp-buckets", "", nil)
	gcpBuckets.ID = "phase8-gcp-buckets"
	gcpBuckets.Description = "Check public GCP bucket endpoint exposure"
	gcpBuckets.OutputFile = filepath.Join(ctx.ws.VulnDir("cloud"), "gcp_buckets.txt")
	gcpBuckets.Timeout = 2 * time.Minute
	gcpBuckets.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		client := httpClientForRun(ctx.runCfg)
		endpoints := []string{
			"https://storage.googleapis.com/" + ctx.rootDomain + "?alt=json",
			"https://storage.googleapis.com/" + strings.ReplaceAll(ctx.rootDomain, ".", "-") + "?alt=json",
		}
		results := make([]string, 0, len(endpoints))
		for _, endpoint := range endpoints {
			req, _ := http.NewRequestWithContext(execCtx, http.MethodGet, endpoint, nil)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_ = resp.Body.Close()
			results = append(results, fmt.Sprintf("%s -> %d", endpoint, resp.StatusCode))
		}
		if len(results) == 0 {
			markSkipped(j, "no GCP bucket endpoints responded")
			return nil
		}
		return writeLines(j.OutputFile, results)
	}
	gcpBuckets.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
	jobs = append(jobs, gcpBuckets)

	awsCred := engine.NewJob(8, "aws-credentials-check", "aws", nil)
	awsCred.ID = "phase8-aws-credentials-check"
	awsCred.Description = "Check discovered AWS credential material safely"
	awsCred.OutputFile = filepath.Join(ctx.ws.VulnDir("cloud"), "aws_credentials_check.txt")
	awsCred.Timeout = 2 * time.Minute
	awsCred.Execute = func(execCtx context.Context, j *engine.Job) error {
		candidates := findAWSCredentialCandidates(ctx.ws)
		if len(candidates) == 0 {
			markSkipped(j, "no AWS credential candidates found")
			return nil
		}
		results := make([]string, 0, len(candidates)+1)
		results = append(results, "Credential candidates found; verification requires operator-approved key usage.")
		results = append(results, candidates...)
		return writeLines(j.OutputFile, results)
	}
	awsCred.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
	jobs = append(jobs, awsCred)

	shodan := engine.NewJob(8, "shodan-cloud", "shodan", nil)
	shodan.ID = "phase8-shodan-cloud"
	shodan.Description = "Search cloud-exposed assets via Shodan CLI"
	shodan.OutputFile = filepath.Join(ctx.ws.ReconIPs, "shodan_cloud.txt")
	shodan.Timeout = 6 * time.Minute
	shodan.Execute = func(execCtx context.Context, j *engine.Job) error {
		if strings.TrimSpace(os.Getenv("SHODAN_API_KEY")) == "" {
			markSkipped(j, "SHODAN_API_KEY not configured")
			return nil
		}
		query := fmt.Sprintf("hostname:%s", ctx.rootDomain)
		if err := runStdoutToFile(execCtx, ctx.runCfg, "shodan", []string{"search", query, "--fields", "ip_str,port,org,product"}, j.OutputFile); err != nil {
			markSkipped(j, "shodan search failed: "+err.Error())
			return nil
		}
		return nil
	}
	shodan.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
	jobs = append(jobs, shodan)

	nucleiCloud := engine.NewJob(8, "nuclei-cloud", "nuclei", nil)
	nucleiCloud.ID = "phase8-nuclei-cloud"
	nucleiCloud.Description = "Run cloud misconfiguration nuclei templates"
	nucleiCloud.OutputFile = filepath.Join(ctx.ws.ScansNuclei, "cloud.json")
	nucleiCloud.Timeout = 25 * time.Minute
	nucleiCloud.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countNonEmptyLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		args := []string{"-l", ctx.liveHosts, "-t", "cloud/", "-silent", "-json", "-o", j.OutputFile, "-rate-limit", fmt.Sprintf("%d", maxInt(20, ctx.nucleiRate)), "-c", fmt.Sprintf("%d", maxInt(10, ctx.threads))}
		if err := runCommand(execCtx, ctx.runCfg, "nuclei", args); err != nil {
			markSkipped(j, "nuclei cloud scan failed: "+err.Error())
			return nil
		}
		return nil
	}
	nucleiCloud.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
	jobs = append(jobs, nucleiCloud)

	return jobs
}

func findAWSCredentialCandidates(ws models.Workspace) []string {
	paths := []string{
		filepath.Join(ws.ReconJS, "secrets", "secretfinder.txt"),
		filepath.Join(ws.ReconJS, "secrets", "jsleak.txt"),
		filepath.Join(ws.Loot, "credentials", "candidates.txt"),
	}
	set := make(map[string]struct{})
	for _, path := range paths {
		for _, row := range readNonEmptyLines(path) {
			low := strings.ToLower(row)
			if strings.Contains(low, "aws_access_key_id") || strings.Contains(low, "aws_secret_access_key") || strings.Contains(low, "akia") {
				set[row] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for row := range set {
		out = append(out, row)
	}
	return sortUnique(out)
}
