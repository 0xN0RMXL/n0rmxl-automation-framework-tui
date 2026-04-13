package phase3

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

type securityHeaderResult struct {
	URL         string   `json:"url"`
	Missing     []string `json:"missing"`
	Interesting []string `json:"interesting"`
}

func buildServiceAnalysisJobs(ctx phase3Context) []*engine.Job {
	jobs := make([]*engine.Job, 0, 6)

	nmapVuln := engine.NewJob(3, "nmap-vuln-scripts", "nmap", nil)
	nmapVuln.Description = "Run nmap vuln/http scripts for discovered open ports"
	nmapVuln.OutputFile = filepath.Join(ctx.ws.ScansPorts, "nmap_vuln_summary.txt")
	nmapVuln.Timeout = 20 * time.Minute
	nmapVuln.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.naabuTop) || countFileLines(ctx.naabuTop) == 0 {
			markSkipped(j, "naabu output missing; skipping nmap vuln scripts")
			return nil
		}
		hostPorts := parseNaabuHostPorts(ctx.naabuTop)
		if len(hostPorts) == 0 {
			markSkipped(j, "no host:port pairs parsed from naabu output")
			return nil
		}
		nmapDir := filepath.Join(ctx.ws.ScansPorts, "nmap")
		_ = os.MkdirAll(nmapDir, 0o755)

		hosts := make([]string, 0, len(hostPorts))
		for host := range hostPorts {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)

		summary := make([]string, 0, len(hosts))
		for _, host := range hosts {
			ports := hostPorts[host]
			if len(ports) == 0 {
				continue
			}
			xmlOut := filepath.Join(nmapDir, sanitizeFileName(host)+"_vuln.xml")
			args := []string{"-sV", "--script", "vuln,http-methods,http-headers", "-p", strings.Join(ports, ","), host, "-oX", xmlOut}
			if err := runCommand(execCtx, ctx.runCfg, "nmap", args); err != nil {
				j.LogLine("[WARN] nmap vuln scripts failed for " + host + ": " + err.Error())
				continue
			}
			summary = append(summary, fmt.Sprintf("%s ports=%s xml=%s", host, strings.Join(ports, ","), xmlOut))
		}
		if len(summary) == 0 {
			markSkipped(j, "nmap vuln scripts produced no usable output")
			return nil
		}
		return writeLines(j.OutputFile, summary)
	}
	nmapVuln.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, nmapVuln)

	analyzeHeaders := engine.NewJob(3, "analyze-headers", "", nil)
	analyzeHeaders.Description = "Analyze security and leakage headers for live hosts"
	analyzeHeaders.OutputFile = filepath.Join(ctx.ws.ScansTech, "security_headers.json")
	analyzeHeaders.Timeout = 15 * time.Minute
	analyzeHeaders.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.httpxJSON) || countFileLines(ctx.httpxJSON) == 0 {
			markSkipped(j, "httpx results missing; skipping header analysis")
			return nil
		}
		urls := parseHTTPXURLs(ctx.httpxJSON)
		if len(urls) == 0 {
			markSkipped(j, "no URLs parsed from httpx results")
			return nil
		}

		client := httpClientForRun(ctx.runCfg)
		missingHeaders := []string{"Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy", "X-XSS-Protection"}
		results := make([]securityHeaderResult, 0, len(urls))
		findings := make([]models.Finding, 0, len(urls))

		for _, targetURL := range urls {
			req, err := http.NewRequestWithContext(execCtx, http.MethodGet, targetURL, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			headers := resp.Header
			_ = resp.Body.Close()

			missing := make([]string, 0, len(missingHeaders))
			for _, key := range missingHeaders {
				if strings.TrimSpace(headers.Get(key)) == "" {
					missing = append(missing, key)
				}
			}

			interesting := make([]string, 0, 3)
			if server := strings.TrimSpace(headers.Get("Server")); server != "" {
				interesting = append(interesting, "Server="+server)
			}
			if powered := strings.TrimSpace(headers.Get("X-Powered-By")); powered != "" {
				interesting = append(interesting, "X-Powered-By="+powered)
			}
			if asp := strings.TrimSpace(headers.Get("X-AspNet-Version")); asp != "" {
				interesting = append(interesting, "X-AspNet-Version="+asp)
			}

			if len(missing) == 0 && len(interesting) == 0 {
				continue
			}
			results = append(results, securityHeaderResult{URL: targetURL, Missing: missing, Interesting: interesting})

			parsed, parseErr := url.Parse(targetURL)
			if parseErr == nil && strings.EqualFold(parsed.Scheme, "https") {
				for _, key := range missing {
					if key == "Strict-Transport-Security" {
						findings = append(findings, models.Finding{
							Phase:       3,
							VulnClass:   "missing-hsts",
							Target:      ctx.domain,
							Host:        parsed.Hostname(),
							URL:         targetURL,
							Severity:    models.Low,
							Title:       "HSTS header missing on HTTPS endpoint",
							Description: "HTTPS response did not include Strict-Transport-Security.",
							Tool:        "analyze-headers",
							Timestamp:   time.Now().UTC(),
						})
						break
					}
				}
			}
		}

		if len(results) == 0 {
			markSkipped(j, "no actionable header observations found")
			return nil
		}
		saveFindings(ctx.ws, findings)
		return writeJSON(j.OutputFile, results)
	}
	analyzeHeaders.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, analyzeHeaders)

	gitExposure := engine.NewJob(3, "git-exposure", "httpx", nil)
	gitExposure.Description = "Check exposed /.git/config endpoints"
	gitExposure.OutputFile = filepath.Join(ctx.ws.Vulns, "misc", "git_exposed.txt")
	gitExposure.Timeout = 10 * time.Minute
	gitExposure.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing; skipping git exposure checks")
			return nil
		}
		args := []string{"-l", ctx.liveHosts, "-path", "/.git/config", "-mc", "200", "-silent", "-o", j.OutputFile}
		if err := runCommand(execCtx, ctx.runCfg, "httpx", args); err != nil {
			return err
		}
		hits := readNonEmptyLines(j.OutputFile)
		if len(hits) == 0 {
			markSkipped(j, "no exposed .git endpoints detected")
			return nil
		}
		findings := make([]models.Finding, 0, len(hits))
		for _, hit := range hits {
			parsed, err := url.Parse(hit)
			host := ""
			if err == nil {
				host = parsed.Hostname()
			}
			findings = append(findings, models.Finding{
				Phase:       3,
				VulnClass:   "exposed-git",
				Target:      ctx.domain,
				Host:        host,
				URL:         hit,
				Severity:    models.High,
				Title:       "Exposed .git repository",
				Description: "The endpoint returned /.git/config and may allow repository disclosure.",
				Tool:        "git-exposure",
				Timestamp:   time.Now().UTC(),
			})
		}
		saveFindings(ctx.ws, findings)
		return nil
	}
	gitExposure.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, gitExposure)

	gitDumper := engine.NewJob(3, "git-dumper", "git-dumper", nil)
	gitDumper.Description = "Attempt repository dump for confirmed git exposures"
	gitDumper.OutputFile = filepath.Join(ctx.ws.Loot, "git_dumps", "git_dumper.log")
	gitDumper.DependsOn = []string{gitExposure.ID}
	gitDumper.Timeout = 20 * time.Minute
	gitDumper.Execute = func(execCtx context.Context, j *engine.Job) error {
		hits := readNonEmptyLines(gitExposure.OutputFile)
		if len(hits) == 0 {
			markSkipped(j, "no confirmed git exposure targets for dumping")
			return nil
		}
		logs := make([]string, 0, len(hits))
		for _, hit := range hits {
			base := strings.TrimSpace(strings.TrimSuffix(hit, "/.git/config"))
			parsed, err := url.Parse(base)
			if err != nil || strings.TrimSpace(parsed.Hostname()) == "" {
				continue
			}
			dest := filepath.Join(ctx.ws.Loot, "git_dumps", sanitizeFileName(parsed.Hostname()))
			repoURL := strings.TrimRight(base, "/") + "/.git/"
			if err := runCommand(execCtx, ctx.runCfg, "git-dumper", []string{repoURL, dest}); err != nil {
				j.LogLine("[WARN] git-dumper failed for " + repoURL + ": " + err.Error())
				continue
			}
			logs = append(logs, fmt.Sprintf("dumped %s to %s", repoURL, dest))
		}
		if len(logs) == 0 {
			markSkipped(j, "git-dumper did not produce any repository dumps")
			return nil
		}
		return writeLines(j.OutputFile, logs)
	}
	gitDumper.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, gitDumper)

	backupFiles := engine.NewJob(3, "backup-files", "ffuf", nil)
	backupFiles.Description = "Probe common backup file exposures with ffuf"
	backupFiles.OutputFile = filepath.Join(ctx.ws.Vulns, "misc", "backups.json")
	backupFiles.Timeout = 15 * time.Minute
	backupFiles.Execute = func(execCtx context.Context, j *engine.Job) error {
		interestingHosts := filepath.Join(ctx.ws.ScansHTTP, "interesting_hosts.txt")
		if !fileExists(interestingHosts) || countFileLines(interestingHosts) == 0 {
			markSkipped(j, "interesting hosts file missing; skipping backup file checks")
			return nil
		}
		hosts := readNonEmptyLines(interestingHosts)
		extensions := []string{".bak", ".old", "~", ".orig", ".backup", ".sql"}
		candidates := make([]string, 0, len(hosts)*len(extensions))
		for _, host := range hosts {
			host = strings.TrimRight(strings.TrimSpace(host), "/")
			if host == "" {
				continue
			}
			for _, ext := range extensions {
				candidates = append(candidates, host+"/backup"+ext)
			}
		}
		if len(candidates) == 0 {
			markSkipped(j, "no URL candidates built for backup checks")
			return nil
		}
		sort.Strings(candidates)
		candidates = dedupSorted(candidates)
		candidateFile := filepath.Join(ctx.ws.Hidden, "phase3_backup_candidates.txt")
		if err := writeLines(candidateFile, candidates); err != nil {
			return err
		}
		args := []string{"-u", "FUZZ", "-w", candidateFile, "-mc", "200", "-of", "json", "-o", j.OutputFile}
		return runCommand(execCtx, ctx.runCfg, "ffuf", args)
	}
	backupFiles.ParseOutput = func(j *engine.Job) int {
		raw, err := os.ReadFile(j.OutputFile)
		if err != nil {
			return 0
		}
		return strings.Count(string(raw), "\"status\":")
	}
	jobs = append(jobs, backupFiles)

	cloudDiscovery := engine.NewJob(3, "cloud-storage-discovery", "python3", nil)
	cloudDiscovery.Description = "Cloud storage bucket discovery"
	cloudDiscovery.OutputFile = filepath.Join(ctx.ws.Vulns, "cloud", "cloud_buckets.txt")
	cloudDiscovery.Timeout = 15 * time.Minute
	cloudDiscovery.Execute = func(execCtx context.Context, j *engine.Job) error {
		script := filepath.Join(expandHome("~"), ".local", "share", "n0rmxl", "tools", "cloud_enum", "cloud_enum.py")
		if !fileExists(script) {
			markSkipped(j, "cloud_enum script not found")
			return nil
		}
		root := rootDomain(ctx.domain)
		if root == "" {
			markSkipped(j, "unable to derive root domain for cloud discovery")
			return nil
		}
		args := []string{script, "-k", root, "--disable-gcp", "-l", j.OutputFile}
		if err := runCommand(execCtx, ctx.runCfg, "python3", args); err != nil {
			return err
		}
		if _, err := exec.LookPath("s3scanner"); err == nil && fileExists(j.OutputFile) && countFileLines(j.OutputFile) > 0 {
			s3Out := filepath.Join(ctx.ws.Vulns, "cloud", "s3scanner.txt")
			_ = runStdoutToFile(execCtx, ctx.runCfg, "s3scanner", []string{"scan", "--domains-file", j.OutputFile}, s3Out)
		}
		return nil
	}
	cloudDiscovery.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, cloudDiscovery)

	return jobs
}
