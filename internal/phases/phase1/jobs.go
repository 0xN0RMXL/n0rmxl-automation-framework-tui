package phase1

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

type phase1Context struct {
	target      *models.Target
	ws          models.Workspace
	runCfg      *config.RunConfig
	domain      string
	subsDir     string
	ipsDir      string
	asnOut      string
	asnIPsOut   string
	ipRangesOut string
	rdnsOut     string
	orgName     string
}

func Jobs(target *models.Target, ws models.Workspace, runCfg *config.RunConfig) []*engine.Job {
	if target == nil || strings.TrimSpace(target.Domain) == "" {
		return []*engine.Job{}
	}
	domain := strings.TrimSpace(target.Domain)
	subsDir := ws.ReconSubs
	ipsDir := ws.ReconIPs
	_ = os.MkdirAll(subsDir, 0o755)
	_ = os.MkdirAll(ipsDir, 0o755)

	ctx := phase1Context{
		target:      target,
		ws:          ws,
		runCfg:      runCfg,
		domain:      domain,
		subsDir:     subsDir,
		ipsDir:      ipsDir,
		asnOut:      filepath.Join(ipsDir, "asn.txt"),
		asnIPsOut:   filepath.Join(ipsDir, "asn_ips.txt"),
		ipRangesOut: filepath.Join(ipsDir, "ip_ranges.txt"),
		rdnsOut:     filepath.Join(ipsDir, "rdns.txt"),
		orgName:     discoverOrgName(target),
	}

	jobs := make([]*engine.Job, 0, 32)
	asnJobs, asnmapIPsID := buildASNIPJobs(ctx)
	jobs = append(jobs, buildPassiveSubsJobs(ctx)...)
	jobs = append(jobs, buildCRTSHJobs(ctx, asnmapIPsID)...)
	jobs = append(jobs, buildGithubScrapeJobs(ctx)...)
	jobs = append(jobs, buildOSINTAPIJobs(ctx)...)
	jobs = append(jobs, asnJobs...)

	depends := make([]string, 0, len(jobs))
	for _, job := range jobs {
		depends = append(depends, job.ID)
	}

	merge := engine.NewJob(1, "merge-subs", "", nil)
	merge.Description = "Merge and deduplicate passive subdomain outputs"
	merge.OutputFile = filepath.Join(ctx.subsDir, "all_subs_merged.txt")
	merge.DependsOn = depends
	merge.Execute = func(execCtx context.Context, j *engine.Job) error {
		if err := execCtx.Err(); err != nil {
			return err
		}
		inputs, err := filepath.Glob(filepath.Join(ctx.subsDir, "*.txt"))
		if err != nil {
			return err
		}
		sort.Strings(inputs)
		filtered := make([]string, 0, len(inputs))
		for _, in := range inputs {
			if filepath.Base(in) == filepath.Base(j.OutputFile) {
				continue
			}
			filtered = append(filtered, in)
		}
		manager := engine.NewOutputManager(ctx.ws)
		if _, err := manager.MergeAndDedup(filtered, j.OutputFile); err != nil {
			return fmt.Errorf("phase1 merge failed: %w", err)
		}
		if ctx.runCfg != nil && ctx.runCfg.Scope != nil {
			tmp := j.OutputFile + ".tmp"
			if _, err := manager.ScopeFilter(j.OutputFile, tmp, ctx.runCfg.Scope); err == nil {
				_ = os.Remove(j.OutputFile)
				_ = os.Rename(tmp, j.OutputFile)
			}
		}
		j.LogLine("[DONE] merged passive subdomain outputs")
		return nil
	}
	merge.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, merge)

	return jobs
}

func runCommand(ctx context.Context, runCfg *config.RunConfig, binary string, args []string) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	applyProxyEnv(cmd, runCfg)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
		}
		return err
	}
	return nil
}

func runStdoutToFile(ctx context.Context, runCfg *config.RunConfig, binary string, args []string, outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, binary, args...)
	applyProxyEnv(cmd, runCfg)
	cmd.Stdout = f
	cmd.Stderr = f
	return cmd.Run()
}

func runCommandWithStdinToFile(ctx context.Context, runCfg *config.RunConfig, binary string, args []string, stdinText string, outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, binary, args...)
	applyProxyEnv(cmd, runCfg)
	cmd.Stdin = strings.NewReader(stdinText)
	cmd.Stdout = f
	cmd.Stderr = f
	return cmd.Run()
}

func collectCommandLines(ctx context.Context, runCfg *config.RunConfig, binary string, args []string, stdinText string) ([]string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	applyProxyEnv(cmd, runCfg)
	if strings.TrimSpace(stdinText) != "" {
		cmd.Stdin = strings.NewReader(stdinText)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) > 0 {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil, err
	}
	rows := make([]string, 0, 128)
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			rows = append(rows, line)
		}
	}
	return rows, nil
}

func applyProxyEnv(cmd *exec.Cmd, runCfg *config.RunConfig) {
	if cmd == nil || runCfg == nil || !runCfg.UseBurp {
		return
	}
	proxy := "http://127.0.0.1:8080"
	cmd.Env = append(os.Environ(), "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy)
}

func markSkipped(job *engine.Job, reason string) {
	if job == nil {
		return
	}
	job.Status = engine.JobSkipped
	job.ErrorMsg = reason
	job.LogLine("[WARN] " + reason)
}

func countFileLines(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func countLinesInDir(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	total := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		total += countFileLines(filepath.Join(dir, entry.Name()))
	}
	return total
}

func httpGetRetry(ctx context.Context, targetURL string, headers map[string]string, attempts int) ([]byte, error) {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		body, err := httpGet(ctx, targetURL, headers)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if attempt == attempts {
			break
		}
		wait := time.Duration(attempt) * 2 * time.Second
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, lastErr
}

func httpGet(ctx context.Context, targetURL string, headers map[string]string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	client := &http.Client{Timeout: 45 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return nil, fmt.Errorf("http request failed: %s", response.Status)
	}
	return io.ReadAll(response.Body)
}

func normalizeSubdomain(raw string, domain string) string {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "*."))
	raw = strings.ToLower(raw)
	domain = strings.ToLower(strings.TrimSpace(domain))
	if raw == "" || domain == "" {
		return ""
	}
	if raw == domain || strings.HasSuffix(raw, "."+domain) {
		return raw
	}
	return ""
}

func hostFromAny(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err == nil {
			return strings.ToLower(parsed.Hostname())
		}
	}
	if idx := strings.Index(raw, "/"); idx > 0 {
		raw = raw[:idx]
	}
	if idx := strings.Index(raw, ":"); idx > 0 {
		raw = raw[:idx]
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func writeUniqueLines(path string, values []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	sort.Strings(values)
	values = dedupSorted(values)
	if len(values) == 0 {
		return os.WriteFile(path, []byte(""), 0o644)
	}
	return os.WriteFile(path, []byte(strings.Join(values, "\n")+"\n"), 0o644)
}

func dedupSorted(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:0]
	last := ""
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || value == last {
			continue
		}
		out = append(out, value)
		last = value
	}
	return out
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func readNonEmptyLines(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	rows := strings.Split(string(raw), "\n")
	clean := make([]string, 0, len(rows))
	for _, row := range rows {
		row = strings.TrimSpace(row)
		if row != "" {
			clean = append(clean, row)
		}
	}
	return clean
}

func pickExisting(paths ...string) string {
	for _, path := range paths {
		if fileExists(path) {
			return path
		}
	}
	return ""
}

func parseASNNumbersFromFile(path string) []string {
	rows := readNonEmptyLines(path)
	asnRe := regexp.MustCompile(`(?i)\bAS?(\d{1,10})\b`)
	set := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		matches := asnRe.FindAllStringSubmatch(row, -1)
		for _, match := range matches {
			if len(match) > 1 {
				set[match[1]] = struct{}{}
			}
		}
	}
	values := make([]string, 0, len(set))
	for asn := range set {
		values = append(values, asn)
	}
	sort.Strings(values)
	return values
}

func extractIPsFromLines(lines []string) []string {
	if len(lines) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		tokens := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == '|' || r == '\t' || r == ' '
		})
		for _, token := range tokens {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			if ip := net.ParseIP(token); ip != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		value := strings.TrimSpace(os.Getenv(key))
		if value != "" {
			return value
		}
	}
	return ""
}

func discoverOrgName(target *models.Target) string {
	if value := strings.TrimSpace(os.Getenv("N0RMXL_ORG_NAME")); value != "" {
		return value
	}
	if target == nil {
		return ""
	}
	if value := strings.TrimSpace(os.Getenv("PROGRAM_ORG_NAME")); value != "" {
		return value
	}
	return ""
}

func expandHome(path string) string {
	path = strings.TrimSpace(path)
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
