package phase4

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

type phase4Context struct {
	target            *models.Target
	ws                models.Workspace
	runCfg            *config.RunConfig
	domain            string
	rootDomain        string
	threads           int
	rateLimit         int
	liveHosts         string
	allSubsMerged     string
	urlsMerged        string
	urlsDeduped       string
	interestingDir    string
	allJS             string
	jsEndpoints       string
	jsSecretsDir      string
	allParams         string
	paramNames        string
	dirWordlist       string
	apiRoutesWordlist string
	paramsWordlist    string
	vhostWordlist     string
}

type urlDiscoveryOutput struct {
	Jobs         []*engine.Job
	MergeURLsID  string
	GFCategorize string
}

type apiDiscoveryOutput struct {
	Jobs        []*engine.Job
	ArjunOutput string
}

func Jobs(target *models.Target, ws models.Workspace, runCfg *config.RunConfig) []*engine.Job {
	if target == nil || strings.TrimSpace(target.Domain) == "" {
		return []*engine.Job{}
	}
	_ = os.MkdirAll(ws.ReconURLs, 0o755)
	_ = os.MkdirAll(filepath.Join(ws.ReconURLs, "interesting"), 0o755)
	_ = os.MkdirAll(ws.ReconJS, 0o755)
	_ = os.MkdirAll(filepath.Join(ws.ReconJS, "secrets"), 0o755)
	_ = os.MkdirAll(ws.ReconParams, 0o755)
	_ = os.MkdirAll(ws.ScansFuzz, 0o755)
	_ = os.MkdirAll(filepath.Join(ws.ScansFuzz, "dirs"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.ScansFuzz, "vhosts"), 0o755)

	defaults := config.DefaultConfig()
	threads := 50
	rate := 100
	if runCfg != nil {
		if runCfg.Settings.Threads > 0 {
			threads = runCfg.Settings.Threads
		}
		if runCfg.Settings.RateLimit > 0 {
			rate = runCfg.Settings.RateLimit
		}
	}
	ctx := phase4Context{
		target:            target,
		ws:                ws,
		runCfg:            runCfg,
		domain:            strings.TrimSpace(target.Domain),
		rootDomain:        rootDomain(strings.TrimSpace(target.Domain)),
		threads:           threads,
		rateLimit:         rate,
		liveHosts:         filepath.Join(ws.ScansHTTP, "live_hosts.txt"),
		allSubsMerged:     filepath.Join(ws.ReconSubs, "all_subs_merged.txt"),
		urlsMerged:        filepath.Join(ws.ReconURLs, "all_urls_merged.txt"),
		urlsDeduped:       filepath.Join(ws.ReconURLs, "all_urls_deduped.txt"),
		interestingDir:    filepath.Join(ws.ReconURLs, "interesting"),
		allJS:             filepath.Join(ws.ReconJS, "all_js.txt"),
		jsEndpoints:       filepath.Join(ws.ReconJS, "endpoints.txt"),
		jsSecretsDir:      filepath.Join(ws.ReconJS, "secrets"),
		allParams:         filepath.Join(ws.ReconParams, "all_params.txt"),
		paramNames:        filepath.Join(ws.ReconParams, "param_names.txt"),
		dirWordlist:       strings.TrimSpace(defaults.Wordlists.DirMedium),
		apiRoutesWordlist: strings.TrimSpace(defaults.Wordlists.APIRoutes),
		paramsWordlist:    strings.TrimSpace(defaults.Wordlists.Params),
		vhostWordlist:     strings.TrimSpace(defaults.Wordlists.DNSMedium),
	}

	urlOut := buildURLDiscoveryJobs(ctx)
	jsJobs := buildJSAnalysisJobs(ctx, urlOut.MergeURLsID)
	apiOut := buildAPIDiscoveryJobs(ctx, urlOut.MergeURLsID)
	paramJobs := buildParamDiscoveryJobs(ctx, urlOut.MergeURLsID, apiOut.ArjunOutput)
	coverageJobs := buildCoverageJobs(ctx, urlOut.MergeURLsID, urlOut.GFCategorize)

	jobs := make([]*engine.Job, 0, 40)
	jobs = append(jobs, urlOut.Jobs...)
	jobs = append(jobs, jsJobs...)
	jobs = append(jobs, apiOut.Jobs...)
	jobs = append(jobs, paramJobs...)
	jobs = append(jobs, coverageJobs...)
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

func runCommandWithInputFileToOutput(ctx context.Context, runCfg *config.RunConfig, binary string, args []string, inputPath string, outputPath string) error {
	in, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()
	cmd := exec.CommandContext(ctx, binary, args...)
	applyProxyEnv(cmd, runCfg)
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

func runCommandWithInputTextToOutput(ctx context.Context, runCfg *config.RunConfig, binary string, args []string, input string, outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()
	cmd := exec.CommandContext(ctx, binary, args...)
	applyProxyEnv(cmd, runCfg)
	cmd.Stdin = strings.NewReader(input)
	cmd.Stdout = out
	cmd.Stderr = out
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

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
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

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if len(lines) == 0 {
		return os.WriteFile(path, []byte(""), 0o644)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func dedupSorted(values []string) []string {
	if len(values) <= 1 {
		return values
	}
	out := values[:1]
	for i := 1; i < len(values); i++ {
		if values[i] != values[i-1] {
			out = append(out, values[i])
		}
	}
	return out
}

func hostFromAny(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if parsed, err := url.Parse(raw); err == nil {
			return strings.ToLower(strings.TrimSpace(parsed.Hostname()))
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

func rootDomain(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func parseURLQueryParamNames(rawURL string) []string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return []string{}
	}
	query := parsed.Query()
	if len(query) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(query))
	for key := range query {
		key = strings.TrimSpace(strings.ToLower(key))
		if key != "" {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return dedupSorted(out)
}

func isLikelyURL(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

func sanitizeFileName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		"?", "_",
		"*", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return replacer.Replace(value)
}

func expandHome(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || !strings.HasPrefix(path, "~") {
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

func saveFindings(workspace models.Workspace, findings []models.Finding) {
	if len(findings) == 0 {
		return
	}
	db, err := models.InitFindingsDB(workspace.Root)
	if err != nil {
		return
	}
	defer db.Close()
	_ = models.SaveFindingsBatch(db, findings)
}
