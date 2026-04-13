package phase5

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
)

func buildVulnSpecificJobs(ctx phase5Context) []*engine.Job {
	jobs := make([]*engine.Job, 0, 12)

	dalfox := engine.NewJob(5, "dalfox-xss", "dalfox", nil)
	dalfox.ID = "phase5-dalfox-xss"
	dalfox.Description = "Run Dalfox in file mode against fuzz_xss URLs"
	dalfox.OutputFile = filepath.Join(ctx.ws.VulnDir("xss"), "dalfox_file.json")
	dalfox.Timeout = 35 * time.Minute
	dalfox.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.fuzzXSS) || countFileLines(ctx.fuzzXSS) == 0 {
			markSkipped(j, "fuzz_xss URL list missing")
			return nil
		}
		args := []string{"file", ctx.fuzzXSS, "--format", "json", "-o", j.OutputFile, "--worker", fmt.Sprintf("%d", maxInt(10, ctx.threads))}
		if ctx.runCfg != nil && ctx.runCfg.UseBurp {
			args = append(args, "--proxy", "http://127.0.0.1:8080")
		}
		return runCommand(execCtx, ctx.runCfg, "dalfox", args)
	}
	dalfox.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, dalfox)

	dalfoxPipe := engine.NewJob(5, "dalfox-pipe", "dalfox", nil)
	dalfoxPipe.ID = "phase5-dalfox-pipe"
	dalfoxPipe.Description = "Run Dalfox pipe mode for additional XSS checks"
	dalfoxPipe.OutputFile = filepath.Join(ctx.ws.VulnDir("xss"), "dalfox_pipe.json")
	dalfoxPipe.Timeout = 35 * time.Minute
	dalfoxPipe.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.fuzzXSS) || countFileLines(ctx.fuzzXSS) == 0 {
			markSkipped(j, "fuzz_xss URL list missing")
			return nil
		}
		args := []string{"pipe", "--format", "json"}
		if ctx.runCfg != nil && ctx.runCfg.UseBurp {
			args = append(args, "--proxy", "http://127.0.0.1:8080")
		}
		return runCommandWithInputFileToOutput(execCtx, ctx.runCfg, "dalfox", args, ctx.fuzzXSS, j.OutputFile)
	}
	dalfoxPipe.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, dalfoxPipe)

	sqlmap := engine.NewJob(5, "sqlmap", "sqlmap", nil)
	sqlmap.ID = "phase5-sqlmap-scan"
	sqlmap.Description = "Run SQLMap against fuzz_sqli URLs"
	sqlmap.OutputFile = filepath.Join(ctx.ws.VulnDir("sqli"), "sqlmap_summary.txt")
	sqlmap.Timeout = 60 * time.Minute
	sqlmap.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.fuzzSQLI) || countFileLines(ctx.fuzzSQLI) == 0 {
			markSkipped(j, "fuzz_sqli URL list missing")
			return nil
		}
		outDir := filepath.Join(ctx.ws.VulnDir("sqli"), "sqlmap")
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
		args := []string{"-m", ctx.fuzzSQLI, "--batch", "--risk", "2", "--level", "3", "--threads", fmt.Sprintf("%d", minInt(10, maxInt(2, ctx.threads/4))), "--random-agent", "--output-dir", outDir}
		if err := runCommand(execCtx, ctx.runCfg, "sqlmap", args); err != nil {
			return err
		}
		return writeLines(j.OutputFile, []string{"sqlmap output dir: " + outDir})
	}
	sqlmap.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, sqlmap)

	crlfuzz := engine.NewJob(5, "crlfuzz", "crlfuzz", nil)
	crlfuzz.ID = "phase5-crlfuzz"
	crlfuzz.Description = "Run CRLF injection checks on live hosts"
	crlfuzz.OutputFile = filepath.Join(ctx.ws.VulnDir("misc"), "crlfuzz.txt")
	crlfuzz.Timeout = 20 * time.Minute
	crlfuzz.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		return runCommandWithInputFileToOutput(execCtx, ctx.runCfg, "crlfuzz", []string{}, ctx.liveHosts, j.OutputFile)
	}
	crlfuzz.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, crlfuzz)

	corsy := engine.NewJob(5, "corsy", selectPythonBinary(), nil)
	corsy.ID = "phase5-corsy"
	corsy.Description = "Run Corsy against live hosts"
	corsy.OutputFile = filepath.Join(ctx.ws.VulnDir("cors"), "corsy.json")
	corsy.Timeout = 25 * time.Minute
	corsy.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		script := filepath.Join(expandHome("~"), ".local", "share", "n0rmxl", "tools", "Corsy", "corsy.py")
		if !fileExists(script) {
			markSkipped(j, "Corsy script not found")
			return nil
		}
		args := []string{script, "-i", ctx.liveHosts, "-t", fmt.Sprintf("%d", maxInt(10, ctx.threads)), "-o", j.OutputFile}
		return runCommand(execCtx, ctx.runCfg, selectPythonBinary(), args)
	}
	corsy.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, corsy)

	ssrf := engine.NewJob(5, "ssrf-scan", "nuclei", nil)
	ssrf.ID = "phase5-ssrf-scan"
	ssrf.Description = "Run SSRF-focused nuclei scan against fuzz_ssrf URLs"
	ssrf.OutputFile = filepath.Join(ctx.ws.VulnDir("ssrf"), "nuclei_ssrf.json")
	ssrf.Timeout = 30 * time.Minute
	ssrf.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.fuzzSSRF) || countFileLines(ctx.fuzzSSRF) == 0 {
			markSkipped(j, "fuzz_ssrf URL list missing")
			return nil
		}
		args := []string{"-l", ctx.fuzzSSRF, "-tags", "ssrf", "-silent", "-json", "-o", j.OutputFile, "-rate-limit", fmt.Sprintf("%d", maxInt(20, ctx.nucleiRate)), "-c", fmt.Sprintf("%d", maxInt(10, ctx.threads))}
		if ctx.runCfg != nil && ctx.runCfg.UseBurp {
			args = append(args, "-proxy", "http://127.0.0.1:8080")
		}
		return runCommand(execCtx, ctx.runCfg, "nuclei", args)
	}
	ssrf.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, ssrf)

	subzy := engine.NewJob(5, "subzy", "subzy", nil)
	subzy.ID = "phase5-subzy-takeover"
	subzy.Description = "Final subdomain takeover sweep"
	subzy.OutputFile = filepath.Join(ctx.ws.VulnDir("takeover"), "subzy_final.json")
	subzy.Timeout = 20 * time.Minute
	subzy.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.allSubsMerged) || countFileLines(ctx.allSubsMerged) == 0 {
			markSkipped(j, "merged subdomain list missing")
			return nil
		}
		args := []string{"run", "--targets", ctx.allSubsMerged, "--concurrency", fmt.Sprintf("%d", maxInt(10, ctx.threads)), "--hide-fails", "--output", j.OutputFile}
		return runCommand(execCtx, ctx.runCfg, "subzy", args)
	}
	subzy.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, subzy)

	headi := engine.NewJob(5, "headi", "headi", nil)
	headi.ID = "phase5-headi-headers"
	headi.Description = "Check host header injection behavior"
	headi.OutputFile = filepath.Join(ctx.ws.VulnDir("misc"), "host_header.txt")
	headi.Timeout = 20 * time.Minute
	headi.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		return runCommand(execCtx, ctx.runCfg, "headi", []string{"-l", ctx.liveHosts, "-o", j.OutputFile})
	}
	headi.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, headi)

	ppmap := engine.NewJob(5, "ppmap", "ppmap", nil)
	ppmap.ID = "phase5-ppmap-pollution"
	ppmap.Description = "Prototype pollution checks with ppmap"
	ppmap.OutputFile = filepath.Join(ctx.ws.VulnDir("misc"), "prototype_pollution.txt")
	ppmap.Timeout = 25 * time.Minute
	ppmap.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.fuzzXSS) || countFileLines(ctx.fuzzXSS) == 0 {
			markSkipped(j, "fuzz_xss URL list missing")
			return nil
		}
		return runCommand(execCtx, ctx.runCfg, "ppmap", []string{"-l", ctx.fuzzXSS, "-o", j.OutputFile})
	}
	ppmap.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, ppmap)

	byp4xx := engine.NewJob(5, "byp4xx", "byp4xx", nil)
	byp4xx.ID = "phase5-byp4xx"
	byp4xx.Description = "Attempt bypasses on 401/403 endpoints"
	byp4xx.OutputFile = filepath.Join(ctx.ws.VulnDir("misc"), "403bypass.txt")
	byp4xx.Timeout = 25 * time.Minute
	byp4xx.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.httpxJSON) {
			markSkipped(j, "httpx results missing")
			return nil
		}
		protected := parseHTTPXProtectedURLs(ctx.httpxJSON)
		if len(protected) == 0 {
			markSkipped(j, "no 401/403 endpoints found")
			return nil
		}
		summary := make([]string, 0, len(protected))
		for _, targetURL := range protected {
			if err := runCommand(execCtx, ctx.runCfg, "byp4xx", []string{"-u", targetURL}); err == nil {
				summary = append(summary, "tested: "+targetURL)
			}
		}
		sort.Strings(summary)
		return writeLines(j.OutputFile, summary)
	}
	byp4xx.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, byp4xx)

	smuggler := engine.NewJob(5, "smuggler", selectPythonBinary(), nil)
	smuggler.ID = "phase5-smuggler"
	smuggler.Description = "HTTP request smuggling checks"
	smuggler.OutputFile = filepath.Join(ctx.ws.VulnDir("smuggling"), "smuggler.txt")
	smuggler.Timeout = 30 * time.Minute
	smuggler.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		script := expandHome("~/.local/share/n0rmxl/tools/smuggler/smuggler.py")
		if !fileExists(script) {
			markSkipped(j, "smuggler.py not found")
			return nil
		}
		return runCommandWithInputFileToOutput(execCtx, ctx.runCfg, selectPythonBinary(), []string{script}, ctx.liveHosts, j.OutputFile)
	}
	smuggler.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, smuggler)

	jwt := engine.NewJob(5, "jwt-scan", "", nil)
	jwt.ID = "phase5-jwt-scan"
	jwt.Description = "Generate JWT test command candidates from discovered URLs"
	jwt.OutputFile = filepath.Join(ctx.ws.VulnDir("jwt"), "jwt_commands.txt")
	jwt.Timeout = 5 * time.Minute
	jwt.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		if !fileExists(ctx.urlsDeduped) {
			markSkipped(j, "deduped URL corpus missing")
			return nil
		}
		commands := make([]string, 0, 128)
		for _, row := range readNonEmptyLines(ctx.urlsDeduped) {
			lower := strings.ToLower(row)
			if strings.Contains(lower, "jwt") || strings.Contains(lower, "token") || strings.Contains(lower, "auth") {
				commands = append(commands, "curl -i '"+row+"' -H 'Authorization: Bearer FUZZ.JWT.TOKEN'")
			}
		}
		sort.Strings(commands)
		commands = dedupSorted(commands)
		if len(commands) == 0 {
			markSkipped(j, "no JWT-like endpoints identified")
			return nil
		}
		return writeLines(j.OutputFile, commands)
	}
	jwt.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, jwt)

	return jobs
}

