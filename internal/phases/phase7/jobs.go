package phase7

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	screenshotpkg "github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/integrations/screenshot"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

type phase7Context struct {
	target           *models.Target
	ws               models.Workspace
	runCfg           *config.RunConfig
	domain           string
	chainsFile       string
	credCandidates   string
	credValidated    string
	impactSummary    string
	confirmedShots   string
	cvssSummary      string
	impactReportsDir string
}

type vulnChain struct {
	Name        string
	Description string
	Classes     []string
	Severity    models.Severity
}

func Jobs(target *models.Target, ws models.Workspace, runCfg *config.RunConfig) []*engine.Job {
	if target == nil || strings.TrimSpace(target.Domain) == "" {
		return []*engine.Job{}
	}
	_ = os.MkdirAll(ws.Reports, 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Loot, "credentials"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Screenshots, "confirmed"), 0o755)

	ctx := phase7Context{
		target:           target,
		ws:               ws,
		runCfg:           runCfg,
		domain:           strings.TrimSpace(target.Domain),
		chainsFile:       filepath.Join(ws.Reports, "chains.md"),
		credCandidates:   filepath.Join(ws.Loot, "credentials", "candidates.txt"),
		credValidated:    filepath.Join(ws.Loot, "credentials", "valid_creds.txt"),
		impactSummary:    filepath.Join(ws.Reports, "phase7_impact_summary.md"),
		confirmedShots:   filepath.Join(ws.Screenshots, "confirmed", "confirmed_urls.txt"),
		cvssSummary:      filepath.Join(ws.Reports, "phase7_cvss_summary.md"),
		impactReportsDir: filepath.Join(ws.Reports, "impact"),
	}

	chain := engine.NewJob(7, "chain-analysis", "", nil)
	chain.Description = "Suggest high-impact vulnerability chains"
	chain.OutputFile = ctx.chainsFile
	chain.Timeout = 2 * time.Minute
	chain.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		findings, err := loadFindings(ctx.ws)
		if err != nil {
			return err
		}
		chains := suggestChains(findings)
		if len(chains) == 0 {
			markSkipped(j, "no chain opportunities found")
			return nil
		}
		var b strings.Builder
		b.WriteString("# Vulnerability Chains\n\n")
		for i, c := range chains {
			b.WriteString(fmt.Sprintf("## CHAIN-%03d %s\n\n", i+1, c.Name))
			b.WriteString(fmt.Sprintf("- Severity: %s\n", strings.ToUpper(string(c.Severity))))
			b.WriteString(fmt.Sprintf("- Classes: %s\n\n", strings.Join(c.Classes, " + ")))
			b.WriteString(c.Description + "\n\n")
		}
		return writeText(j.OutputFile, b.String())
	}
	chain.ParseOutput = func(j *engine.Job) int { return countMatchesInFile(j.OutputFile, "## CHAIN-") }

	cred := engine.NewJob(7, "credential-harvest", "", nil)
	cred.Description = "Extract credential candidates from loot and secrets"
	cred.OutputFile = ctx.credValidated
	cred.Timeout = 3 * time.Minute
	cred.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		candidates := collectCredentialCandidates(ctx.ws)
		if len(candidates) == 0 {
			markSkipped(j, "no credential candidates discovered")
			return nil
		}
		if err := writeLines(ctx.credCandidates, candidates); err != nil {
			return err
		}
		validated := make([]string, 0, len(candidates))
		for _, c := range candidates {
			validated = append(validated, c+" | validation=manual-required")
		}
		return writeLines(j.OutputFile, validated)
	}
	cred.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }

	impact := engine.NewJob(7, "data-impact-assessment", "", nil)
	impact.Description = "Generate safe impact demonstration actions"
	impact.OutputFile = ctx.impactSummary
	impact.DependsOn = []string{chain.ID}
	impact.Timeout = 2 * time.Minute
	impact.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		findings, err := loadFindings(ctx.ws)
		if err != nil {
			return err
		}
		if len(findings) == 0 {
			markSkipped(j, "no findings available for impact assessment")
			return nil
		}
		var b strings.Builder
		b.WriteString("# Phase 7 Impact Assessment\n\n")
		for _, f := range findings {
			if !(f.Confirmed || f.Severity == models.Critical || f.Severity == models.High) {
				continue
			}
			b.WriteString(fmt.Sprintf("## %s — %s\n\n", safeString(f.VulnClass, "unknown"), safeString(f.URL, f.Host)))
			b.WriteString("- Safe demonstration command:\n")
			b.WriteString("```bash\n")
			b.WriteString(impactCommandForFinding(f) + "\n")
			b.WriteString("```\n\n")
		}
		if b.Len() == 0 {
			markSkipped(j, "no high-impact findings available")
			return nil
		}
		return writeText(j.OutputFile, b.String())
	}
	impact.ParseOutput = func(j *engine.Job) int { return countMatchesInFile(j.OutputFile, "## ") }

	shots := engine.NewJob(7, "screenshot-confirmed", "gowitness", nil)
	shots.Description = "Capture screenshots for confirmed finding URLs"
	shots.OutputFile = ctx.confirmedShots
	shots.Timeout = 15 * time.Minute
	shots.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		findings, err := loadFindings(ctx.ws)
		if err != nil {
			return err
		}
		urls := uniqueConfirmedURLs(findings)
		if len(urls) == 0 {
			markSkipped(j, "no confirmed finding URLs available")
			return nil
		}
		if err := writeLines(j.OutputFile, urls); err != nil {
			return err
		}
		screenshotter := screenshotpkg.NewScreenshotter(filepath.Join(ctx.ws.Screenshots, "confirmed"))
		if !screenshotter.IsAvailable() {
			markSkipped(j, "gowitness not available; URL list prepared for manual capture")
			return nil
		}
		if err := screenshotter.ScreenshotList(j.OutputFile, filepath.Join(ctx.ws.Screenshots, "confirmed")); err != nil {
			markSkipped(j, "gowitness execution failed: "+err.Error())
			return nil
		}
		return nil
	}
	shots.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }

	cvss := engine.NewJob(7, "cvss-calculator", "", nil)
	cvss.Description = "Calculate CVSS-like base scores and update findings DB"
	cvss.OutputFile = ctx.cvssSummary
	cvss.DependsOn = []string{chain.ID}
	cvss.Timeout = 2 * time.Minute
	cvss.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		findings, err := loadFindings(ctx.ws)
		if err != nil {
			return err
		}
		if len(findings) == 0 {
			markSkipped(j, "no findings available for CVSS scoring")
			return nil
		}
		for i := range findings {
			findings[i].CVSS = computeCVSS(findings[i])
		}
		if err := saveFindings(ctx.ws, findings); err != nil {
			return err
		}
		var b strings.Builder
		b.WriteString("# CVSS Summary\n\n")
		for _, f := range findings {
			b.WriteString(fmt.Sprintf("- %.1f | %s | %s\n", f.CVSS, safeString(f.VulnClass, "unknown"), safeString(f.URL, f.Host)))
		}
		return writeText(j.OutputFile, b.String())
	}
	cvss.ParseOutput = func(j *engine.Job) int { return countMatchesInFile(j.OutputFile, "- ") }

	reports := engine.NewJob(7, "impact-report", "", nil)
	reports.Description = "Generate per-finding impact report markdown files"
	reports.OutputFile = filepath.Join(ctx.impactReportsDir, "index.md")
	reports.DependsOn = []string{impact.ID, cvss.ID}
	reports.Timeout = 3 * time.Minute
	reports.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		findings, err := loadFindings(ctx.ws)
		if err != nil {
			return err
		}
		if len(findings) == 0 {
			markSkipped(j, "no findings available for impact reports")
			return nil
		}
		if err := os.MkdirAll(ctx.impactReportsDir, 0o755); err != nil {
			return err
		}
		index := make([]string, 0, len(findings)+2)
		index = append(index, "# Impact Reports", "")
		count := 0
		for _, f := range findings {
			if !(f.Confirmed || f.Severity == models.Critical || f.Severity == models.High) {
				continue
			}
			name := sanitizeFileName(safeString(f.Host, safeString(f.VulnClass, "finding"))) + "_impact.md"
			out := filepath.Join(ctx.impactReportsDir, name)
			if err := writeText(out, renderImpactReport(f)); err != nil {
				return err
			}
			index = append(index, fmt.Sprintf("- %s", name))
			count++
		}
		if count == 0 {
			markSkipped(j, "no eligible findings for impact reports")
			return nil
		}
		return writeLines(j.OutputFile, index)
	}
	reports.ParseOutput = func(j *engine.Job) int { return countMatchesInFile(j.OutputFile, "- ") }

	return []*engine.Job{chain, cred, impact, shots, cvss, reports}
}

func loadFindings(ws models.Workspace) ([]models.Finding, error) {
	db, err := models.InitFindingsDB(ws.Root)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return models.GetFindings(db, models.FindingFilter{})
}

func saveFindings(ws models.Workspace, findings []models.Finding) error {
	db, err := models.InitFindingsDB(ws.Root)
	if err != nil {
		return err
	}
	defer db.Close()
	return models.SaveFindingsBatch(db, findings)
}

func suggestChains(findings []models.Finding) []vulnChain {
	if len(findings) == 0 {
		return []vulnChain{}
	}
	has := map[string]bool{}
	for _, f := range findings {
		cls := strings.ToLower(strings.TrimSpace(f.VulnClass))
		if cls != "" {
			has[cls] = true
		}
	}
	chains := make([]vulnChain, 0, 6)
	if has["ssrf"] && has["idor"] {
		chains = append(chains, vulnChain{Name: "SSRF + IDOR", Classes: []string{"ssrf", "idor"}, Severity: models.Critical, Description: "Potential internal service reachability plus authorization bypass can expose sensitive account records and enable account takeover paths."})
	}
	if has["xss"] && has["csrf"] {
		chains = append(chains, vulnChain{Name: "XSS + CSRF token theft", Classes: []string{"xss", "csrf"}, Severity: models.High, Description: "Session token extraction via XSS can bypass CSRF defenses and permit authenticated actions."})
	}
	if has["sqli"] {
		chains = append(chains, vulnChain{Name: "SQLi + credential dump", Classes: []string{"sqli", "credential-access"}, Severity: models.Critical, Description: "Database extraction can yield credentials and enable lateral movement to additional environments."})
	}
	if has["takeover"] && has["xss"] {
		chains = append(chains, vulnChain{Name: "Subdomain takeover + XSS", Classes: []string{"takeover", "xss"}, Severity: models.High, Description: "Takeover of trusted subdomain combined with script execution can be used for session hijack and phishing."})
	}
	if has["jwt"] && has["idor"] {
		chains = append(chains, vulnChain{Name: "JWT abuse + IDOR", Classes: []string{"jwt", "idor"}, Severity: models.High, Description: "Weak token validation plus object authorization failures can permit cross-account data access."})
	}
	return chains
}

func collectCredentialCandidates(ws models.Workspace) []string {
	roots := []string{ws.Loot, ws.ReconJS, ws.ReconParams, ws.Notes}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?([a-z0-9_\-\./+=]{8,})`),
		regexp.MustCompile(`(?i)aws_access_key_id\s*[:=]\s*([A-Z0-9]{16,})`),
		regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{20,})`),
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 64)
	for _, root := range roots {
		entries, err := walkTextFiles(root)
		if err != nil {
			continue
		}
		for _, file := range entries {
			raw, err := os.ReadFile(file)
			if err != nil || len(raw) > 2*1024*1024 {
				continue
			}
			content := string(raw)
			for _, re := range patterns {
				matches := re.FindAllString(content, -1)
				for _, match := range matches {
					candidate := file + " :: " + strings.TrimSpace(match)
					if _, ok := seen[candidate]; ok {
						continue
					}
					seen[candidate] = struct{}{}
					out = append(out, candidate)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func walkTextFiles(root string) ([]string, error) {
	if strings.TrimSpace(root) == "" {
		return []string{}, nil
	}
	if _, err := os.Stat(root); err != nil {
		return []string{}, nil
	}
	files := make([]string, 0, 64)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			name := strings.ToLower(d.Name())
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".txt", ".log", ".md", ".json", ".env", ".yaml", ".yml", ".cfg", ".ini", "":
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func uniqueConfirmedURLs(findings []models.Finding) []string {
	set := make(map[string]struct{})
	for _, f := range findings {
		if !f.Confirmed {
			continue
		}
		url := strings.TrimSpace(f.URL)
		if url == "" {
			continue
		}
		set[url] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for url := range set {
		out = append(out, url)
	}
	sort.Strings(out)
	return out
}

func impactCommandForFinding(f models.Finding) string {
	url := safeString(f.URL, "https://example.com")
	className := strings.ToLower(strings.TrimSpace(f.VulnClass))
	switch {
	case strings.Contains(className, "sqli"):
		return fmt.Sprintf("sqlmap -u \"%s\" --batch --dump --stop 5", url)
	case strings.Contains(className, "idor"):
		return fmt.Sprintf("curl -iks \"%s\" -H \"Authorization: Bearer <low-priv-token>\"", url)
	case strings.Contains(className, "ssrf"):
		return fmt.Sprintf("curl -iks \"%s\"", url)
	default:
		return fmt.Sprintf("curl -iks \"%s\"", url)
	}
}

func computeCVSS(f models.Finding) float64 {
	base := map[string]float64{
		"sqli": 9.1,
		"ssrf": 8.8,
		"xss":  7.2,
		"idor": 8.0,
		"lfi":  8.1,
		"jwt":  7.5,
	}
	cls := strings.ToLower(strings.TrimSpace(f.VulnClass))
	score := 6.0
	for key, value := range base {
		if strings.Contains(cls, key) {
			score = value
			break
		}
	}
	if f.Confirmed {
		score += 0.7
	}
	if len(f.ChainedWith) > 0 {
		score += 0.4
	}
	if f.Severity == models.Critical {
		score += 0.6
	}
	if f.Severity == models.High {
		score += 0.3
	}
	if score > 10.0 {
		score = 10.0
	}
	return float64(int(score*10)) / 10.0
}

func renderImpactReport(f models.Finding) string {
	var b strings.Builder
	b.WriteString("# Impact Report\n\n")
	b.WriteString(fmt.Sprintf("## %s\n\n", safeString(f.Title, safeString(f.VulnClass, "Untitled finding"))))
	b.WriteString(fmt.Sprintf("- Severity: %s\n", strings.ToUpper(string(f.Severity))))
	b.WriteString(fmt.Sprintf("- CVSS: %.1f\n", f.CVSS))
	b.WriteString(fmt.Sprintf("- Host: %s\n", safeString(f.Host, "n/a")))
	b.WriteString(fmt.Sprintf("- URL: %s\n\n", safeString(f.URL, "n/a")))
	b.WriteString("## Business Impact\n\n")
	b.WriteString("The finding can expose sensitive data or privileged actions and should be prioritized for remediation based on exploitability and blast radius.\n\n")
	b.WriteString("## Technical Root Cause\n\n")
	b.WriteString(safeString(f.Description, "Input validation and authorization controls are insufficient for this execution path.") + "\n\n")
	b.WriteString("## Reproduction\n\n")
	b.WriteString("```bash\n")
	b.WriteString(impactCommandForFinding(f) + "\n")
	b.WriteString("```\n\n")
	b.WriteString("## Evidence\n\n")
	b.WriteString("```\n")
	b.WriteString(safeString(f.Evidence, "No evidence attached yet."))
	b.WriteString("\n```\n\n")
	b.WriteString("## Remediation\n\n")
	b.WriteString(safeString(f.Remediation, "Apply strict input validation, enforce authorization checks, and deploy defense-in-depth controls."))
	b.WriteString("\n")
	return b.String()
}

func writeText(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
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

func countNonEmptyLines(path string) int {
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

func countMatchesInFile(path string, needle string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	if strings.TrimSpace(needle) == "" {
		return 0
	}
	return strings.Count(string(raw), needle)
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

func safeString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func markSkipped(job *engine.Job, reason string) {
	if job == nil {
		return
	}
	job.Status = engine.JobSkipped
	job.ErrorMsg = reason
	job.LogLine("[WARN] " + reason)
}

