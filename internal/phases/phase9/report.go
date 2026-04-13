package phase9

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

type ReportData struct {
	Target           models.Target
	Findings         []models.Finding
	Summary          ReportSummary
	GeneratedAt      time.Time
	FrameworkVersion string
}

type ReportSummary struct {
	TotalFindings     int
	BySeverity        map[models.Severity]int
	ByVulnClass       map[string]int
	ConfirmedFindings int
	CriticalFindings  []models.Finding
	CVSS              float64
	TopFindings       []models.Finding
	Chains            []VulnChain
	Phase             map[int]models.PhaseResult
}

type VulnChain struct {
	Name        string
	Severity    models.Severity
	Classes     []string
	Description string
}

func buildReportData(target *models.Target, workspace models.Workspace) (ReportData, error) {
	if target == nil {
		return ReportData{}, fmt.Errorf("target is required")
	}
	findings, err := loadFindings(workspace)
	if err != nil {
		return ReportData{}, err
	}
	chains := loadChains(filepath.Join(workspace.Reports, "chains.md"))
	phaseMap, _ := loadPhaseMap(workspace)
	summary := summarizeFindings(findings, chains, phaseMap)
	return ReportData{
		Target:           *target,
		Findings:         findings,
		Summary:          summary,
		GeneratedAt:      time.Now().UTC(),
		FrameworkVersion: "dev",
	}, nil
}

func summarizeFindings(findings []models.Finding, chains []VulnChain, phases map[int]models.PhaseResult) ReportSummary {
	summary := ReportSummary{
		TotalFindings:    len(findings),
		BySeverity:       map[models.Severity]int{},
		ByVulnClass:      map[string]int{},
		CriticalFindings: make([]models.Finding, 0, 8),
		TopFindings:      make([]models.Finding, 0, 5),
		Chains:           chains,
		Phase:            phases,
	}
	if len(findings) == 0 {
		return summary
	}
	var cvssTotal float64
	for _, finding := range findings {
		summary.BySeverity[finding.Severity]++
		className := strings.TrimSpace(strings.ToLower(finding.VulnClass))
		if className == "" {
			className = "unknown"
		}
		summary.ByVulnClass[className]++
		if finding.Confirmed {
			summary.ConfirmedFindings++
		}
		if finding.Severity == models.Critical {
			summary.CriticalFindings = append(summary.CriticalFindings, finding)
		}
		if finding.CVSS > 0 {
			cvssTotal += finding.CVSS
		}
	}
	if len(findings) > 0 {
		summary.CVSS = cvssTotal / float64(len(findings))
	}
	sort.SliceStable(findings, func(i int, j int) bool {
		if findings[i].CVSS != findings[j].CVSS {
			return findings[i].CVSS > findings[j].CVSS
		}
		return findings[i].Severity > findings[j].Severity
	})
	limit := 5
	if len(findings) < limit {
		limit = len(findings)
	}
	summary.TopFindings = append(summary.TopFindings, findings[:limit]...)
	return summary
}

func loadChains(path string) []VulnChain {
	if _, err := os.Stat(path); err != nil {
		return []VulnChain{}
	}
	f, err := os.Open(path)
	if err != nil {
		return []VulnChain{}
	}
	defer f.Close()
	chains := make([]VulnChain, 0, 8)
	var current *VulnChain
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "## CHAIN-") {
			if current != nil {
				chains = append(chains, *current)
			}
			name := strings.TrimSpace(strings.TrimPrefix(line, "##"))
			current = &VulnChain{Name: name, Severity: models.Medium}
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "- Severity:") {
			sev := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "- Severity:")))
			current.Severity = models.Severity(sev)
			continue
		}
		if strings.HasPrefix(line, "- Classes:") {
			classes := strings.TrimSpace(strings.TrimPrefix(line, "- Classes:"))
			if classes != "" {
				current.Classes = strings.Split(classes, " + ")
			}
			continue
		}
		if line != "" {
			if current.Description == "" {
				current.Description = line
			} else {
				current.Description += " " + line
			}
		}
	}
	if current != nil {
		chains = append(chains, *current)
	}
	return chains
}

func loadPhaseMap(workspace models.Workspace) (map[int]models.PhaseResult, error) {
	result := make(map[int]models.PhaseResult)
	db, err := models.InitCheckpointDB(workspace.Root)
	if err != nil {
		return result, err
	}
	defer db.Close()
	statuses, err := models.GetAllPhaseStatuses(db)
	if err != nil {
		return result, err
	}
	for phase, status := range statuses {
		result[phase] = models.PhaseResult{Phase: phase, Status: status}
	}
	return result, nil
}

func loadFindings(workspace models.Workspace) ([]models.Finding, error) {
	db, err := models.InitFindingsDB(workspace.Root)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return models.GetFindings(db, models.FindingFilter{})
}

