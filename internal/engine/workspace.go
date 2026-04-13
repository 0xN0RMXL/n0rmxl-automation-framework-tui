package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

func InitWorkspace(rootDir string, target *models.Target) (models.Workspace, error) {
	if target == nil {
		return models.Workspace{}, fmt.Errorf("target is required")
	}
	if strings.TrimSpace(target.Domain) == "" {
		return models.Workspace{}, fmt.Errorf("target domain is required")
	}

	rootDir = expandHome(rootDir)
	if strings.TrimSpace(rootDir) == "" {
		rootDir = filepath.Join(expandHome("~"), "bounty")
	}

	workspace := models.NewWorkspace(rootDir, target.Domain)
	if err := workspace.EnsureAll(); err != nil {
		return models.Workspace{}, err
	}

	scope := config.Scope{
		Wildcards:  target.Wildcards,
		Explicit:   target.Explicit,
		IPRanges:   target.IPRanges,
		OutOfScope: target.OutOfScope,
	}
	if err := writeScopeFile(filepath.Join(workspace.Root, "scope.txt"), scope); err != nil {
		return models.Workspace{}, err
	}

	cfg := config.DefaultConfig()
	cfg.WorkspaceRoot = rootDir
	if err := cfg.Save(); err != nil {
		return models.Workspace{}, err
	}

	checkpointDB, err := models.InitCheckpointDB(workspace.Root)
	if err != nil {
		return models.Workspace{}, err
	}
	_ = checkpointDB.Close()

	findingsDB, err := models.InitFindingsDB(workspace.Root)
	if err != nil {
		return models.Workspace{}, err
	}
	_ = findingsDB.Close()

	return workspace, nil
}

func ValidateWorkspace(workspace models.Workspace) []string {
	issues := make([]string, 0, 8)

	requiredDirs := []string{
		workspace.Hidden,
		workspace.Recon,
		workspace.Scans,
		workspace.Reports,
		workspace.Loot,
		workspace.Screenshots,
	}
	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); err != nil {
			issues = append(issues, fmt.Sprintf("missing directory: %s", dir))
		}
	}

	requiredFiles := []string{
		workspace.ConfigFile,
		workspace.CheckpointDB,
		workspace.FindingsDB,
		filepath.Join(workspace.Root, "scope.txt"),
	}
	for _, file := range requiredFiles {
		if _, err := os.Stat(file); err != nil {
			issues = append(issues, fmt.Sprintf("missing file: %s", file))
		}
	}

	return issues
}

func WorkspaceExists(rootDir string, domain string) bool {
	if strings.TrimSpace(domain) == "" {
		return false
	}
	rootDir = expandHome(rootDir)
	ws := models.NewWorkspace(rootDir, domain)
	if _, err := os.Stat(ws.Hidden); err != nil {
		return false
	}
	return true
}

func ListWorkspaces(rootDir string) ([]models.Target, error) {
	rootDir = expandHome(rootDir)
	if rootDir == "" {
		rootDir = filepath.Join(expandHome("~"), "bounty")
	}
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []models.Target{}, nil
		}
		return nil, err
	}

	targets := make([]models.Target, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domain := entry.Name()
		workspace := models.NewWorkspace(rootDir, domain)
		if _, err := os.Stat(filepath.Join(workspace.Hidden, "config.yaml")); err != nil {
			continue
		}
		target := models.Target{
			Domain:       domain,
			WorkspaceDir: workspace.Root,
		}
		targets = append(targets, target)
	}

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Domain < targets[j].Domain
	})
	return targets, nil
}

func writeScopeFile(path string, scope config.Scope) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sections := []struct {
		title string
		rows  []string
	}{
		{title: "# Wildcards", rows: scope.Wildcards},
		{title: "# Explicit", rows: scope.Explicit},
		{title: "# CIDRs", rows: scope.IPRanges},
		{title: "# Out of Scope", rows: scope.OutOfScope},
	}
	for _, section := range sections {
		if _, err := f.WriteString(section.title + "\n"); err != nil {
			return err
		}
		for _, row := range section.rows {
			if _, err := f.WriteString(strings.TrimSpace(row) + "\n"); err != nil {
				return err
			}
		}
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}
	return nil
}
func expandHome(path string) string {
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

