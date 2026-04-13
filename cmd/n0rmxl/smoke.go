package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	cfgpkg "github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/installer"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	phasespkg "github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases"
	"github.com/spf13/cobra"
)

type smokePreflightReport struct {
	TotalRegisteredTools         int
	ExpectedTools                int
	InstalledTools               int
	MissingTools                 []string
	MissingWordlists             []string
	MissingScripts               []string
	PayloadLibraryPath           string
	PayloadLibraryReady          bool
	PhaseJobCount                int
	MissingPhaseBinaries         []string
	MissingRequiredPhaseBinaries []string
}

func newSmokeCommand() *cobra.Command {
	var targetFlag string
	var phasesFlag string
	var workspaceRoot string
	var installMissing bool
	var strict bool
	var preflightOnly bool
	var minTools int

	cmd := &cobra.Command{
		Use:   "smoke [target]",
		Short: "Run end-to-end readiness checks and launch a manual TUI smoke run",
		Long:  "Smoke validates installer coverage, tool presence, wordlists, payload libraries, and phase tool wiring before launching a full manual TUI run.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := initRuntime(); err != nil {
				return err
			}
			if err := validateEnvironment(); err != nil {
				return err
			}

			target := strings.TrimSpace(targetFlag)
			if len(args) > 0 {
				target = strings.TrimSpace(args[0])
			}
			if target == "" {
				target = "example.com"
			}

			selectedPhases, err := parsePhaseList(phasesFlag)
			if err != nil {
				return err
			}

			cfg, err := cfgpkg.Load()
			if err != nil {
				return err
			}
			if strings.TrimSpace(workspaceRoot) != "" {
				cfg.WorkspaceRoot = strings.TrimSpace(workspaceRoot)
			}

			report, err := runSmokePreflight(cmd.Context(), cfg, target, selectedPhases, installMissing, minTools)
			printSmokeSummary(cmd.OutOrStdout(), report, target, selectedPhases)
			if err != nil {
				if strict {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] smoke warning: %v\n", err)
			}

			if preflightOnly || noTUI {
				fmt.Fprintln(cmd.OutOrStdout(), "[n0rmxl] smoke preflight completed (TUI launch skipped)")
				return nil
			}

			targetModel := models.Target{
				Domain:       target,
				WorkspaceDir: strings.TrimSpace(cfg.WorkspaceRoot),
				Wildcards:    []string{"*." + target},
				Profile:      models.StealthProfile(profile),
			}
			fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] launching manual TUI smoke run target=%s phases=%s\n", target, phasesToSpec(selectedPhases))
			return launchTargetRunTUI(targetModel, selectedPhases)
		},
	}

	cmd.Flags().StringVar(&targetFlag, "target", "", "Target domain for the smoke run (arg overrides flag)")
	cmd.Flags().StringVar(&phasesFlag, "phases", "0,1,2,3,4,5,6,7,8,9", "Comma-separated phase list for smoke run")
	cmd.Flags().StringVar(&workspaceRoot, "workspace-root", "", "Override workspace root for smoke preflight and run")
	cmd.Flags().BoolVar(&installMissing, "install", true, "Attempt installing missing tools and wordlists before validation")
	cmd.Flags().BoolVar(&strict, "strict", true, "Fail smoke command when readiness checks are not clean")
	cmd.Flags().BoolVar(&preflightOnly, "preflight-only", false, "Run readiness checks only and do not launch TUI")
	cmd.Flags().IntVar(&minTools, "min-tools", 100, "Minimum registered installer tool count required for smoke")
	return cmd
}

func runSmokePreflight(ctx context.Context, cfg *cfgpkg.Config, target string, phases []int, installMissing bool, minTools int) (*smokePreflightReport, error) {
	report := &smokePreflightReport{}
	if cfg == nil {
		cfg = cfgpkg.DefaultConfig()
	}

	inst := installer.NewInstaller(cfg)
	inst.RegisterAll()
	report.TotalRegisteredTools = len(inst.Jobs())
	if report.TotalRegisteredTools < minTools {
		return report, fmt.Errorf("installer registered %d tools, below required minimum %d", report.TotalRegisteredTools, minTools)
	}

	if installMissing {
		if err := inst.Run(ctx); err != nil {
			return report, fmt.Errorf("installer run failed during smoke preflight: %w", err)
		}
	}

	status := inst.CheckAll()
	report.ExpectedTools, report.InstalledTools, report.MissingTools = summarizeInstallerStatus(inst.Jobs(), status)
	report.MissingWordlists = findMissingWordlistsForPhases(cfg, phases)
	report.MissingScripts = findMissingScriptDependenciesForPhases(cfg, phases)
	report.PayloadLibraryPath, report.PayloadLibraryReady = installer.PayloadLibraryStatus(cfg)

	phaseJobCount, missingPhaseBinaries, missingRequiredPhaseBinaries, err := collectMissingPhaseBinaries(cfg, target, phases, status)
	report.PhaseJobCount = phaseJobCount
	report.MissingPhaseBinaries = missingPhaseBinaries
	report.MissingRequiredPhaseBinaries = missingRequiredPhaseBinaries
	if err != nil {
		return report, err
	}

	if readinessErr := smokeReadinessError(report); readinessErr != nil {
		return report, readinessErr
	}
	return report, nil
}

func smokeReadinessError(report *smokePreflightReport) error {
	if report == nil {
		return fmt.Errorf("smoke readiness report is nil")
	}
	if len(report.MissingWordlists) > 0 || len(report.MissingScripts) > 0 || len(report.MissingRequiredPhaseBinaries) > 0 || !report.PayloadLibraryReady {
		return fmt.Errorf("smoke readiness incomplete: missing_tools=%d missing_wordlists=%d missing_scripts=%d missing_phase_binaries=%d missing_required_phase_binaries=%d payload_ready=%t", len(report.MissingTools), len(report.MissingWordlists), len(report.MissingScripts), len(report.MissingPhaseBinaries), len(report.MissingRequiredPhaseBinaries), report.PayloadLibraryReady)
	}
	return nil
}

func findMissingWordlistsForPhases(cfg *cfgpkg.Config, phases []int) []string {
	if !requiresWordlistAssets(phases) {
		return []string{}
	}
	if cfg == nil {
		cfg = cfgpkg.DefaultConfig()
	}
	return findMissingWordlists(cfg)
}

func findMissingScriptDependenciesForPhases(cfg *cfgpkg.Config, phases []int) []string {
	if !requiresScriptAssets(phases) {
		return []string{}
	}
	if cfg == nil {
		cfg = cfgpkg.DefaultConfig()
	}
	return findMissingScriptDependencies(cfg)
}

func requiresWordlistAssets(phases []int) bool {
	selected := selectedPhaseSet(phases)
	for _, phase := range []int{2, 4} {
		if _, ok := selected[phase]; ok {
			return true
		}
	}
	return false
}

func requiresScriptAssets(phases []int) bool {
	selected := selectedPhaseSet(phases)
	for _, phase := range []int{3, 4, 5} {
		if _, ok := selected[phase]; ok {
			return true
		}
	}
	return false
}

func selectedPhaseSet(phases []int) map[int]struct{} {
	set := make(map[int]struct{}, len(phases))
	for _, phase := range phases {
		if phase >= 0 && phase <= 9 {
			set[phase] = struct{}{}
		}
	}
	if len(set) == 0 {
		set[0] = struct{}{}
	}
	return set
}

func summarizeInstallerStatus(jobs []*installer.ToolJob, status map[string]bool) (expected int, installed int, missing []string) {
	missing = make([]string, 0, len(jobs))
	for _, job := range jobs {
		if job == nil {
			continue
		}
		if runtime.GOOS != "linux" && job.Category == "system" {
			continue
		}
		expected++
		if status[job.Name] {
			installed++
			continue
		}
		missing = append(missing, job.Name)
	}
	sort.Strings(missing)
	return expected, installed, missing
}

func findMissingWordlists(cfg *cfgpkg.Config) []string {
	paths := []string{
		strings.TrimSpace(cfg.Wordlists.DNSLarge),
		strings.TrimSpace(cfg.Wordlists.DNSMedium),
		strings.TrimSpace(cfg.Wordlists.DNSSmall),
		strings.TrimSpace(cfg.Wordlists.DirLarge),
		strings.TrimSpace(cfg.Wordlists.DirMedium),
		strings.TrimSpace(cfg.Wordlists.FilesLarge),
		strings.TrimSpace(cfg.Wordlists.Params),
		strings.TrimSpace(cfg.Wordlists.LFI),
		strings.TrimSpace(cfg.Wordlists.XSS),
		strings.TrimSpace(cfg.Wordlists.Resolvers),
		strings.TrimSpace(cfg.Wordlists.APIRoutes),
	}

	resolverTrusted := ""
	if strings.TrimSpace(cfg.Wordlists.Resolvers) != "" {
		resolverTrusted = filepath.Join(filepath.Dir(cfg.Wordlists.Resolvers), "resolvers-trusted.txt")
		paths = append(paths, resolverTrusted)
	}

	missing := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		if !fileExistsPath(p) {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	return missing
}

func findMissingScriptDependencies(cfg *cfgpkg.Config) []string {
	base := strings.TrimSpace(cfg.Tools.GitClones)
	if base == "" {
		base = filepath.Join(defaultDataDir(), "tools")
	}
	missing := make([]string, 0, 6)
	linkFinderUpper := filepath.Join(base, "LinkFinder", "linkfinder.py")
	linkFinderLower := filepath.Join(base, "linkfinder", "linkfinder.py")
	if !fileExistsPath(linkFinderUpper) && !fileExistsPath(linkFinderLower) {
		missing = append(missing, linkFinderUpper)
	}

	for _, path := range []string{
		filepath.Join(base, "SecretFinder", "SecretFinder.py"),
		filepath.Join(base, "Corsy", "corsy.py"),
		filepath.Join(base, "smuggler", "smuggler.py"),
		filepath.Join(base, "jwt_tool", "jwt_tool.py"),
	} {
		if !fileExistsPath(path) {
			missing = append(missing, path)
		}
	}
	sort.Strings(missing)
	return missing
}

func collectMissingPhaseBinaries(cfg *cfgpkg.Config, target string, phases []int, installStatus map[string]bool) (int, []string, []string, error) {
	if cfg == nil {
		cfg = cfgpkg.DefaultConfig()
	}
	root := strings.TrimSpace(cfg.WorkspaceRoot)
	if root == "" {
		root = defaultWorkspaceRoot()
	}

	targetModel := models.Target{
		Domain:       strings.TrimSpace(target),
		WorkspaceDir: root,
		Wildcards:    []string{"*." + strings.TrimSpace(target)},
		Profile:      models.StealthProfile(profile),
	}
	workspace, err := engine.InitWorkspace(root, &targetModel)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("smoke workspace init failed: %w", err)
	}
	targetModel.WorkspaceDir = workspace.Root

	runCfgValue := cfgpkg.NewRunConfig(targetModel.Profile, cfg)
	runCfg := &runCfgValue
	runCfg.Scope = &cfgpkg.Scope{
		Wildcards:  append([]string{}, targetModel.Wildcards...),
		Explicit:   append([]string{}, targetModel.Explicit...),
		IPRanges:   append([]string{}, targetModel.IPRanges...),
		OutOfScope: append([]string{}, targetModel.OutOfScope...),
	}

	phaseJobs := 0
	missingSet := make(map[string]struct{})
	requiredMissingSet := make(map[string]struct{})
	for _, phase := range phases {
		jobs, err := phasespkg.JobsForPhase(phase, &targetModel, workspace, runCfg)
		if err != nil {
			return phaseJobs, nil, nil, fmt.Errorf("smoke failed building phase %d jobs: %w", phase, err)
		}
		phaseJobs += len(jobs)
		for _, job := range jobs {
			if job == nil {
				continue
			}
			binary := strings.TrimSpace(job.Binary)
			if binary == "" {
				continue
			}
			if isBinarySatisfied(binary, strings.TrimSpace(job.ToolName), installStatus) {
				continue
			}
			key := fmt.Sprintf("phase %d tool=%s binary=%s", phase, strings.TrimSpace(job.ToolName), binary)
			missingSet[key] = struct{}{}
			if job.Required {
				requiredMissingSet[key] = struct{}{}
			}
		}
	}

	missing := make([]string, 0, len(missingSet))
	for item := range missingSet {
		missing = append(missing, item)
	}
	requiredMissing := make([]string, 0, len(requiredMissingSet))
	for item := range requiredMissingSet {
		requiredMissing = append(requiredMissing, item)
	}
	sort.Strings(missing)
	sort.Strings(requiredMissing)
	return phaseJobs, missing, requiredMissing, nil
}

func isBinarySatisfied(binary string, tool string, installStatus map[string]bool) bool {
	if strings.TrimSpace(binary) == "" {
		return true
	}
	if _, err := exec.LookPath(binary); err == nil {
		return true
	}
	if installStatus[strings.TrimSpace(binary)] {
		return true
	}
	if strings.TrimSpace(tool) != "" && installStatus[strings.TrimSpace(tool)] {
		return true
	}
	aliases := map[string][]string{
		"kr":      {"kiterunner"},
		"python":  {"python3", "py"},
		"python3": {"python", "py"},
		"aws":     {"awscli"},
	}
	for _, alias := range aliases[strings.TrimSpace(binary)] {
		if installStatus[alias] {
			return true
		}
		if _, err := exec.LookPath(alias); err == nil {
			return true
		}
	}
	return false
}

func printSmokeSummary(out io.Writer, report *smokePreflightReport, target string, phases []int) {
	if report == nil {
		return
	}
	if out == nil {
		out = os.Stdout
	}

	fmt.Fprintf(out, "[n0rmxl] smoke target: %s\n", target)
	fmt.Fprintf(out, "[n0rmxl] smoke phases: %s\n", phasesToSpec(phases))
	fmt.Fprintf(out, "[n0rmxl] installer tools: registered=%d expected=%d installed=%d missing=%d\n", report.TotalRegisteredTools, report.ExpectedTools, report.InstalledTools, len(report.MissingTools))
	fmt.Fprintf(out, "[n0rmxl] phase jobs built: %d missing binaries: %d\n", report.PhaseJobCount, len(report.MissingPhaseBinaries))
	fmt.Fprintf(out, "[n0rmxl] payload library: %s ready=%t\n", report.PayloadLibraryPath, report.PayloadLibraryReady)
	fmt.Fprintf(out, "[n0rmxl] missing wordlists: %d missing scripts: %d\n", len(report.MissingWordlists), len(report.MissingScripts))

	printLimitedList(out, "missing installer tools", report.MissingTools, 20)
	printLimitedList(out, "missing phase binaries", report.MissingPhaseBinaries, 20)
	printLimitedList(out, "missing wordlists", report.MissingWordlists, 20)
	printLimitedList(out, "missing script dependencies", report.MissingScripts, 20)
}

func printLimitedList(out io.Writer, title string, items []string, limit int) {
	if len(items) == 0 {
		return
	}
	if out == nil {
		out = os.Stdout
	}
	if limit < 1 {
		limit = 1
	}
	fmt.Fprintf(out, "[n0rmxl] %s:\n", title)
	for idx, item := range items {
		if idx >= limit {
			fmt.Fprintf(out, "  ... and %d more\n", len(items)-limit)
			break
		}
		fmt.Fprintf(out, "  - %s\n", item)
	}
}

func fileExistsPath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

