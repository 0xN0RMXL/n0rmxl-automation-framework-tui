package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	cfgpkg "github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/installer"
	notifypkg "github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/integrations/notify"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	phasespkg "github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	version     = "dev"
	commit      = "none"
	date        = "unknown"
	configPath  string
	profile     string
	noTUI       bool
	vaultUnlock bool
)

func main() {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "n0rmxl",
		Short: "N0RMXL Automation Framework TUI",
		Long:  "N0RMXL is a modular, phase-based bug bounty automation framework for authorized testing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := initRuntime(); err != nil {
				return err
			}
			return launchTUI(cmd)
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if profile != "slow" && profile != "normal" && profile != "aggressive" {
				return fmt.Errorf("invalid profile %q: must be slow|normal|aggressive", profile)
			}
			if strings.TrimSpace(configPath) != "" {
				if err := os.Setenv("N0RMXL_CONFIG", configPath); err != nil {
					return fmt.Errorf("failed to apply --config override: %w", err)
				}
			}
			if err := initLogger(); err != nil {
				return err
			}
			if noTUI {
				printBanner(cmd)
			}
			return nil
		},
	}

	root.PersistentFlags().StringVar(&configPath, "config", defaultConfigPath(), "Path to config file")
	root.PersistentFlags().StringVar(&profile, "profile", "normal", "Stealth profile: slow|normal|aggressive")
	root.PersistentFlags().BoolVar(&noTUI, "no-tui", false, "Run in non-TUI mode")

	root.AddCommand(newInstallCommand())
	root.AddCommand(newSmokeCommand())
	root.AddCommand(newRunCommand())
	root.AddCommand(newCampaignCommand())
	root.AddCommand(newReportCommand())
	root.AddCommand(newVaultCommand())
	root.AddCommand(newVersionCommand())
	return root
}

func newInstallCommand() *cobra.Command {
	var checkOnly bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install and verify toolchain dependencies",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := initRuntime(); err != nil {
				return err
			}
			cfg, err := cfgpkg.Load()
			if err != nil {
				return err
			}
			inst := installer.NewInstaller(cfg)
			inst.RegisterAll()

			if checkOnly {
				status := inst.CheckAll()
				names := make([]string, 0, len(status))
				for name := range status {
					names = append(names, name)
				}
				sort.Strings(names)
				installed := 0
				for _, name := range names {
					if status[name] {
						installed++
						fmt.Fprintf(cmd.OutOrStdout(), "[ok] %s\n", name)
						continue
					}
					fmt.Fprintf(cmd.OutOrStdout(), "[missing] %s\n", name)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] tool check: %d/%d installed\n", installed, len(names))
				log.Info().Str("command", "install").Bool("check", true).Msg("installer check mode invoked")
				return nil
			}

			if err := inst.Run(context.Background()); err != nil {
				return err
			}
			installed, total := inst.InstalledCount()
			if noTUI {
				fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] installer finished: %d/%d\n", installed, total)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] installer backend completed (%d/%d). full installer TUI screen is next.\n", installed, total)
			}
			log.Info().Str("command", "install").Msg("installer command invoked")
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false, "Check installed tools without performing installs")
	return cmd
}

func newRunCommand() *cobra.Command {
	var phasesFlag string

	cmd := &cobra.Command{
		Use:   "run <target>",
		Short: "Run phase pipeline against a target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := initRuntime(); err != nil {
				return err
			}
			if err := validateEnvironment(); err != nil {
				return err
			}
			target := strings.TrimSpace(args[0])
			if target == "" {
				return errors.New("target cannot be empty")
			}
			selectedPhases, err := parsePhaseList(phasesFlag)
			if err != nil {
				return err
			}
			phaseSpec := phasesToSpec(selectedPhases)
			log.Info().Str("target", target).Str("profile", profile).Str("phases", phaseSpec).Bool("no_tui", noTUI).Msg("run command invoked")
			if noTUI {
				return runPhasesNonTUI(cmd.Context(), cmd, target, phaseSpec, "")
			}
			cfg, err := cfgpkg.Load()
			if err != nil {
				return err
			}
			targetModel := models.Target{
				Domain:       target,
				WorkspaceDir: strings.TrimSpace(cfg.WorkspaceRoot),
				Wildcards:    []string{"*." + target},
				Profile:      models.StealthProfile(profile),
			}
			return launchTargetRunTUI(targetModel, selectedPhases)
		},
	}
	cmd.Flags().StringVar(&phasesFlag, "phases", "0", "Comma-separated phase list, e.g. 0,1,2")
	return cmd
}

func runPhasesNonTUI(ctx context.Context, cmd *cobra.Command, domain string, phaseSpec string, workspaceRootOverride string) error {
	cfg, err := cfgpkg.Load()
	if err != nil {
		return err
	}
	if cfg.Notify.Telegram.Enabled || cfg.Notify.Slack.Enabled || cfg.Notify.Discord.Enabled {
		notifier := notifypkg.NewNotifier(&cfg.Notify, nil)
		models.SetFindingSavedHook(func(f models.Finding) {
			if sendErr := notifier.Send(f); sendErr != nil {
				log.Warn().Err(sendErr).Str("finding", f.ID).Str("severity", string(f.Severity)).Msg("notification dispatch failed")
			}
		})
		defer models.SetFindingSavedHook(nil)
	}
	selectedPhases, err := parsePhaseList(phaseSpec)
	if err != nil {
		return err
	}

	workspaceRoot := strings.TrimSpace(workspaceRootOverride)
	if workspaceRoot == "" {
		workspaceRoot = strings.TrimSpace(cfg.WorkspaceRoot)
	}

	target := &models.Target{
		Domain:       strings.TrimSpace(domain),
		WorkspaceDir: workspaceRoot,
		Wildcards:    []string{"*." + strings.TrimSpace(domain)},
		Profile:      models.StealthProfile(profile),
	}
	workspace, err := engine.InitWorkspace(workspaceRoot, target)
	if err != nil {
		return err
	}
	target.WorkspaceDir = workspace.Root

	runCfgValue := cfgpkg.NewRunConfig(target.Profile, cfg)
	runCfg := &runCfgValue
	runCfg.Scope = &cfgpkg.Scope{
		Wildcards:  append([]string{}, target.Wildcards...),
		Explicit:   append([]string{}, target.Explicit...),
		IPRanges:   append([]string{}, target.IPRanges...),
		OutOfScope: append([]string{}, target.OutOfScope...),
	}

	checkpoint, err := engine.NewCheckpoint(workspace.Root)
	if err != nil {
		return err
	}
	defer checkpoint.Close()

	fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] workspace: %s\n", workspace.Root)
	fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] phases: %v\n", selectedPhases)

	for _, phase := range selectedPhases {
		jobs, err := phasespkg.JobsForPhase(phase, target, workspace, runCfg)
		if err != nil {
			return err
		}
		runner := engine.NewPhaseRunner(phase, runCfg, checkpoint)
		for _, job := range jobs {
			runner.AddJob(job)
		}

		done := make(chan struct{})
		go func() {
			for update := range runner.Progress {
				jobName := "unknown"
				if update.Job != nil {
					jobName = update.Job.ToolName
				}
				switch update.Event {
				case "start":
					fmt.Fprintf(cmd.OutOrStdout(), "[RUN][phase %d] %s\n", phase, jobName)
				case "done":
					fmt.Fprintf(cmd.OutOrStdout(), "[DONE][phase %d] %s\n", phase, jobName)
				case "skip":
					fmt.Fprintf(cmd.OutOrStdout(), "[SKIP][phase %d] %s %s\n", phase, jobName, update.Line)
				case "error":
					fmt.Fprintf(cmd.OutOrStdout(), "[ERR][phase %d] %s %s\n", phase, jobName, update.Line)
				case "line":
					if strings.TrimSpace(update.Line) != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "[LOG][phase %d] %s: %s\n", phase, jobName, update.Line)
					}
				}
			}
			close(done)
		}()

		started := time.Now()
		if err := runner.Run(ctx); err != nil {
			<-done
			return fmt.Errorf("phase %d failed: %w", phase, err)
		}
		<-done
		fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] phase %d completed in %s\n", phase, time.Since(started).Truncate(time.Second))
	}

	fmt.Fprintln(cmd.OutOrStdout(), "[n0rmxl] selected phases completed")
	return nil
}

func parsePhaseList(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		spec = "0"
	}
	parts := strings.Split(spec, ",")
	set := make(map[int]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		phase, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid phase %q", part)
		}
		if phase < 0 || phase > 9 {
			return nil, fmt.Errorf("phase %d out of range (0-9)", phase)
		}
		set[phase] = struct{}{}
	}
	if len(set) == 0 {
		set[0] = struct{}{}
	}
	out := make([]int, 0, len(set))
	for phase := range set {
		out = append(out, phase)
	}
	sort.Ints(out)
	return out, nil
}

func defaultPhaseSpec(spec string) string {
	if strings.TrimSpace(spec) == "" {
		return "0"
	}
	return spec
}

func phasesToSpec(phases []int) string {
	if len(phases) == 0 {
		return "0"
	}
	parts := make([]string, 0, len(phases))
	for _, phase := range phases {
		parts = append(parts, strconv.Itoa(phase))
	}
	return strings.Join(parts, ",")
}

func newCampaignCommand() *cobra.Command {
	var workspaceRoot string
	var runAll bool
	var phasesFlag string
	var parallel int
	var stateFile string
	var resume bool
	var retryFailed bool
	var maxTargets int
	var showState bool
	var clearState bool
	cmd := &cobra.Command{
		Use:   "campaign",
		Short: "Launch campaign manager",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := initRuntime(); err != nil {
				return err
			}
			cfg, err := cfgpkg.Load()
			if err != nil {
				return err
			}
			root := strings.TrimSpace(workspaceRoot)
			if root == "" {
				root = strings.TrimSpace(cfg.WorkspaceRoot)
			}

			statePath := strings.TrimSpace(stateFile)
			if statePath == "" {
				statePath = filepath.Join(defaultDataDir(), "campaign_state.json")
			}

			if clearState {
				if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("failed to clear campaign state %s: %w", statePath, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] campaign state cleared: %s\n", statePath)
			}

			loadedState, loadStateErr := loadCampaignRunState(statePath)
			if loadStateErr != nil && !errors.Is(loadStateErr, os.ErrNotExist) {
				fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] warning: unable to read campaign state (%v)\n", loadStateErr)
			}
			summaries, err := collectCampaignSummaries(root)
			if err != nil {
				return err
			}
			summaries = applyCampaignRunStateToSummaries(summaries, loadedState)
			fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] campaign workspace: %s\n", root)
			if showState {
				if loadedState == nil {
					fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] campaign state: %s (not found)\n", statePath)
				} else {
					phaseSpec, updatedAt, pending, succeeded, failed, missing := summarizeCampaignRunState(loadedState)
					updated := "n/a"
					if !updatedAt.IsZero() {
						updated = updatedAt.Local().Format("2006-01-02 15:04")
					}
					fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] campaign state: %s\n", statePath)
					fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] state summary: phase=%s updated=%s queued=%d succeeded=%d failed=%d missing=%d\n", defaultTextValue(phaseSpec, "n/a"), updated, pending, succeeded, failed, missing)
				}
			}
			if len(summaries) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "[n0rmxl] no target workspaces found")
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), "TARGET                  PHASE     STATUS    RUN        FINDINGS   CRIT  HIGH  UPDATED")
			for _, summary := range summaries {
				updated := "n/a"
				if !summary.UpdatedAt.IsZero() {
					updated = summary.UpdatedAt.Local().Format("2006-01-02 15:04")
				}
				runStatus := defaultTextValue(summary.RunStatus, "n/a")
				fmt.Fprintf(cmd.OutOrStdout(), "%-22s %-9s %-8s %-10s %8d %6d %5d  %s\n",
					summary.Target,
					summary.PhaseProgress,
					string(summary.Status),
					runStatus,
					summary.TotalFindings,
					summary.Critical,
					summary.High,
					updated,
				)
			}

			if !runAll {
				if resume || retryFailed || maxTargets > 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "[n0rmxl] resume and batching flags apply only with --run-all")
				}
				log.Info().Str("command", "campaign").Int("targets", len(summaries)).Msg("campaign command listed targets")
				return nil
			}

			selectedPhases, err := parsePhaseList(phasesFlag)
			if err != nil {
				return err
			}
			phaseParts := make([]string, len(selectedPhases))
			for i, phase := range selectedPhases {
				phaseParts[i] = strconv.Itoa(phase)
			}
			phaseSpec := strings.Join(phaseParts, ",")

			var state *campaignRunState
			if resume {
				state = loadedState
				if state == nil {
					loaded, loadErr := loadCampaignRunState(statePath)
					if loadErr != nil {
						return loadErr
					}
					state = loaded
				}
				if strings.TrimSpace(state.PhaseSpec) != "" && !cmd.Flags().Changed("phases") {
					phaseSpec = strings.TrimSpace(state.PhaseSpec)
				}
				if strings.TrimSpace(state.WorkspaceRoot) != "" && state.WorkspaceRoot != root {
					fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] resume state workspace differs (%s), using current workspace root (%s)\n", state.WorkspaceRoot, root)
				}
			} else {
				state = newCampaignRunState(root, phaseSpec)
			}

			state.WorkspaceRoot = root
			state.PhaseSpec = phaseSpec
			state.UpdatedAt = time.Now().UTC()
			if state.Targets == nil {
				state.Targets = make(map[string]campaignTargetState, len(summaries))
			}

			knownTargets := make(map[string]struct{}, len(summaries))
			for _, summary := range summaries {
				knownTargets[summary.Target] = struct{}{}
				if _, exists := state.Targets[summary.Target]; !exists {
					state.Targets[summary.Target] = campaignTargetState{Status: campaignTargetPending, UpdatedAt: time.Now().UTC()}
				}
			}
			for target, targetState := range state.Targets {
				if _, found := knownTargets[target]; found {
					continue
				}
				targetState.Status = campaignTargetMissing
				targetState.UpdatedAt = time.Now().UTC()
				state.Targets[target] = targetState
			}

			queued := make([]campaignSummary, 0, len(summaries))
			skippedSucceeded := 0
			skippedFailed := 0
			for _, summary := range summaries {
				targetState := state.Targets[summary.Target]
				if resume {
					if targetState.Status == campaignTargetSucceeded {
						skippedSucceeded++
						continue
					}
					if targetState.Status == campaignTargetFailed && !retryFailed {
						skippedFailed++
						continue
					}
				}
				targetState.Status = campaignTargetPending
				targetState.LastError = ""
				targetState.UpdatedAt = time.Now().UTC()
				state.Targets[summary.Target] = targetState
				queued = append(queued, summary)
			}

			if maxTargets > 0 && len(queued) > maxTargets {
				queued = queued[:maxTargets]
			}

			if err := saveCampaignRunState(statePath, state); err != nil {
				return err
			}

			if resume {
				fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] resumed campaign state from %s\n", statePath)
				fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] resume filters: skipped succeeded=%d skipped failed=%d retry_failed=%t\n", skippedSucceeded, skippedFailed, retryFailed)
			}

			if len(queued) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "[n0rmxl] no queued targets to run after resume filters")
				return nil
			}

			workers := parallel
			if workers < 1 {
				workers = 1
			}
			notifyEnabled := cfg.Notify.Telegram.Enabled || cfg.Notify.Slack.Enabled || cfg.Notify.Discord.Enabled
			if notifyEnabled && workers > 1 {
				workers = 1
				fmt.Fprintln(cmd.OutOrStdout(), "[n0rmxl] notifications enabled; forcing --parallel=1 for safe hook dispatch")
			}

			fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] running selected phases (%s) for %d queued targets (parallel=%d, discovered=%d)\n", phaseSpec, len(queued), workers, len(summaries))

			type campaignRunResult struct {
				target   string
				duration time.Duration
				output   string
				err      error
			}

			jobs := make(chan campaignSummary)
			results := make(chan campaignRunResult, len(queued))
			var wg sync.WaitGroup

			for worker := 0; worker < workers; worker++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for summary := range jobs {
						started := time.Now()
						var out bytes.Buffer
						runCmd := &cobra.Command{}
						runCmd.SetOut(&out)
						runCmd.SetErr(&out)
						err := runPhasesNonTUI(cmd.Context(), runCmd, summary.Target, phaseSpec, root)
						results <- campaignRunResult{
							target:   summary.Target,
							duration: time.Since(started),
							output:   out.String(),
							err:      err,
						}
					}
				}()
			}

			go func() {
				for _, summary := range queued {
					jobs <- summary
				}
				close(jobs)
				wg.Wait()
				close(results)
			}()

			failed := 0
			succeeded := 0
			for result := range results {
				fmt.Fprintf(cmd.OutOrStdout(), "\n--- target: %s (%s) ---\n", result.target, result.duration.Truncate(time.Second))
				if strings.TrimSpace(result.output) != "" {
					fmt.Fprint(cmd.OutOrStdout(), result.output)
					if !strings.HasSuffix(result.output, "\n") {
						fmt.Fprintln(cmd.OutOrStdout())
					}
				}

				targetState := state.Targets[result.target]
				targetState.UpdatedAt = time.Now().UTC()
				targetState.DurationSeconds = int64(result.duration.Seconds())
				if result.err != nil {
					failed++
					targetState.Status = campaignTargetFailed
					targetState.LastError = result.err.Error()
					state.Targets[result.target] = targetState
					state.UpdatedAt = time.Now().UTC()
					if saveErr := saveCampaignRunState(statePath, state); saveErr != nil {
						fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] warning: failed to save campaign state: %v\n", saveErr)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] target failed: %s (%v)\n", result.target, result.err)
					continue
				}
				succeeded++
				targetState.Status = campaignTargetSucceeded
				targetState.LastError = ""
				state.Targets[result.target] = targetState
				state.UpdatedAt = time.Now().UTC()
				if saveErr := saveCampaignRunState(statePath, state); saveErr != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] warning: failed to save campaign state: %v\n", saveErr)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] target completed: %s\n", result.target)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] campaign run complete: %d succeeded, %d failed\n", succeeded, failed)
			fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] campaign state saved: %s\n", statePath)
			log.Info().Str("command", "campaign").Int("targets", len(summaries)).Int("queued", len(queued)).Int("succeeded", succeeded).Int("failed", failed).Str("phases", phaseSpec).Int("parallel", workers).Bool("resume", resume).Str("state_file", statePath).Msg("campaign command executed target runs")
			if failed > 0 {
				return fmt.Errorf("campaign run completed with failures: %d/%d queued targets failed", failed, len(queued))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&workspaceRoot, "workspace-root", "", "Override workspace root for campaign discovery")
	cmd.Flags().BoolVar(&runAll, "run-all", false, "Run selected phases against all discovered targets")
	cmd.Flags().StringVar(&phasesFlag, "phases", "0", "Comma-separated phase list for --run-all, e.g. 0,1,2")
	cmd.Flags().IntVar(&parallel, "parallel", 2, "Number of concurrent target runs for --run-all")
	cmd.Flags().StringVar(&stateFile, "state-file", "", "Campaign run state file (default: ~/.local/share/n0rmxl/campaign_state.json)")
	cmd.Flags().BoolVar(&resume, "resume", false, "Resume queued targets from campaign state and skip succeeded targets")
	cmd.Flags().BoolVar(&retryFailed, "retry-failed", false, "With --resume, retry targets that previously failed")
	cmd.Flags().IntVar(&maxTargets, "max-targets", 0, "Limit queued targets for this run (0 = all queued targets)")
	cmd.Flags().BoolVar(&showState, "show-state", false, "Show campaign state summary before listing or running")
	cmd.Flags().BoolVar(&clearState, "clear-state", false, "Delete campaign state file before continuing")
	return cmd
}

func newReportCommand() *cobra.Command {
	var openArtifacts bool
	cmd := &cobra.Command{
		Use:   "report <target>",
		Short: "Regenerate reports for a target workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := initRuntime(); err != nil {
				return err
			}
			target := strings.TrimSpace(args[0])
			if target == "" {
				return errors.New("target cannot be empty")
			}
			if err := runPhasesNonTUI(cmd.Context(), cmd, target, "9", ""); err != nil {
				return err
			}
			cfg, err := cfgpkg.Load()
			if err != nil {
				return err
			}
			ws := models.NewWorkspace(cfg.WorkspaceRoot, target)
			artifacts := []string{
				filepath.Join(ws.Reports, "report.md"),
				filepath.Join(ws.Reports, "report.html"),
				filepath.Join(ws.Reports, "report.pdf"),
				filepath.Join(ws.Reports, "executive_summary.md"),
			}
			fmt.Fprintln(cmd.OutOrStdout(), "[n0rmxl] report artifacts:")
			for _, artifact := range artifacts {
				status := "missing"
				if fileExists(artifact) {
					status = "ready"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "- [%s] %s\n", status, artifact)
			}
			if openArtifacts {
				for _, candidate := range []string{
					filepath.Join(ws.Reports, "report.pdf"),
					filepath.Join(ws.Reports, "report.html"),
					filepath.Join(ws.Reports, "report.md"),
				} {
					if !fileExists(candidate) {
						continue
					}
					if err := openPath(candidate); err == nil {
						fmt.Fprintf(cmd.OutOrStdout(), "[n0rmxl] opened %s\n", candidate)
						break
					}
				}
			}
			log.Info().Str("target", target).Msg("report command completed")
			return nil
		},
	}
	cmd.Flags().BoolVar(&openArtifacts, "open", false, "Open the best available generated report artifact")
	return cmd
}

func newVaultCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage encrypted API key vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := initRuntime(); err != nil {
				return err
			}
			cfg, err := cfgpkg.Load()
			if err != nil {
				return err
			}
			vault := cfgpkg.NewVault(cfg.VaultPath)
			password, err := cfgpkg.PromptPassword("Vault passphrase")
			if err != nil {
				return fmt.Errorf("failed to read vault passphrase: %w", err)
			}
			if _, err := os.Stat(cfg.VaultPath); errors.Is(err, os.ErrNotExist) {
				if err := vault.Create(password); err != nil {
					return err
				}
				if err := vault.Unlock(password); err != nil {
					return err
				}
			} else if err := vault.Unlock(password); err != nil {
				return err
			}
			defer vault.Lock()

			if vaultUnlock {
				if err := vault.InjectToEnv(); err != nil {
					return err
				}
				if err := vault.InjectToConfig(cfg); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "[n0rmxl] vault unlocked and environment variables injected")
				return nil
			}
			keys := vault.List()
			fmt.Fprintln(cmd.OutOrStdout(), "[n0rmxl] vault unlocked")
			if len(keys) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "stored keys: (none)")
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), "stored keys:")
			for _, key := range keys {
				fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", key)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&vaultUnlock, "unlock", false, "Unlock vault and inject secrets to environment")
	return cmd
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "n0rmxl %s\ncommit: %s\nbuilt: %s\n", version, commit, date)
		},
	}
}

func initRuntime() error {
	paths := []string{defaultConfigDir(), defaultDataDir(), defaultWorkspaceRoot()}
	for _, p := range paths {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return fmt.Errorf("failed to create runtime directory %s: %w", p, err)
		}
	}
	cfg, err := cfgpkg.Load()
	if err != nil {
		return err
	}
	for _, warning := range cfg.Validate() {
		log.Warn().Str("warning", warning).Msg("config validation")
	}
	return nil
}

func validateEnvironment() error {
	if runtime.GOOS == "windows" {
		log.Warn().Msg("N0RMXL is Linux-first; current OS is Windows")
	}
	return nil
}

func launchTUI(cmd *cobra.Command) error {
	if noTUI {
		fmt.Fprintln(cmd.OutOrStdout(), "[n0rmxl] no subcommand provided; non-TUI mode selected")
		return nil
	}
	program := tea.NewProgram(tui.NewAppModel(), tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		return fmt.Errorf("failed to launch TUI: %w", err)
	}
	return nil
}

func launchTargetRunTUI(target models.Target, phases []int) error {
	if target.Profile == "" {
		target.Profile = models.Normal
	}
	program := tea.NewProgram(tui.NewAppModelForRun(target, phases), tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		return fmt.Errorf("failed to launch target run TUI: %w", err)
	}
	return nil
}

func initLogger() error {
	if err := os.MkdirAll(defaultDataDir(), 0o700); err != nil {
		return fmt.Errorf("failed to create data dir: %w", err)
	}
	logPath := filepath.Join(defaultDataDir(), "n0rmxl.log")
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", logPath, err)
	}

	zerolog.TimeFieldFormat = time.RFC3339
	logger := zerolog.New(file).With().Timestamp().Str("app", "n0rmxl").Logger()
	log.Logger = logger
	return nil
}

func printBanner(cmd *cobra.Command) {
	fmt.Fprintln(cmd.OutOrStdout(), "N0RMXL Automation Framework TUI")
	fmt.Fprintln(cmd.OutOrStdout(), "Authorized bug bounty automation workflows")
}

func defaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".config", "n0rmxl")
	}
	return filepath.Join(home, ".config", "n0rmxl")
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".local", "share", "n0rmxl")
	}
	return filepath.Join(home, ".local", "share", "n0rmxl")
}

func defaultConfigPath() string {
	return filepath.Join(defaultConfigDir(), "config.yaml")
}

func defaultWorkspaceRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "bounty")
	}
	return filepath.Join(home, "bounty")
}

type campaignSummary struct {
	Target        string
	PhaseProgress string
	Status        models.PhaseStatus
	RunStatus     string
	Critical      int
	High          int
	TotalFindings int
	UpdatedAt     time.Time
}

func defaultTextValue(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

type campaignTargetStatus string

const (
	campaignTargetPending   campaignTargetStatus = "pending"
	campaignTargetSucceeded campaignTargetStatus = "succeeded"
	campaignTargetFailed    campaignTargetStatus = "failed"
	campaignTargetMissing   campaignTargetStatus = "missing"
)

type campaignTargetState struct {
	Status          campaignTargetStatus `json:"status"`
	LastError       string               `json:"last_error,omitempty"`
	UpdatedAt       time.Time            `json:"updated_at"`
	DurationSeconds int64                `json:"duration_seconds,omitempty"`
}

type campaignRunState struct {
	ID            string                         `json:"id"`
	WorkspaceRoot string                         `json:"workspace_root"`
	PhaseSpec     string                         `json:"phase_spec"`
	StartedAt     time.Time                      `json:"started_at"`
	UpdatedAt     time.Time                      `json:"updated_at"`
	Targets       map[string]campaignTargetState `json:"targets"`
}

func newCampaignRunState(workspaceRoot string, phaseSpec string) *campaignRunState {
	now := time.Now().UTC()
	return &campaignRunState{
		ID:            fmt.Sprintf("campaign-%d", now.Unix()),
		WorkspaceRoot: strings.TrimSpace(workspaceRoot),
		PhaseSpec:     strings.TrimSpace(phaseSpec),
		StartedAt:     now,
		UpdatedAt:     now,
		Targets:       make(map[string]campaignTargetState),
	}
}

func loadCampaignRunState(path string) (*campaignRunState, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("campaign state path is empty")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("campaign state file not found: %s: %w", path, os.ErrNotExist)
		}
		return nil, fmt.Errorf("failed to read campaign state file %s: %w", path, err)
	}
	state := &campaignRunState{}
	if err := json.Unmarshal(content, state); err != nil {
		return nil, fmt.Errorf("failed to parse campaign state file %s: %w", path, err)
	}
	if state.Targets == nil {
		state.Targets = make(map[string]campaignTargetState)
	}
	return state, nil
}

func saveCampaignRunState(path string, state *campaignRunState) error {
	if state == nil {
		return errors.New("campaign state is nil")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("campaign state path is empty")
	}
	if state.Targets == nil {
		state.Targets = make(map[string]campaignTargetState)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create campaign state directory: %w", err)
	}
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize campaign state: %w", err)
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0o600); err != nil {
		return fmt.Errorf("failed to write temporary campaign state file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(path)
		if errRetry := os.Rename(tmpPath, path); errRetry != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("failed to replace campaign state file %s: %w", path, errRetry)
		}
	}
	return nil
}

func applyCampaignRunStateToSummaries(summaries []campaignSummary, state *campaignRunState) []campaignSummary {
	if len(summaries) == 0 || state == nil || len(state.Targets) == 0 {
		return summaries
	}
	index := make(map[string]int, len(summaries))
	for i, summary := range summaries {
		index[summary.Target] = i
	}
	for target, targetState := range state.Targets {
		i, ok := index[target]
		if !ok {
			continue
		}
		summaries[i].RunStatus = normalizeCampaignTargetStatus(targetState.Status)
	}
	return summaries
}

func summarizeCampaignRunState(state *campaignRunState) (phaseSpec string, updatedAt time.Time, pending int, succeeded int, failed int, missing int) {
	if state == nil {
		return "", time.Time{}, 0, 0, 0, 0
	}
	phaseSpec = strings.TrimSpace(state.PhaseSpec)
	updatedAt = state.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = state.StartedAt
	}
	for _, targetState := range state.Targets {
		switch normalizeCampaignTargetStatus(targetState.Status) {
		case string(campaignTargetSucceeded):
			succeeded++
		case string(campaignTargetFailed):
			failed++
		case string(campaignTargetMissing):
			missing++
		default:
			pending++
		}
	}
	return phaseSpec, updatedAt, pending, succeeded, failed, missing
}

func normalizeCampaignTargetStatus(status campaignTargetStatus) string {
	switch status {
	case campaignTargetSucceeded:
		return string(campaignTargetSucceeded)
	case campaignTargetFailed:
		return string(campaignTargetFailed)
	case campaignTargetMissing:
		return string(campaignTargetMissing)
	default:
		return string(campaignTargetPending)
	}
}

func collectCampaignSummaries(workspaceRoot string) ([]campaignSummary, error) {
	workspaceRoot = strings.TrimSpace(workspaceRoot)
	if workspaceRoot == "" {
		return []campaignSummary{}, nil
	}
	entries, err := os.ReadDir(workspaceRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []campaignSummary{}, nil
		}
		return nil, err
	}
	out := make([]campaignSummary, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		target := strings.TrimSpace(entry.Name())
		if target == "" {
			continue
		}
		workspaceDir := filepath.Join(workspaceRoot, target)
		if info, statErr := os.Stat(filepath.Join(workspaceDir, ".n0rmxl")); statErr != nil || !info.IsDir() {
			continue
		}
		summary := campaignSummary{Target: target, PhaseProgress: "P0/10", Status: models.PhasePending}
		if db, dbErr := models.InitCheckpointDB(workspaceDir); dbErr == nil {
			if statuses, statusErr := models.GetAllPhaseStatuses(db); statusErr == nil {
				summary.PhaseProgress, summary.Status = summarizeCampaignStatus(statuses)
			}
			_ = db.Close()
		}
		if db, dbErr := models.InitFindingsDB(workspaceDir); dbErr == nil {
			if findings, findErr := models.GetFindings(db, models.FindingFilter{}); findErr == nil {
				for _, finding := range findings {
					summary.TotalFindings++
					if finding.Severity == models.Critical {
						summary.Critical++
					}
					if finding.Severity == models.High {
						summary.High++
					}
				}
			}
			_ = db.Close()
		}
		summary.UpdatedAt = latestTargetUpdate(workspaceDir)
		out = append(out, summary)
	}
	sort.SliceStable(out, func(i int, j int) bool {
		if out[i].Status != out[j].Status {
			return phaseStatusRank(out[i].Status) < phaseStatusRank(out[j].Status)
		}
		return out[i].Target < out[j].Target
	})
	return out, nil
}

func summarizeCampaignStatus(statuses map[int]models.PhaseStatus) (string, models.PhaseStatus) {
	if len(statuses) == 0 {
		return "P0/10", models.PhasePending
	}
	completed := 0
	maxDone := -1
	final := models.PhasePending
	for phase := 0; phase <= 9; phase++ {
		status := statuses[phase]
		switch status {
		case models.PhaseFailed:
			final = models.PhaseFailed
		case models.PhaseRunning:
			if final != models.PhaseFailed {
				final = models.PhaseRunning
			}
		case models.PhaseDone, models.PhaseSkipped:
			completed++
			maxDone = phase
			if final == models.PhasePending {
				final = models.PhaseDone
			}
		}
	}
	if completed == 10 {
		return "Done", models.PhaseDone
	}
	current := maxDone + 1
	if current < 0 {
		current = 0
	}
	if current > 9 {
		current = 9
	}
	return fmt.Sprintf("P%d/10", current), final
}

func phaseStatusRank(status models.PhaseStatus) int {
	switch status {
	case models.PhaseRunning:
		return 0
	case models.PhaseFailed:
		return 1
	case models.PhasePending:
		return 2
	case models.PhaseDone:
		return 3
	case models.PhaseSkipped:
		return 4
	default:
		return 5
	}
}

func latestTargetUpdate(workspaceDir string) time.Time {
	paths := []string{
		filepath.Join(workspaceDir, ".n0rmxl", "checkpoint.db"),
		filepath.Join(workspaceDir, ".n0rmxl", "findings.db"),
		filepath.Join(workspaceDir, "reports", "report.md"),
		filepath.Join(workspaceDir, "reports", "report.html"),
		filepath.Join(workspaceDir, "reports", "report.pdf"),
	}
	latest := time.Time{}
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil {
			if info.ModTime().After(latest) {
				latest = info.ModTime()
			}
		}
	}
	return latest
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func openPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path is empty")
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	case "darwin":
		cmd = exec.Command("open", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	return cmd.Start()
}

