package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
)

type GitTool struct {
	Name    string
	Repo    string
	ReqFile string
	Setup   string
	Build   string
}

var pipTools = []string{
	"arjun",
	"wafw00f",
	"dirsearch",
	"bbot",
	"trufflehog",
	"shodan",
	"censys",
	"waymore",
	"git-dumper",
	"s3scanner",
	"subdominator",
	"clairvoyance",
}

var gitPythonTools = []GitTool{
	{Name: "LinkFinder", Repo: "https://github.com/GerbenJavado/LinkFinder", ReqFile: "requirements.txt"},
	{Name: "SecretFinder", Repo: "https://github.com/m4ll0k/SecretFinder", ReqFile: "requirements.txt"},
	{Name: "tplmap", Repo: "https://github.com/epinna/tplmap", ReqFile: "requirements.txt"},
	{Name: "Corsy", Repo: "https://github.com/s0md3v/Corsy", ReqFile: "requirements.txt"},
	{Name: "GitDorker", Repo: "https://github.com/obheda12/GitDorker", ReqFile: "requirements.txt"},
	{Name: "SSRFmap", Repo: "https://github.com/swisskyrepo/SSRFmap", ReqFile: "requirements.txt"},
	{Name: "jwt_tool", Repo: "https://github.com/ticarpi/jwt_tool", ReqFile: "requirements.txt"},
	{Name: "cloud_enum", Repo: "https://github.com/initstring/cloud_enum", ReqFile: "requirements.txt"},
	{Name: "paramspider", Repo: "https://github.com/devanshbatham/ParamSpider", ReqFile: "requirements.txt"},
	{Name: "graphw00f", Repo: "https://github.com/dolevf/graphw00f", ReqFile: "requirements.txt"},
	{Name: "bfac", Repo: "https://github.com/mazen160/bfac", ReqFile: "requirements.txt"},
	{Name: "phpggc", Repo: "https://github.com/ambionics/phpggc"},
	{Name: "lazyegg", Repo: "https://github.com/schooldropout1337/lazyegg"},
	{Name: "smuggler", Repo: "https://github.com/defparam/smuggler"},
	{Name: "EyeWitness", Repo: "https://github.com/RedSiege/EyeWitness", ReqFile: "Python/requirements.txt"},
}

var pythonBootstrapMu sync.Mutex

func RegisterPythonTools(i *Installer) {
	i.Register(&ToolJob{
		Name:        "python-runtime",
		Category:    "python",
		Description: "Ensure Python runtime and pip are available",
		Required:    true,
		CheckFunc: func() bool {
			return hasWorkingPythonAndPip()
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			return ensurePythonRuntime(ctx)
		},
	})

	for _, pipTool := range pipTools {
		name := pipTool
		i.Register(&ToolJob{
			Name:        name,
			Category:    "python",
			Description: "pip tool " + name,
			Required:    false,
			CheckFunc: func() bool {
				if _, err := exec.LookPath(name); err == nil {
					return true
				}
				pythonCmd := detectPythonCommand()
				if pythonCmd == "" {
					return false
				}
				_, err := runShellCommand(context.Background(), fmt.Sprintf("%s -c \"import %s\"", pythonCmd, strings.ReplaceAll(name, "-", "_")))
				return err == nil
			},
			InstallFunc: func(ctx context.Context, job *ToolJob) error {
				if err := ensurePythonRuntime(ctx); err != nil {
					return err
				}
				pythonCmd := detectPythonCommand()
				if pythonCmd == "" {
					return fmt.Errorf("python runtime not found after bootstrap")
				}
				cmd := fmt.Sprintf("%s -m pip install --break-system-packages %s", pythonCmd, name)
				if _, err := runShellCommand(ctx, cmd); err != nil {
					cmd = fmt.Sprintf("pip3 install --break-system-packages %s", name)
					_, err = runShellCommand(ctx, cmd)
					return err
				}
				return nil
			},
		})
	}

	for _, tool := range gitPythonTools {
		g := tool
		i.Register(&ToolJob{
			Name:        g.Name,
			Category:    "python",
			Description: "git clone " + g.Name,
			Required:    false,
			CheckFunc: func() bool {
				path, err := gitClonePath(i.cfg, g.Name)
				if err != nil {
					return false
				}
				_, err = os.Stat(path)
				return err == nil
			},
			InstallFunc: func(ctx context.Context, job *ToolJob) error {
				clonePath, err := gitClonePath(i.cfg, g.Name)
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(clonePath), 0o755); err != nil {
					return err
				}
				if err := ensurePythonRuntime(ctx); err != nil {
					return err
				}
				pythonCmd := detectPythonCommand()
				if _, err := os.Stat(clonePath); err == nil {
					pull := exec.CommandContext(ctx, "git", "-C", clonePath, "pull", "--ff-only")
					pull.Env = buildGitEnv(os.Environ())
					_, _ = pull.CombinedOutput()
				} else {
					if err := gitCloneShallow(ctx, g.Repo, clonePath, false); err != nil {
						return err
					}
				}
				if g.ReqFile != "" {
					req := filepath.Join(clonePath, g.ReqFile)
					if _, err := os.Stat(req); err == nil {
						if pythonCmd != "" {
							_, _ = runShellCommand(ctx, fmt.Sprintf("%s -m pip install --break-system-packages -r %q", pythonCmd, req))
						}
					}
				}
				if strings.TrimSpace(g.Build) != "" {
					_, _ = runShellCommand(ctx, fmt.Sprintf("cd %q ; %s", clonePath, g.Build))
				}
				if strings.TrimSpace(g.Setup) != "" {
					_, _ = runShellCommand(ctx, fmt.Sprintf("cd %q ; %s", clonePath, g.Setup))
				}
				return nil
			},
		})
	}

	i.Register(&ToolJob{
		Name:        "hacker-scoper",
		Category:    "python",
		Description: "Scope-based result filtering helper",
		Required:    false,
		CheckFunc: func() bool {
			if _, err := exec.LookPath("hacker-scoper"); err == nil {
				return true
			}
			pythonCmd := detectPythonCommand()
			if pythonCmd == "" {
				return false
			}
			_, err := runShellCommand(context.Background(), fmt.Sprintf("%s -c \"import hacker_scoper\"", pythonCmd))
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			if err := ensurePythonRuntime(ctx); err != nil {
				return err
			}
			pythonCmd := detectPythonCommand()
			if pythonCmd == "" {
				return fmt.Errorf("python runtime not found after bootstrap")
			}

			pipInstallCmd := fmt.Sprintf("%s -m pip install --break-system-packages git+https://github.com/Amet13/hacker-scoper.git", pythonCmd)
			if _, err := runShellCommand(ctx, pipInstallCmd); err == nil {
				return nil
			}

			clonePath, err := gitClonePath(i.cfg, "hacker-scoper")
			if err != nil {
				return err
			}
			if _, err := os.Stat(clonePath); err == nil {
				pull := exec.CommandContext(ctx, "git", "-C", clonePath, "pull", "--ff-only")
				pull.Env = buildGitEnv(os.Environ())
				_, _ = pull.CombinedOutput()
			} else {
				if err := gitCloneShallow(ctx, "https://github.com/Amet13/hacker-scoper.git", clonePath, false); err != nil {
					return fmt.Errorf("hacker-scoper clone failed: %w", err)
				}
			}

			_, err = runShellCommand(ctx, fmt.Sprintf("%s -m pip install --break-system-packages %q", pythonCmd, clonePath))
			if err != nil {
				return fmt.Errorf("hacker-scoper install failed: %w", err)
			}
			return nil
		},
	})

	i.Register(&ToolJob{
		Name:        "commix",
		Category:    "python",
		Description: "Automated command injection exploitation tool",
		Required:    false,
		CheckFunc: func() bool {
			if _, err := exec.LookPath("commix"); err == nil {
				return true
			}
			clonePath, err := gitClonePath(i.cfg, "commix")
			if err != nil {
				return false
			}
			if _, err := os.Stat(filepath.Join(clonePath, "commix.py")); err == nil {
				return true
			}
			wrapper := filepath.Join(defaultDataDir(), "scripts", commixWrapperName())
			_, err = os.Stat(wrapper)
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			if err := ensurePythonRuntime(ctx); err != nil {
				return err
			}

			clonePath, err := gitClonePath(i.cfg, "commix")
			if err != nil {
				return err
			}

			if _, err := os.Stat(clonePath); err == nil {
				pull := exec.CommandContext(ctx, "git", "-C", clonePath, "pull", "--ff-only")
				pull.Env = buildGitEnv(os.Environ())
				_, _ = pull.CombinedOutput()
			} else {
				if err := gitCloneShallow(ctx, "https://github.com/commixproject/commix.git", clonePath, false); err != nil {
					return err
				}
			}

			mainFile := filepath.Join(clonePath, "commix.py")
			if _, err := os.Stat(mainFile); err != nil {
				return fmt.Errorf("commix clone is incomplete: %w", err)
			}

			pythonCmd := detectPythonCommand()
			if pythonCmd != "" {
				reqFile := filepath.Join(clonePath, "requirements.txt")
				if _, err := os.Stat(reqFile); err == nil {
					_, _ = runShellCommand(ctx, fmt.Sprintf("%s -m pip install --break-system-packages -r %q", pythonCmd, reqFile))
				}
			}

			wrapperPath, err := ensureCommixWrapper(clonePath)
			if err != nil {
				return err
			}
			job.Output = "commix available via clone at " + clonePath + " and wrapper " + wrapperPath
			return nil
		},
	})
}

func gitClonePath(cfg *config.Config, name string) (string, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	if cfg.Tools.GitClones == "" {
		return "", fmt.Errorf("git clone path is empty")
	}
	return filepath.Join(cfg.Tools.GitClones, name), nil
}

func detectPythonCommand() string {
	if runtime.GOOS == "windows" {
		if _, err := exec.LookPath("py"); err == nil {
			return "py -3"
		}
	}
	if _, err := exec.LookPath("python3"); err == nil {
		return "python3"
	}
	if _, err := exec.LookPath("python"); err == nil {
		return "python"
	}
	return ""
}

func hasWorkingPythonAndPip() bool {
	pythonCmd := detectPythonCommand()
	if pythonCmd == "" {
		return false
	}
	if _, err := runShellCommand(context.Background(), fmt.Sprintf("%s --version", pythonCmd)); err != nil {
		return false
	}
	if _, err := runShellCommand(context.Background(), fmt.Sprintf("%s -m pip --version", pythonCmd)); err != nil {
		return false
	}
	return true
}

func ensurePythonRuntime(ctx context.Context) error {
	if hasWorkingPythonAndPip() {
		return nil
	}

	pythonBootstrapMu.Lock()
	defer pythonBootstrapMu.Unlock()

	if hasWorkingPythonAndPip() {
		return nil
	}

	if err := bootstrapPythonRuntime(ctx); err != nil {
		return err
	}

	if !hasWorkingPythonAndPip() {
		return fmt.Errorf("python bootstrap completed but python/pip are still unavailable")
	}

	pythonCmd := detectPythonCommand()
	if pythonCmd != "" {
		_, _ = runShellCommand(ctx, fmt.Sprintf("%s -m pip install --upgrade pip setuptools wheel", pythonCmd))
	}
	if _, err := exec.LookPath("pipx"); err == nil {
		_, _ = runShellCommand(ctx, "pipx ensurepath")
	}

	return nil
}

func bootstrapPythonRuntime(ctx context.Context) error {
	switch runtime.GOOS {
	case "linux":
		cmd := "sudo apt-get update ; sudo apt-get install -y python3 python3-pip python3-venv pipx"
		if _, err := runShellCommand(ctx, cmd); err == nil {
			return nil
		}
		fallback := "apt-get update ; apt-get install -y python3 python3-pip python3-venv pipx"
		if _, err := runShellCommand(ctx, fallback); err != nil {
			return fmt.Errorf("failed to auto-install Python runtime on linux: %w", err)
		}
		return nil
	case "darwin":
		if _, err := exec.LookPath("brew"); err != nil {
			return fmt.Errorf("python runtime missing and Homebrew is not available")
		}
		if _, err := runShellCommand(ctx, "brew install python pipx"); err != nil {
			return fmt.Errorf("failed to auto-install Python runtime with Homebrew: %w", err)
		}
		return nil
	case "windows":
		if _, err := exec.LookPath("winget"); err != nil {
			return fmt.Errorf("python runtime missing and winget is not available; use WSL2 or install Python manually")
		}
		cmd := "winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements"
		if _, err := runShellCommand(ctx, cmd); err != nil {
			return fmt.Errorf("failed to auto-install Python runtime with winget: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("automatic python bootstrap is not supported on %s", runtime.GOOS)
	}
}

func commixWrapperName() string {
	if runtime.GOOS == "windows" {
		return "commix.cmd"
	}
	return "commix"
}

func ensureCommixWrapper(clonePath string) (string, error) {
	scriptDir := filepath.Join(defaultDataDir(), "scripts")
	if err := os.MkdirAll(scriptDir, 0o755); err != nil {
		return "", err
	}

	wrapperPath := filepath.Join(scriptDir, commixWrapperName())
	mainFile := filepath.Join(clonePath, "commix.py")
	if runtime.GOOS == "windows" {
		content := fmt.Sprintf("@echo off\r\npython \"%s\" %%*\r\n", mainFile)
		if err := os.WriteFile(wrapperPath, []byte(content), 0o755); err != nil {
			return "", err
		}
		return wrapperPath, nil
	}

	content := fmt.Sprintf("#!/usr/bin/env sh\nexec python3 %q \"$@\"\n", mainFile)
	if err := os.WriteFile(wrapperPath, []byte(content), 0o755); err != nil {
		return "", err
	}
	return wrapperPath, nil
}
