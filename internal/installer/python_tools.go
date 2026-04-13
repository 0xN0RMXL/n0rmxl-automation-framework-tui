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
	"paramspider",
	"trufflehog",
	"shodan",
	"censys",
	"waymore",
	"git-dumper",
	"s3scanner",
	"cloud_enum",
	"subdominator",
	"graphw00f",
	"clairvoyance",
	"bfac",
	"hacker-scoper",
}

var gitPythonTools = []GitTool{
	{Name: "LinkFinder", Repo: "https://github.com/GerbenJavado/LinkFinder", ReqFile: "requirements.txt"},
	{Name: "SecretFinder", Repo: "https://github.com/m4ll0k/SecretFinder", ReqFile: "requirements.txt"},
	{Name: "tplmap", Repo: "https://github.com/epinna/tplmap", ReqFile: "requirements.txt"},
	{Name: "Corsy", Repo: "https://github.com/s0md3v/Corsy", ReqFile: "requirements.txt"},
	{Name: "GitDorker", Repo: "https://github.com/obheda12/GitDorker", ReqFile: "requirements.txt"},
	{Name: "SSRFmap", Repo: "https://github.com/swisskyrepo/SSRFmap", ReqFile: "requirements.txt"},
	{Name: "jwt_tool", Repo: "https://github.com/ticarpi/jwt_tool", ReqFile: "requirements.txt"},
	{Name: "commix", Repo: "https://github.com/commixproject/commix", Setup: "python3 commix.py --install"},
	{Name: "cloud_enum", Repo: "https://github.com/initstring/cloud_enum", ReqFile: "requirements.txt"},
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
					_, _ = runShellCommand(ctx, fmt.Sprintf("git -C %q pull --ff-only", clonePath))
				} else {
					if _, err := runShellCommand(ctx, fmt.Sprintf("git clone %s %q", g.Repo, clonePath)); err != nil {
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
