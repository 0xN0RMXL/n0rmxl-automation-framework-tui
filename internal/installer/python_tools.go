package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	{Name: "massdns", Repo: "https://github.com/blechschmidt/massdns", Build: "make"},
	{Name: "cloud_enum", Repo: "https://github.com/initstring/cloud_enum", ReqFile: "requirements.txt"},
	{Name: "phpggc", Repo: "https://github.com/ambionics/phpggc"},
	{Name: "lazyegg", Repo: "https://github.com/schooldropout1337/lazyegg"},
	{Name: "smuggler", Repo: "https://github.com/defparam/smuggler"},
	{Name: "EyeWitness", Repo: "https://github.com/RedSiege/EyeWitness", ReqFile: "Python/requirements.txt"},
}

func RegisterPythonTools(i *Installer) {
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
				_, err := runShellCommand(context.Background(), fmt.Sprintf("python -c \"import %s\"", strings.ReplaceAll(name, "-", "_")))
				return err == nil
			},
			InstallFunc: func(ctx context.Context, job *ToolJob) error {
				cmd := fmt.Sprintf("python -m pip install --break-system-packages %s", name)
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
				if _, err := os.Stat(clonePath); err == nil {
					_, _ = runShellCommand(ctx, fmt.Sprintf("git -C %s pull --ff-only", clonePath))
				} else {
					if _, err := runShellCommand(ctx, fmt.Sprintf("git clone %s %s", g.Repo, clonePath)); err != nil {
						return err
					}
				}
				if g.ReqFile != "" {
					req := filepath.Join(clonePath, g.ReqFile)
					if _, err := os.Stat(req); err == nil {
						_, _ = runShellCommand(ctx, fmt.Sprintf("python -m pip install --break-system-packages -r %s", req))
					}
				}
				if strings.TrimSpace(g.Build) != "" {
					_, _ = runShellCommand(ctx, fmt.Sprintf("cd %s ; %s", clonePath, g.Build))
				}
				if strings.TrimSpace(g.Setup) != "" {
					_, _ = runShellCommand(ctx, fmt.Sprintf("cd %s ; %s", clonePath, g.Setup))
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

