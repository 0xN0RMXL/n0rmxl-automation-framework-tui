package installer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/n0rmxl/n0rmxl/internal/config"
)

type CheckResult struct {
	Name      string
	Installed bool
	Version   string
	Path      string
}

func CheckAllTools() []CheckResult {
	cfg := config.DefaultConfig()
	inst := NewInstaller(cfg)
	inst.RegisterAll()
	results := make([]CheckResult, 0, len(inst.jobs))
	for _, job := range inst.jobs {
		results = append(results, CheckTool(job.Name))
	}
	return results
}

func CheckTool(name string) CheckResult {
	result := CheckResult{Name: name}
	path, err := exec.LookPath(name)
	if err != nil {
		return result
	}
	result.Installed = true
	result.Path = path
	result.Version = detectVersion(name)
	return result
}

func CheckGoEnv() (goVersion string, goPath string, err error) {
	path, err := exec.LookPath("go")
	if err != nil {
		return "", "", err
	}
	out, runErr := runShellCommand(context.Background(), "go version")
	if runErr != nil {
		return "", path, runErr
	}
	return strings.TrimSpace(out), path, nil
}

func CheckPythonEnv() (pythonVersion string, pipVersion string, err error) {
	pythonCmd := "python --version"
	if runtime.GOOS == "linux" {
		pythonCmd = "python3 --version"
	}
	pyOut, pyErr := runShellCommand(context.Background(), pythonCmd)
	if pyErr != nil {
		return "", "", pyErr
	}
	pipOut, pipErr := runShellCommand(context.Background(), "python -m pip --version")
	if pipErr != nil {
		return strings.TrimSpace(pyOut), "", pipErr
	}
	return strings.TrimSpace(pyOut), strings.TrimSpace(pipOut), nil
}

func detectVersion(name string) string {
	commands := []string{name + " --version", name + " version", name + " -version"}
	for _, cmd := range commands {
		out, err := runShellCommand(context.Background(), cmd)
		if err == nil && strings.TrimSpace(out) != "" {
			line := strings.Split(strings.TrimSpace(out), "\n")[0]
			return strings.TrimSpace(line)
		}
	}
	if name == "python" || name == "python3" {
		if out, err := runShellCommand(context.Background(), "python --version"); err == nil {
			return strings.TrimSpace(out)
		}
	}
	return "unknown"
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".local", "share", "n0rmxl")
}
