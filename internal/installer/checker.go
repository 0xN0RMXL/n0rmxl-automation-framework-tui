package installer

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
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
	pythonExec := detectPythonCommand()
	if pythonExec == "" {
		return "", "", fmt.Errorf("python runtime not found")
	}
	pyOut, pyErr := runShellCommand(context.Background(), fmt.Sprintf("%s --version", pythonExec))
	if pyErr != nil {
		return "", "", pyErr
	}
	pipOut, pipErr := runShellCommand(context.Background(), fmt.Sprintf("%s -m pip --version", pythonExec))
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
		pythonExec := detectPythonCommand()
		if pythonExec == "" {
			return "unknown"
		}
		if out, err := runShellCommand(context.Background(), fmt.Sprintf("%s --version", pythonExec)); err == nil {
			return strings.TrimSpace(out)
		}
	}
	return "unknown"
}
