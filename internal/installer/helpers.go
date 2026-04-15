package installer

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
)

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".local", "share", "n0rmxl")
}

func resolveGOPATH(cfg *config.Config) string {
	if cfg != nil {
		goBin := strings.TrimSpace(cfg.Tools.GoBin)
		if goBin != "" {
			normalized := filepath.Clean(filepath.FromSlash(goBin))
			if strings.EqualFold(filepath.Base(normalized), "bin") {
				return filepath.Dir(normalized)
			}
			return normalized
		}
	}

	if gp := strings.TrimSpace(os.Getenv("GOPATH")); gp != "" {
		return gp
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "go")
}

func goToolCheckFunc(binaryName string, cfg *config.Config) func() bool {
	binary := strings.TrimSpace(binaryName)
	return func() bool {
		if binary == "" {
			return false
		}
		if _, err := exec.LookPath(binary); err == nil {
			return true
		}
		goPath := resolveGOPATH(cfg)
		if goPath == "" {
			return false
		}
		candidate := filepath.Join(goPath, "bin", binary)
		if runtime.GOOS == "windows" {
			if _, err := os.Stat(candidate + ".exe"); err == nil {
				return true
			}
		}
		if _, err := os.Stat(candidate); err == nil {
			return true
		}
		return false
	}
}

func findBinary(name string, cfg *config.Config) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", fmt.Errorf("binary name is empty")
	}

	if p, err := exec.LookPath(trimmed); err == nil {
		return p, nil
	}

	goPath := resolveGOPATH(cfg)
	if goPath != "" {
		candidate := filepath.Join(goPath, "bin", trimmed)
		if runtime.GOOS == "windows" {
			if _, err := os.Stat(candidate + ".exe"); err == nil {
				return candidate + ".exe", nil
			}
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%s not found", trimmed)
}

func findGoBinary() string {
	candidates := make([]string, 0, 6)
	if goroot := strings.TrimSpace(os.Getenv("GOROOT")); goroot != "" {
		candidates = append(candidates, filepath.Join(goroot, "bin", "go"))
	}
	if runtime.GOOS != "windows" {
		candidates = append(candidates, "/usr/local/go/bin/go", "/usr/lib/go/bin/go")
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "go"))
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return "go"
}

func buildGitEnv(env []string) []string {
	base := append([]string{}, env...)
	base = append(base,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=echo",
	)
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		base = append(base, "HOME="+home)
	}
	return base
}

func installedBinaryPath(binaryName string, cfg *config.Config) string {
	goPath := resolveGOPATH(cfg)
	if goPath == "" {
		return binaryName
	}
	candidate := filepath.Join(goPath, "bin", strings.TrimSpace(binaryName))
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(candidate), ".exe") {
		candidate += ".exe"
	}
	return candidate
}

func goInstallEnv(cfg *config.Config, extraEnv []string) ([]string, error) {
	goPath := resolveGOPATH(cfg)
	if goPath == "" {
		return nil, fmt.Errorf("unable to resolve GOPATH")
	}

	binPath := filepath.Join(goPath, "bin")
	if err := os.MkdirAll(binPath, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create go bin directory: %w", err)
	}

	env := append(os.Environ(),
		"GOPATH="+goPath,
		"GOBIN="+binPath,
		"PATH="+binPath+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GOTOOLCHAIN=auto",
		"GONOSUMCHECK=*",
		"GONOSUMDB=*",
		"GOFLAGS=-mod=mod",
		"GOTELEMETRY=off",
	)
	env = buildGitEnv(env)
	env = append(env, extraEnv...)
	return env, nil
}

func installGoTool(ctx context.Context, importPath string, cfg *config.Config) error {
	path := strings.TrimSpace(importPath)
	if path == "" {
		return fmt.Errorf("empty go import path")
	}

	env, err := goInstallEnv(cfg, nil)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, findGoBinary(), "install", "-v", path)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go install %s failed: %w\noutput: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func buildAndInstallFromGit(ctx context.Context, repoURL, binaryName string, cfg *config.Config) error {
	return buildAndInstallFromGitWithGoFlags(ctx, repoURL, binaryName, cfg, nil)
}

func buildAndInstallFromGitWithGoFlags(ctx context.Context, repoURL, binaryName string, cfg *config.Config, extraEnv []string) error {
	repoURL = strings.TrimSpace(repoURL)
	binaryName = strings.TrimSpace(binaryName)
	if repoURL == "" || binaryName == "" {
		return fmt.Errorf("repo URL and binary name are required")
	}

	dest := filepath.Join(defaultDataDir(), "tools", binaryName)
	if _, err := os.Stat(dest); err == nil {
		pull := exec.CommandContext(ctx, "git", "-C", dest, "pull", "--ff-only")
		pull.Env = buildGitEnv(os.Environ())
		_, _ = pull.CombinedOutput()
	} else if err := gitCloneShallow(ctx, repoURL, dest, false); err != nil {
		return fmt.Errorf("failed to clone %s: %w", repoURL, err)
	}

	env, err := goInstallEnv(cfg, extraEnv)
	if err != nil {
		return err
	}

	binaryPath := installedBinaryPath(binaryName, cfg)
	if err := buildMainPackage(ctx, dest, binaryPath, env); err != nil {
		return err
	}

	if _, err := os.Stat(binaryPath); err != nil {
		return fmt.Errorf("binary %s was not produced at %s", binaryName, binaryPath)
	}
	return nil
}

func buildMainPackage(ctx context.Context, repoDir, outputBin string, env []string) error {
	goBin := findGoBinary()
	attempts := make([]string, 0, 8)

	run := func(dir string, args ...string) error {
		cmd := exec.CommandContext(ctx, goBin, args...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		attempts = append(attempts, fmt.Sprintf("%s %s => %s", dir, strings.Join(args, " "), strings.TrimSpace(string(out))))
		return err
	}

	if err := run(repoDir, "build", "-v", "-o", outputBin, "."); err == nil {
		return nil
	}

	if err := run(repoDir, "install", "-v", "./..."); err == nil {
		if _, statErr := os.Stat(outputBin); statErr == nil {
			return nil
		}
	}

	cmdDir := filepath.Join(repoDir, "cmd")
	if entries, err := os.ReadDir(cmdDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pkg := "./cmd/" + entry.Name()
			if err := run(repoDir, "build", "-v", "-o", outputBin, pkg); err == nil {
				return nil
			}
		}
	}

	if err := run(repoDir, "build", "-v", "-o", outputBin, "./..."); err == nil {
		if _, statErr := os.Stat(outputBin); statErr == nil {
			return nil
		}
	}

	if len(attempts) == 0 {
		return fmt.Errorf("could not build repository at %s", repoDir)
	}
	return fmt.Errorf("could not build repository at %s: %s", repoDir, strings.Join(attempts, " | "))
}

func downloadFile(ctx context.Context, url, dest string) error {
	cmd := exec.CommandContext(ctx, "curl", "-fsSL", "--connect-timeout", "30", "--max-time", "300", "--retry", "3", "--retry-delay", "5", "-o", dest, url)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("curl download failed for %s: %w\n%s", url, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func installBinary(ctx context.Context, src, dest string) error {
	if err := copyFile(src, dest); err == nil {
		return nil
	}
	if runtime.GOOS == "windows" {
		return copyFile(src, dest)
	}

	cmd := exec.CommandContext(ctx, "sudo", "cp", src, dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install binary %s -> %s failed: %w\n%s", src, dest, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func gitCloneShallow(ctx context.Context, repoURL, dest string, withSudo bool) error {
	if _, err := os.Stat(dest); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}

	args := []string{"clone", "--depth", "1", "--single-branch", "--no-tags", repoURL, dest}
	clone := exec.CommandContext(ctx, "git", args...)
	clone.Env = buildGitEnv(os.Environ())
	out, err := clone.CombinedOutput()
	if err == nil {
		return nil
	}

	if !withSudo || runtime.GOOS == "windows" {
		return fmt.Errorf("git clone failed for %s: %w\n%s", repoURL, err, strings.TrimSpace(string(out)))
	}

	sudoArgs := append([]string{"git"}, args...)
	clone2 := exec.CommandContext(ctx, "sudo", sudoArgs...)
	clone2.Env = buildGitEnv(os.Environ())
	out2, err2 := clone2.CombinedOutput()
	if err2 != nil {
		return fmt.Errorf("git clone failed for %s: %w\n%s\n%s", repoURL, err2, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
	}
	return nil
}
