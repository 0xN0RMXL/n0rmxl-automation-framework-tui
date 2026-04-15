package installer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
)

const payloadsAllTheThingsRepo = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"

func PayloadLibraryPath(cfg *config.Config) string {
	clonePath, err := gitClonePath(cfg, "PayloadsAllTheThings")
	if err == nil && strings.TrimSpace(clonePath) != "" {
		return clonePath
	}
	base := ""
	if cfg != nil {
		base = strings.TrimSpace(cfg.Tools.GitClones)
	}
	if base == "" {
		base = filepath.Join(defaultDataDir(), "tools")
	}
	return filepath.Join(base, "PayloadsAllTheThings")
}

func PayloadLibraryStatus(cfg *config.Config) (string, bool) {
	root := PayloadLibraryPath(cfg)
	if info, err := os.Stat(filepath.Join(root, ".git")); err == nil && info.IsDir() {
		return root, true
	}
	if _, err := os.Stat(filepath.Join(root, "README.md")); err == nil {
		return root, true
	}
	return root, false
}

func RegisterPayloadLibraries(i *Installer) {
	if i == nil {
		return
	}
	i.Register(&ToolJob{
		Name:        "payloads-all-the-things",
		Category:    "wordlist",
		Description: "Clone/update PayloadsAllTheThings payload library",
		Required:    false,
		CheckFunc: func() bool {
			_, ready := PayloadLibraryStatus(i.cfg)
			return ready
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			clonePath := PayloadLibraryPath(i.cfg)
			if err := os.MkdirAll(filepath.Dir(clonePath), 0o755); err != nil {
				return err
			}
			return syncGitRepository(ctx, payloadsAllTheThingsRepo, clonePath)
		},
	})
}

func syncGitRepository(ctx context.Context, repoURL string, targetPath string) error {
	targetPath = strings.TrimSpace(targetPath)
	if targetPath == "" {
		return errors.New("target path is empty")
	}
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git is required to sync payload repository: %w", err)
	}

	if info, err := os.Stat(filepath.Join(targetPath, ".git")); err == nil && info.IsDir() {
		cmd := exec.CommandContext(ctx, "git", "-C", targetPath, "pull", "--ff-only")
		cmd.Env = buildGitEnv(os.Environ())
		out, runErr := cmd.CombinedOutput()
		if runErr != nil {
			return fmt.Errorf("git pull failed for %s: %w: %s", targetPath, runErr, strings.TrimSpace(string(out)))
		}
		return nil
	}

	if info, err := os.Stat(targetPath); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("target path exists and is not a directory: %s", targetPath)
		}
		entries, readErr := os.ReadDir(targetPath)
		if readErr != nil {
			return fmt.Errorf("failed to inspect target directory %s: %w", targetPath, readErr)
		}
		if len(entries) > 0 {
			return fmt.Errorf("target directory exists and is not a git repository: %s", targetPath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to inspect target path %s: %w", targetPath, err)
	}

	if err := gitCloneShallow(ctx, repoURL, targetPath, false); err != nil {
		return fmt.Errorf("git clone failed for %s: %w", repoURL, err)
	}
	return nil
}
