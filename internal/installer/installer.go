package installer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
)

type InstallStatus string

const (
	StatusPending InstallStatus = "pending"
	StatusRunning InstallStatus = "running"
	StatusDone    InstallStatus = "done"
	StatusFailed  InstallStatus = "failed"
	StatusSkipped InstallStatus = "skipped"
)

type ToolJob struct {
	Name        string
	Category    string
	Description string
	InstallFunc func(ctx context.Context, job *ToolJob) error
	CheckFunc   func() bool
	Version     string
	Status      InstallStatus
	Output      string
	Required    bool
}

type Installer struct {
	jobs        []*ToolJob
	concurrency int
	progress    chan ToolJob
	cfg         *config.Config
	mu          sync.Mutex
}

func NewInstaller(cfg *config.Config) *Installer {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &Installer{
		jobs:        make([]*ToolJob, 0, 256),
		concurrency: 4,
		progress:    make(chan ToolJob, 1024),
		cfg:         cfg,
	}
}

func (i *Installer) RegisterAll() {
	RegisterSystemTools(i)
	RegisterGoTools(i)
	RegisterPythonTools(i)
	RegisterWordlists(i)
	RegisterPayloadLibraries(i)
}

func (i *Installer) Register(job *ToolJob) {
	if job == nil {
		return
	}
	if job.Status == "" {
		job.Status = StatusPending
	}
	i.jobs = append(i.jobs, job)
}

func (i *Installer) Progress() <-chan ToolJob {
	return i.progress
}

func (i *Installer) Jobs() []*ToolJob {
	return i.jobs
}

func (i *Installer) Run(ctx context.Context) error {
	if len(i.jobs) == 0 {
		i.RegisterAll()
	}
	categories := []string{"system", "go", "post-go", "python", "wordlist", "binary"}
	for _, category := range categories {
		if err := i.RunCategory(ctx, category); err != nil {
			return err
		}
	}
	if err := i.saveInstallStatus(); err != nil {
		return err
	}
	return nil
}

func (i *Installer) RunCategory(ctx context.Context, category string) error {
	jobs := make([]*ToolJob, 0, len(i.jobs))
	for _, job := range i.jobs {
		if job.Category == category {
			jobs = append(jobs, job)
		}
	}
	if len(jobs) == 0 {
		return nil
	}

	workerCountMap := map[string]int{
		"system":   1,
		"go":       6,
		"post-go":  1,
		"python":   3,
		"wordlist": 2,
		"binary":   3,
	}

	workerCount := workerCountMap[category]
	if workerCount == 0 {
		workerCount = 2
	}
	if workerCount < 1 {
		workerCount = 1
	}

	jobCh := make(chan *ToolJob)
	errCh := make(chan error, len(jobs))
	var wg sync.WaitGroup

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				if job == nil {
					continue
				}
				if job.CheckFunc != nil && job.CheckFunc() {
					i.setJobStatus(job, StatusSkipped, "already installed")
					continue
				}
				i.setJobStatus(job, StatusRunning, "starting")
				if job.InstallFunc == nil {
					i.setJobStatus(job, StatusSkipped, "no installer defined")
					continue
				}
				if err := job.InstallFunc(ctx, job); err != nil {
					if job.Required {
						i.setJobStatus(job, StatusFailed, err.Error())
						errCh <- fmt.Errorf("required installer job %s failed: %w", job.Name, err)
						continue
					}
					i.setJobStatus(job, StatusFailed, err.Error())
					continue
				}
				i.setJobStatus(job, StatusDone, "installed")
			}
		}()
	}

	for _, job := range jobs {
		select {
		case <-ctx.Done():
			close(jobCh)
			wg.Wait()
			return ctx.Err()
		case jobCh <- job:
		}
	}
	close(jobCh)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *Installer) CheckAll() map[string]bool {
	if len(i.jobs) == 0 {
		i.RegisterAll()
	}

	goPath := resolveGOPATH(i.cfg)
	if strings.TrimSpace(goPath) != "" {
		goBin := filepath.Join(goPath, "bin")
		currentPath := os.Getenv("PATH")
		if !strings.Contains(currentPath, goBin) {
			_ = os.Setenv("PATH", goBin+string(os.PathListSeparator)+currentPath)
		}
	}

	status := make(map[string]bool, len(i.jobs))
	for _, job := range i.jobs {
		installed := false
		if job.CheckFunc != nil {
			installed = job.CheckFunc()
		}
		status[job.Name] = installed
	}
	return status
}

func (i *Installer) MissingTools() []string {
	missing := make([]string, 0)
	for name, installed := range i.CheckAll() {
		if !installed {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

func (i *Installer) InstalledCount() (installed int, total int) {
	total = len(i.jobs)
	for _, job := range i.jobs {
		if job.Status == StatusDone || job.Status == StatusSkipped {
			installed++
		}
	}
	return installed, total
}

func (i *Installer) setJobStatus(job *ToolJob, status InstallStatus, output string) {
	i.mu.Lock()
	job.Status = status
	job.Output = output
	snapshot := *job
	i.mu.Unlock()
	select {
	case i.progress <- snapshot:
	default:
	}
}

func (i *Installer) saveInstallStatus() error {
	if i.cfg == nil {
		return errors.New("config is nil")
	}
	path := filepath.ToSlash(filepath.Join(filepath.Dir(i.cfg.VaultPath), "install_status.json"))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create installer status directory: %w", err)
	}
	state := make(map[string]InstallStatus, len(i.jobs))
	for _, job := range i.jobs {
		state[job.Name] = job.Status
	}
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize install status: %w", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("failed to write install status: %w", err)
	}
	return nil
}
