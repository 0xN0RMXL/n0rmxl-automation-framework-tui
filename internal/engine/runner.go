package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

type PhaseRunner struct {
	Phase      int
	Jobs       []*Job
	MaxConc    int
	Progress   chan JobUpdate
	checkpoint *Checkpoint
	runCfg     *config.RunConfig

	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	paused    bool
	running   map[string]*Job
	forceSkip map[string]struct{}
}

type JobUpdate struct {
	Job   *Job
	Line  string
	Event string
}

func NewPhaseRunner(phase int, runCfg *config.RunConfig, checkpoint *Checkpoint) *PhaseRunner {
	maxConc := 4
	if runCfg != nil && runCfg.Settings.Threads > 0 {
		maxConc = runCfg.Settings.Threads
		if maxConc > 64 {
			maxConc = 64
		}
	}
	return &PhaseRunner{
		Phase:      phase,
		Jobs:       make([]*Job, 0, 64),
		MaxConc:    maxConc,
		Progress:   make(chan JobUpdate, 2048),
		checkpoint: checkpoint,
		runCfg:     runCfg,
		running:    make(map[string]*Job),
		forceSkip:  make(map[string]struct{}),
	}
}

func (pr *PhaseRunner) AddJob(j *Job) {
	if j == nil {
		return
	}
	if j.ID == "" {
		j.ID = fmt.Sprintf("%d-%s", pr.Phase, strings.TrimSpace(j.ToolName))
	}
	if j.Phase == 0 {
		j.Phase = pr.Phase
	}
	pr.Jobs = append(pr.Jobs, j)
}

func (pr *PhaseRunner) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	pr.ctx, pr.cancel = context.WithCancel(ctx)
	defer func() {
		if pr.cancel != nil {
			pr.cancel()
		}
		close(pr.Progress)
	}()

	if pr.checkpoint != nil {
		_ = pr.checkpoint.SetPhaseStatus(pr.Phase, models.PhaseRunning)
	}

	pending := make(map[string]*Job, len(pr.Jobs))
	completed := make(map[string]bool, len(pr.Jobs)*2)
	for _, job := range pr.Jobs {
		pending[job.ID] = job
	}

	for len(pending) > 0 {
		ready := pr.collectReadyJobs(pending, completed)
		if len(ready) == 0 {
			if pr.checkpoint != nil {
				_ = pr.checkpoint.SetPhaseStatus(pr.Phase, models.PhaseFailed)
			}
			return errors.New("dependency cycle detected in phase jobs")
		}

		if err := pr.runReadyBatch(ready, completed); err != nil {
			if pr.checkpoint != nil {
				_ = pr.checkpoint.SetPhaseStatus(pr.Phase, models.PhaseFailed)
			}
			return err
		}

		for _, job := range ready {
			delete(pending, job.ID)
		}
	}

	if pr.checkpoint != nil {
		_ = pr.checkpoint.SetPhaseStatus(pr.Phase, models.PhaseDone)
	}
	return nil
}

func (pr *PhaseRunner) collectReadyJobs(pending map[string]*Job, completed map[string]bool) []*Job {
	ready := make([]*Job, 0, len(pending))
	keys := make([]string, 0, len(pending))
	for id := range pending {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		job := pending[id]
		if job == nil {
			continue
		}
		if pr.dependenciesSatisfied(job, completed) {
			ready = append(ready, job)
		}
	}
	return ready
}

func (pr *PhaseRunner) dependenciesSatisfied(job *Job, completed map[string]bool) bool {
	if len(job.DependsOn) == 0 {
		return true
	}
	for _, dep := range job.DependsOn {
		dep = strings.TrimSpace(dep)
		if dep == "" {
			continue
		}
		if completed[dep] {
			continue
		}
		if completed[fmt.Sprintf("%d-%s", pr.Phase, dep)] {
			continue
		}
		return false
	}
	return true
}

func (pr *PhaseRunner) runReadyBatch(ready []*Job, completed map[string]bool) error {
	sem := make(chan struct{}, pr.MaxConc)
	var wg sync.WaitGroup
	var runErr error
	var once sync.Once
	var completeMu sync.Mutex

	for _, job := range ready {
		if job == nil {
			continue
		}
		select {
		case <-pr.ctx.Done():
			return pr.ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(j *Job) {
			defer wg.Done()
			defer func() { <-sem }()

			if pr.shouldSkip(j) {
				j.Status = JobSkipped
				pr.emit(JobUpdate{Job: j, Event: "skip", Line: "checkpoint indicates completed"})
				pr.setToolCheckpoint(j, models.PhaseSkipped, nil)
				completeMu.Lock()
				completed[j.ID] = true
				completed[j.ToolName] = true
				completeMu.Unlock()
				return
			}

			originalOnLine := j.OnLine
			j.OnLine = func(job *Job, line string) {
				pr.emit(JobUpdate{Job: job, Event: "line", Line: line})
				if originalOnLine != nil {
					originalOnLine(job, line)
				}
			}

			pr.trackRunning(j, true)
			pr.emit(JobUpdate{Job: j, Event: "start"})
			err := j.Run(pr.ctx)
			pr.trackRunning(j, false)
			if err != nil {
				pr.emit(JobUpdate{Job: j, Event: "error", Line: err.Error()})
				pr.setToolCheckpoint(j, models.PhaseFailed, err)
				if j.Required {
					once.Do(func() { runErr = err })
				}
			} else {
				if j.Status == JobSkipped {
					pr.emit(JobUpdate{Job: j, Event: "skip", Line: j.ErrorMsg})
					pr.setToolCheckpoint(j, models.PhaseSkipped, nil)
				} else {
					if j.ParseOutput != nil {
						j.ItemsFound = j.ParseOutput(j)
					}
					pr.emit(JobUpdate{Job: j, Event: "done"})
					pr.setToolCheckpoint(j, models.PhaseDone, nil)
				}
			}
			completeMu.Lock()
			completed[j.ID] = true
			completed[j.ToolName] = true
			completeMu.Unlock()
		}(job)
	}
	wg.Wait()
	if runErr != nil {
		return runErr
	}
	return nil
}

func (pr *PhaseRunner) shouldSkip(job *Job) bool {
	pr.mu.Lock()
	_, forceSkip := pr.forceSkip[job.ID]
	pr.mu.Unlock()
	if forceSkip {
		return true
	}
	if pr.checkpoint == nil {
		return false
	}
	return pr.checkpoint.IsToolDone(pr.Phase, job.ToolName)
}

func (pr *PhaseRunner) setToolCheckpoint(job *Job, status models.PhaseStatus, runErr error) {
	if pr.checkpoint == nil || job == nil {
		return
	}
	result := models.ToolResult{
		ToolName:   job.ToolName,
		Status:     status,
		OutputFile: job.OutputFile,
		StartedAt:  job.StartedAt,
		FinishedAt: job.FinishedAt,
		ItemsFound: job.ItemsFound,
	}
	if runErr != nil {
		result.Error = runErr.Error()
	}
	_ = pr.checkpoint.SetToolStatus(pr.Phase, job.ToolName, result)
}

func (pr *PhaseRunner) emit(update JobUpdate) {
	select {
	case pr.Progress <- update:
	default:
	}
}

func (pr *PhaseRunner) trackRunning(job *Job, add bool) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if add {
		pr.running[job.ID] = job
		return
	}
	delete(pr.running, job.ID)
}

func (pr *PhaseRunner) Skip(jobID string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.forceSkip[jobID] = struct{}{}
}

func (pr *PhaseRunner) Pause() {
	pr.mu.Lock()
	pr.paused = true
	jobs := make([]*Job, 0, len(pr.running))
	for _, job := range pr.running {
		jobs = append(jobs, job)
	}
	pr.mu.Unlock()
	for _, job := range jobs {
		if job != nil && job.cmd != nil && job.cmd.Process != nil {
			_ = pauseProcess(job.cmd.Process)
		}
	}
}

func (pr *PhaseRunner) Resume() {
	pr.mu.Lock()
	pr.paused = false
	jobs := make([]*Job, 0, len(pr.running))
	for _, job := range pr.running {
		jobs = append(jobs, job)
	}
	pr.mu.Unlock()
	for _, job := range jobs {
		if job != nil && job.cmd != nil && job.cmd.Process != nil {
			_ = resumeProcess(job.cmd.Process)
		}
	}
}

func (pr *PhaseRunner) Stop() {
	if pr.cancel != nil {
		pr.cancel()
	}
	pr.mu.Lock()
	jobs := make([]*Job, 0, len(pr.running))
	for _, job := range pr.running {
		jobs = append(jobs, job)
	}
	pr.mu.Unlock()
	for _, job := range jobs {
		if job != nil {
			job.Kill()
		}
	}
}

func (pr *PhaseRunner) Status() map[string]JobStatus {
	statuses := make(map[string]JobStatus, len(pr.Jobs))
	for _, job := range pr.Jobs {
		if job == nil {
			continue
		}
		statuses[job.ToolName] = job.Status
	}
	return statuses
}

func (pr *PhaseRunner) Elapsed() time.Duration {
	var started time.Time
	for _, job := range pr.Jobs {
		if job == nil || job.StartedAt.IsZero() {
			continue
		}
		if started.IsZero() || job.StartedAt.Before(started) {
			started = job.StartedAt
		}
	}
	if started.IsZero() {
		return 0
	}
	return time.Since(started)
}

