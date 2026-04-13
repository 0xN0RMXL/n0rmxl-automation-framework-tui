package phase6

import (
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/models"
	"github.com/n0rmxl/n0rmxl/internal/phases/phase6/exploits"
)

type WizardState string

const (
	WizardClassList  WizardState = "class_list"
	WizardTargetList WizardState = "target_list"
	WizardPayloads   WizardState = "payloads"
	WizardExecute    WizardState = "execute"
	WizardCapture    WizardState = "capture"
	WizardResult     WizardState = "result"
)

type ExploitWizard struct {
	target   *models.Target
	ws       models.Workspace
	cfg      *config.RunConfig
	findings []models.Finding

	state     WizardState
	vulnClass string

	selectedFinding *models.Finding
	selectedPayload string
	editedCommand   string

	items     []string
	textinput textinput.Model
	viewport  viewport.Model
	logLines  []string
}

func NewExploitWizard(target *models.Target, ws models.Workspace, cfg *config.RunConfig, findings []models.Finding) ExploitWizard {
	input := textinput.New()
	input.Placeholder = "Edit exploit command"

	view := viewport.New(0, 0)
	view.SetContent("Select a vulnerability class to begin.")

	wizard := ExploitWizard{
		target:    target,
		ws:        ws,
		cfg:       cfg,
		findings:  append([]models.Finding{}, findings...),
		state:     WizardClassList,
		items:     make([]string, 0, 32),
		textinput: input,
		viewport:  view,
		logLines:  make([]string, 0, 32),
	}
	wizard.sortFindings()
	return wizard
}

func (w *ExploitWizard) sortFindings() {
	sort.SliceStable(w.findings, func(i int, j int) bool {
		if severityRank(w.findings[i].Severity) != severityRank(w.findings[j].Severity) {
			return severityRank(w.findings[i].Severity) > severityRank(w.findings[j].Severity)
		}
		if w.findings[i].CVSS != w.findings[j].CVSS {
			return w.findings[i].CVSS > w.findings[j].CVSS
		}
		if w.findings[i].VulnClass != w.findings[j].VulnClass {
			return w.findings[i].VulnClass < w.findings[j].VulnClass
		}
		return w.findings[i].URL < w.findings[j].URL
	})
}

func (w *ExploitWizard) Classes() []string {
	set := make(map[string]struct{})
	for _, finding := range w.findings {
		className := strings.TrimSpace(strings.ToLower(finding.VulnClass))
		if className == "" {
			continue
		}
		set[className] = struct{}{}
	}
	classes := make([]string, 0, len(set))
	for className := range set {
		classes = append(classes, className)
	}
	sort.Strings(classes)
	return classes
}

func (w *ExploitWizard) FindingsForClass(className string) []models.Finding {
	className = strings.TrimSpace(strings.ToLower(className))
	if className == "" {
		return []models.Finding{}
	}
	out := make([]models.Finding, 0, 16)
	for _, finding := range w.findings {
		if strings.TrimSpace(strings.ToLower(finding.VulnClass)) == className {
			out = append(out, finding)
		}
	}
	return out
}

func (w *ExploitWizard) StepsForFinding(finding *models.Finding) []exploits.ExploitStep {
	if finding == nil {
		return []exploits.ExploitStep{}
	}
	module := exploits.SelectModule(finding.VulnClass, exploits.DefaultModules())
	targetDomain := ""
	if w.target != nil {
		targetDomain = w.target.Domain
	}
	return module.Steps(targetDomain, finding, w.cfg)
}

func (w *ExploitWizard) Log(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	w.logLines = append(w.logLines, line)
	if len(w.logLines) > 200 {
		w.logLines = w.logLines[len(w.logLines)-200:]
	}
	w.viewport.SetContent(strings.Join(w.logLines, "\n"))
}

func (w *ExploitWizard) SetState(state WizardState) {
	w.state = state
}

func (w *ExploitWizard) State() WizardState {
	return w.state
}
