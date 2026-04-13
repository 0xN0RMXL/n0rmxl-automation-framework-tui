package models

import (
	"os"
	"path/filepath"
	"strings"
)

type Workspace struct {
	Root             string
	Hidden           string
	CheckpointDB     string
	FindingsDB       string
	ConfigFile       string
	RuntimeFile      string
	Recon            string
	ReconSubs        string
	ReconIPs         string
	ReconURLs        string
	ReconJS          string
	ReconParams      string
	ReconInteresting string
	Scans            string
	ScansPorts       string
	ScansHTTP        string
	ScansTech        string
	ScansNuclei      string
	ScansBurp        string
	ScansFuzz        string
	Vulns            string
	Loot             string
	Screenshots      string
	Reports          string
	Notes            string
}

func NewWorkspace(rootDir string, domain string) Workspace {
	safeDomain := sanitizeDomain(domain)
	root := filepath.Join(expandHome(rootDir), safeDomain)
	hidden := filepath.Join(root, ".n0rmxl")
	recon := filepath.Join(root, "recon")
	scans := filepath.Join(root, "scans")

	return Workspace{
		Root:             root,
		Hidden:           hidden,
		CheckpointDB:     filepath.Join(hidden, "checkpoint.db"),
		FindingsDB:       filepath.Join(hidden, "findings.db"),
		ConfigFile:       filepath.Join(hidden, "config.yaml"),
		RuntimeFile:      filepath.Join(hidden, "runtime.json"),
		Recon:            recon,
		ReconSubs:        filepath.Join(recon, "subs"),
		ReconIPs:         filepath.Join(recon, "ips"),
		ReconURLs:        filepath.Join(recon, "urls"),
		ReconJS:          filepath.Join(recon, "js"),
		ReconParams:      filepath.Join(recon, "params"),
		ReconInteresting: filepath.Join(recon, "interesting"),
		Scans:            scans,
		ScansPorts:       filepath.Join(scans, "ports"),
		ScansHTTP:        filepath.Join(scans, "http"),
		ScansTech:        filepath.Join(scans, "tech"),
		ScansNuclei:      filepath.Join(scans, "nuclei"),
		ScansBurp:        filepath.Join(scans, "burp"),
		ScansFuzz:        filepath.Join(scans, "fuzz"),
		Vulns:            filepath.Join(root, "vulns"),
		Loot:             filepath.Join(root, "loot"),
		Screenshots:      filepath.Join(root, "screenshots"),
		Reports:          filepath.Join(root, "reports"),
		Notes:            filepath.Join(root, "notes"),
	}
}

func (w Workspace) EnsureAll() error {
	dirs := []string{
		w.Root,
		w.Hidden,
		w.Recon,
		w.ReconSubs,
		w.ReconIPs,
		w.ReconURLs,
		w.ReconJS,
		w.ReconParams,
		w.ReconInteresting,
		w.Scans,
		w.ScansPorts,
		w.ScansHTTP,
		w.ScansTech,
		w.ScansNuclei,
		w.ScansBurp,
		w.ScansFuzz,
		w.Vulns,
		w.Loot,
		w.Screenshots,
		w.Reports,
		w.Notes,
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func (w Workspace) VulnDir(class string) string {
	return filepath.Join(w.Vulns, strings.ToLower(strings.TrimSpace(class)))
}

func sanitizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.ReplaceAll(d, "*", "wildcard")
	d = strings.ReplaceAll(d, " ", "-")
	d = strings.ReplaceAll(d, "/", "-")
	d = strings.ReplaceAll(d, "\\", "-")
	if d == "" {
		return "unknown-target"
	}
	return d
}

func expandHome(path string) string {
	if path == "" {
		return path
	}
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return strings.TrimPrefix(path, "~")
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/"))
}
