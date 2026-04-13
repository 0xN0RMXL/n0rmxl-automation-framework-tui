# N0RMXL

```text
███╗   ██╗ ██████╗ ██████╗ ███╗   ███╗██╗  ██╗██╗     
████╗  ██║██╔═████╗██╔══██╗████╗ ████║╚██╗██╔╝██║     
██╔██╗ ██║██║██╔██║██████╔╝██╔████╔██║ ╚███╔╝ ██║     
██║╚██╗██║████╔╝██║██╔══██╗██║╚██╔╝██║ ██╔██╗ ██║     
██║ ╚████║╚██████╔╝██║  ██║██║ ╚═╝ ██║██╔╝ ██╗███████╗
╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
```

Zero to bounty, directly from your terminal.

![Go](https://img.shields.io/badge/Go-1.22%2B%20%28module%201.26.1%29-00ADD8)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20Primary-blue)
![Build](https://img.shields.io/badge/Build-Go%20CLI%20%2B%20TUI-success)

A single Go binary for terminal-native bug bounty automation across the full 10-phase workflow, with checkpoint resume, encrypted secrets, and production-friendly reporting.

## 1. Header / Banner

N0RMXL is a TUI-first bug bounty automation framework built for real hunting workflows, not disconnected one-off scripts. You run one binary, keep one workspace per target, and move from scope setup to final report with persistent state.

Core identity:

- Name: N0RMXL Automation Framework TUI
- Module: github.com/0xN0RMXL/n0rmxl-automation-framework-tui
- Binary: n0rmxl
- License: MIT
- Primary platform: Linux (Ubuntu 22.04+ / Debian 12+)

## 2. What is N0RMXL? (Overview)

N0RMXL solves a common bug bounty problem: hunters often glue together dozens of tools with ad-hoc scripts, then lose context, results, or progress after interruptions. N0RMXL replaces that with one coherent, resumable system.

What makes it different:

- TUI-first operation: full-screen interactive workflow via Bubbletea, Lipgloss, and Bubbles.
- 10-phase methodology alignment: phases 0 through 9 map to a complete hunting lifecycle.
- Persistent state: SQLite databases keep checkpoints and findings durable across restarts.
- Single binary deployment: straightforward installation and execution model.
- Built-in operational controls: stealth profiles, background installer, vault-based secret handling.
- Automation with operator control: phase 6 is guided exploitation, not blind escalation.

Who it is for:

- Beginners: guided flow, structured outputs, less setup friction.
- Advanced hunters: orchestration speed, reproducible output, campaign and headless operation.

Design philosophy:

- Keep execution practical and safe.
- Keep data structured and queryable.
- Keep long-running work resumable.
- Keep UI responsive while jobs run.

## 3. Screenshots / Demo

Place screenshots or terminal GIFs in this section. Recommended captures:

| Screenshot | What it should show |
|---|---|
| Splash screen | Startup identity and theme language |
| Dashboard | Live findings table with severity distribution |
| Phase runner | Job progress, streaming logs, and throughput |
| Exploit wizard | Guided phase 6 workflow for a selected finding |
| Report viewer | Rendered report content from stored findings |


## 4. Features Overview

### Reconnaissance

- Passive recon from many sources (subdomains, certificates, archives, APIs, source-code intelligence).
- Active enumeration with DNS brute-force, DNS resolution, HTTP probing, and port scanning.
- Structured per-phase output writing under a target workspace.

### Vulnerability Scanning

- Template scanning with nuclei.
- Targeted scanners for XSS, SQLi, SSRF, CORS, CRLF, host header, takeover, and more.
- Automated normalization of findings into SQLite.

### Phase 6 Exploit Wizard

- Guided interactive exploitation flow for 30+ vulnerability classes.
- Stepwise commands you can copy, edit, and execute.
- Confirmation workflow to mark confirmed, duplicate, or chained findings.

### Post-Exploitation and Impact

- Chain analysis suggestions.
- CVSS scoring support.
- Screenshot attachment and reproducible command capture.

### Cloud / Mobile / Thick Client Coverage

- Cloud misconfiguration checks and cloud template support.
- Mobile and thick-client testing guides and output scaffolding.

### Reporting

- Markdown, HTML, PDF, and executive summary outputs.
- Regeneration via CLI without re-running every phase.

### Operations and Scale

- Campaign mode for multi-target tracking and batch runs.
- Encrypted vault (AES-256-GCM, Argon2id) for secret storage.
- Slow, normal, aggressive stealth profiles.
- Checkpoint resume via SQLite.
- Telegram, Slack, Discord notifications.
- Burp Suite proxy and active scan integration paths.
- Headless mode with no-tui for CI pipelines.

### Runtime Packaging

- Single Go binary workflow.
- Linux-first behavior with practical WSL2 support on Windows.

### Complete Toolchain Inventory

<details>
<summary>Go tools (installed by installer)</summary>

pdtm, subfinder, httpx, nuclei, katana, dnsx, naabu, asnmap, uncover, tlsx, mapcidr, interactsh-client, notify, csprecon, assetfinder, chaos, github-subdomains, gitlab-subdomains, related-domains, shosubgo, puredns, shuffledns, hakrevdns, hakip2host, dnsbruter, gotator, alterx, hakrawler, subjs, gau, gauplus, hakcheckurl, urldedupe, qsreplace, fff, ffuf, kiterunner, gf, x8, dalfox, Gxss, kxss, airixss, bxss, crlfuzz, ppmap, headi, byp4xx, mantra, jsleak, subzy, graphw00f, grpc-gateway, gowitness, webanalyze, fingerprintx, originiphunter, anew, unfurl, haktrails, nrich.

</details>

<details>
<summary>Python and git-cloned tools</summary>

pip-managed tools include arjun, wafw00f, dirsearch, bbot, paramspider, trufflehog, shodan, censys, waymore, git-dumper, s3scanner, cloud_enum, subdominator, graphw00f, clairvoyance, bfac, hacker-scoper.

git-cloned tooling includes LinkFinder, SecretFinder, tplmap, Corsy, GitDorker, SSRFmap, jwt_tool, commix, massdns, cloud_enum, phpggc, lazyegg, smuggler, EyeWitness.

</details>

<details>
<summary>System packages and wordlists</summary>

System package jobs cover nmap, masscan, curl, jq, python3-pip, git, golang, ruby-dev, build-essential, sqlmap, seclists, libpcap-dev, dnsutils, whois, netcat-openbsd, wget, unzip, whatweb, amass, findomain, awscli, plus wpscan, feroxbuster, and rustscan helpers.

Wordlists and payload data include Assetnote DNS lists, trickest resolvers, SecLists web and fuzzing dictionaries, API route lists, and payload libraries cached under ~/.local/share/n0rmxl.

</details>

## 5. Requirements

| Category | Requirement |
|---|---|
| OS | Linux primary (Ubuntu 22.04+ / Debian 12+ recommended) |
| Other OS | macOS partial support, Windows via WSL2 |
| Go | 1.22+ to build from source (module target: 1.26.1) |
| Python | Python 3.10+ for Python-based tools |
| Python package managers | pip required, pipx optional but recommended for isolated CLI apps |
| Base utilities | git, curl, wget, build tooling |
| Disk | ~5GB recommended for tools + wordlists + templates |
| Memory | 8GB recommended for aggressive profile workflows |
| Optional | Burp Suite Pro/Enterprise for active scan integration |

## 6. Installation

### Method A: Pre-built binary (fastest)

For fastest setup, use the Linux amd64 pre-built artifact named n0rmxl-linux-amd64 (typically around 23MB).

If you download it from release assets:

```bash
wget https://github.com/0xN0RMXL/n0rmxl-automation-framework-tui/releases/latest/download/n0rmxl-linux-amd64
chmod +x n0rmxl-linux-amd64
sudo install -m 0755 n0rmxl-linux-amd64 /usr/local/bin/n0rmxl
n0rmxl version
```

If you already cloned this repository and want the included binary:

```bash
chmod +x bin/n0rmxl-linux-amd64
sudo install -m 0755 bin/n0rmxl-linux-amd64 /usr/local/bin/n0rmxl
n0rmxl version
```

This pre-built path avoids local compile time and is the quickest way to start scanning.

### Method B: Install with go install

```bash
go install github.com/0xN0RMXL/n0rmxl-automation-framework-tui/cmd/n0rmxl@latest
n0rmxl version
```

### Method C: Build from source

```bash
git clone https://github.com/0xN0RMXL/n0rmxl-automation-framework-tui
cd n0rmxl
go build -ldflags="-s -w" -trimpath -o bin/n0rmxl ./cmd/n0rmxl
./bin/n0rmxl version
```

### Python setup guide (do this before n0rmxl install)

N0RMXL installs many Python-based tools during `n0rmxl install`. To avoid failed installs and PATH issues, set up Python first.

#### pip vs pipx (what you actually need)

- Required: pip. The installer uses `python -m pip ...` (and falls back to `pip3 ...`) for Python tool dependencies.
- Optional: pipx. Useful for isolated CLI app installs, but not a replacement for pip in N0RMXL's installer flow.
- Recommended: install both pip and pipx, keep `python3` and `pip3` available in PATH.

#### Linux / WSL2 (recommended runtime)

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv pipx
python3 --version
python3 -m pip --version
pipx --version
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pipx ensurepath
```

If your shell cannot find user-installed CLI tools, add local bin paths:

```bash
echo 'export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### macOS (partial support)

```bash
brew install python pipx
python3 --version
python3 -m pip --version
pipx --version
python3 -m pip install --upgrade pip setuptools wheel
pipx ensurepath
```

Typical Python binary locations on macOS:

- Apple Silicon: `/opt/homebrew/bin/python3`
- Intel: `/usr/local/bin/python3`

#### Windows

Officially, run N0RMXL inside WSL2. If you still need native Python on Windows:

```powershell
winget install --id Python.Python.3.12 -e
py -3 --version
py -3 -m pip --version
py -3 -m pip install --upgrade pip setuptools wheel
```

#### Set the correct Python path in config

Find your Python path:

```bash
command -v python3
```

Set it in `~/.config/n0rmxl/config.yaml`:

```yaml
tools:
	python_bin: /usr/bin/python3
```

Common values:

- Ubuntu/Debian/WSL2: `/usr/bin/python3`
- macOS Apple Silicon: `/opt/homebrew/bin/python3`
- macOS Intel: `/usr/local/bin/python3`

#### Final Python preflight before installer

```bash
python3 --version
python3 -m pip --version
command -v python3
command -v pip3
command -v pipx || true
n0rmxl install --check
```

After installing the binary, bootstrap dependencies:

```bash
n0rmxl install
n0rmxl install --check
```

First full install typically takes around 15 minutes depending on network and package manager speed.

## 7. Quick Start (3-minute guide)

Minimal path from zero to first run:

```bash
n0rmxl install
n0rmxl vault
n0rmxl
```

Quick non-TUI phase run:

```bash
n0rmxl run example.com --phases 0,1,2 --no-tui
```

Quick preflight validation:

```bash
n0rmxl smoke example.com --preflight-only --no-tui --install=false --strict=false
```

## 8. Detailed Usage — The TUI

Default invocation launches full-screen TUI:

```bash
n0rmxl
```

### Typical flow

1. Splash: enter the interface and choose your path.
2. Dashboard: inspect current target status and findings.
3. New target: enter target domain and scope details.
4. Phase menu: pick phase set.
5. Phase runner: observe job status and live logs.
6. Findings review and exploitation flow.
7. Report view for generated artifacts.

### Screen-by-screen walkthrough

#### 1) Splash Screen

- Purpose: fast entry into scanning, campaign, installer, settings, and vault workflows.
- What you do: choose new target flow, campaign view, installer, or settings.
- What to watch: environment warnings and startup routing actions.

#### 2) Dashboard

- Purpose: central operational view for findings and run state.
- What you do: filter findings, sort by severity, jump into next actions.
- What to watch: critical/high spikes, repeated vuln classes, and target-level trends.

#### 3) Target Input Wizard

- Purpose: create a target profile with scope and run context.
- What you do: enter root domain, optional wildcard and explicit scope entries, profile defaults.
- What to watch: scope precision and accidental overbreadth before launch.

#### 4) Phase Menu

- Purpose: pick exact phases for execution.
- What you do: select phase subset for discovery-only, scanning-only, or full flow.
- What to watch: selected phase list consistency with your objective and bounty rules.

#### 5) Phase Runner

- Purpose: execute jobs with live status and log streaming.
- What you do: monitor running jobs, skipped jobs, and output progression.
- What to watch: timeouts, missing binary skips, API-limited paths, and completion summaries.

#### 6) Settings

- Purpose: operational configuration and integration control.
- What you do: manage keys, Burp, notifications, profiles, and tool health.
- What to watch: enabled channels, minimum severity thresholds, and Burp endpoint correctness.

#### 7) Campaign

- Purpose: coordinate multiple targets in one workspace root.
- What you do: review per-target status, queue runs, resume, retry failed targets.
- What to watch: run-state persistence, failed target counts, and queue depth.

#### 8) Exploit Wizard

- Purpose: guided phase 6 validation and impact proofing.
- What you do: choose vuln class, select finding, execute/edit commands, record evidence.
- What to watch: reproducibility, false positives, and chain opportunities.

#### 9) Report Viewer

- Purpose: review generated report content before submission.
- What you do: inspect markdown/html rendering and evidence completeness.
- What to watch: missing reproduction steps, weak impact narrative, absent screenshots.

### Main screens

1. Splash
2. Dashboard
3. Target Input Wizard
4. Phase Menu
5. Phase Runner
6. Settings
7. Campaign
8. Exploit Wizard
9. Report Viewer

### Settings tabs

- API Keys: unlock vault and manage secrets.
- Burp: configure API URL and proxy host/port.
- Notifications: enable channels and minimum severity.
- Profiles: switch slow, normal, aggressive.
- Tools: check installed/missing toolchain state.

Detailed behavior by tab:

- API Keys
	- Create or unlock vault session.
	- Add, rotate, or remove key entries without exposing plaintext in config files.
	- Validate that source-specific APIs are present before passive recon runs.
- Burp
	- Toggle Burp integration behavior.
	- Set API URL and proxy host/port.
	- Confirm connectivity before phase 5 active scan workflows.
- Notifications
	- Enable Telegram, Slack, Discord paths.
	- Define minimum severity threshold.
	- Verify channels can receive structured finding messages.
- Profiles
	- Switch stealth profile presets.
	- Confirm expected thread/rate behavior before launching broad scans.
- Tools
	- Run health checks for installed and missing tools.
	- Confirm prerequisite readiness before strict smoke or full phase runs.

### Navigation and control keys

- Arrow keys: move selection.
- Enter: confirm action.
- Tab: switch focus/tab.
- Esc: back/cancel.
- q: quit current view or app depending on screen state.
- Ctrl+C: interrupt foreground execution safely.

## 9. Detailed Usage — CLI Mode

### Root command

```bash
n0rmxl
n0rmxl --profile slow
n0rmxl --config /path/to/config.yaml
n0rmxl --no-tui
```

### Install and checks

```bash
n0rmxl install
n0rmxl install --check
```

### Run pipeline

```bash
n0rmxl run target.com
n0rmxl run target.com --phases 0,1,2,3,4,5,6,7,8,9 --profile slow
n0rmxl run target.com --phases 1,2 --no-tui | tee scan.log
n0rmxl run target.com --phases 5 --profile aggressive
```

### Campaign operations

```bash
n0rmxl campaign
n0rmxl campaign --run-all --phases 0,1,2 --parallel 2
n0rmxl campaign --run-all --resume --retry-failed
```

### Report and vault

```bash
n0rmxl report target.com
n0rmxl vault
n0rmxl vault --unlock
```

### Smoke and version

```bash
n0rmxl smoke target.com --preflight-only --no-tui --install=false --strict=false
n0rmxl smoke target.com --preflight-only --no-tui --install=false --strict=true
n0rmxl version
```

## 10. The 10 Phases — Complete Reference

### Phase 0 — Scope & Environment Setup

- Mode: Automatic
- What it does: bootstraps workspace, validates scope, prepares config/vault/runtime.
- Which tools and actions run:
	- Workspace initializer and directory scaffold creation.
	- Scope parsing and validation logic.
	- Provider config generation for passive recon APIs.
	- Nuclei template refresh path.
- Outputs produced:
	- scope.txt
	- .n0rmxl/checkpoint.db
	- .n0rmxl/findings.db
	- .n0rmxl/runtime.json
- Findings produced: generally none; phase focuses on readiness.
- Estimated time: 1 to 5 minutes depending on environment.
- Tips: keep scope precise before running broader phases.

### Phase 1 — Passive Recon & OSINT

- Mode: Automatic (parallel-heavy)
- What it does: collects passive host intelligence from many sources without direct target probing.
- Which tools run:
	- subfinder, assetfinder, findomain, chaos, amass passive, bbot, subdominator, haktrails.
	- crt.sh and certspotter parsing.
	- source-code discovery helpers (github-subdomains, gitlab-subdomains, dork workflows when keys are present).
	- OSINT API pulls (historical and threat intel sources where configured).
- Outputs produced:
	- recon/subs/all_subs_merged.txt
	- recon/subs/crtsh.txt
	- recon/subs/certspotter.txt
	- recon/ips/asn.txt
	- recon/ips/asn_ips.txt
- Findings produced: reconnaissance artifacts, suspicious subdomain clusters, and exposure candidates.
- Estimated time: 5 to 25 minutes based on domain size and APIs.
- Tips: add API keys to vault for deeper coverage.

### Phase 2 — Active Enumeration & Asset Discovery

- Mode: Automatic (dependency chain)
- What it does: validates live assets and expands attack surface with active probing.
- Which tools run:
	- puredns and shuffledns for brute and resolution.
	- alterx and gotator for permutation expansion.
	- dnsx for resolution normalization.
	- httpx for live HTTP probing and metadata.
	- naabu for port discovery.
	- gowitness for screenshot capture.
- Outputs produced:
	- recon/subs/final_subs.txt
	- scans/http/live_hosts.txt
	- scans/http/httpx_results.json
	- scans/ports/naabu_top1000.txt
	- screenshots/
- Findings produced: alive assets, potentially sensitive exposed services, and high-value host candidates.
- Estimated time: 10 to 45 minutes by profile and scope size.
- Tips: start with normal profile on production programs.

### Phase 3 — Fingerprinting, Tech Stack & Service Analysis

- Mode: Automatic
- What it does: fingerprints frameworks, middleware, WAFs, and service stacks.
- Which tools run:
	- whatweb, webanalyze, wafw00f.
	- fingerprintx and targeted nmap service analysis.
	- graph and API-surface identification helpers.
- Outputs produced:
	- scans/tech/whatweb.json
	- scans/tech/webanalyze.json
	- scans/tech/security_headers.json
	- scans/ports/nmap/
- Findings produced: weak header posture, exposed debug surfaces, stack-specific risk indicators.
- Estimated time: 10 to 35 minutes.
- Tips: prioritize hosts exposing admin/debug indicators.

### Phase 4 — Deep URL, API & Parameter Discovery

- Mode: Automatic
- What it does: builds deep endpoint coverage from crawlers, archives, JS analysis, and parameter discovery.
- Which tools run:
	- katana and hakrawler for active crawl expansion.
	- gau, gauplus, and archive pulls for historical coverage.
	- subjs, LinkFinder, SecretFinder, jsleak, and mantra for JS endpoint/secret mining.
	- kiterunner, ffuf, arjun, x8, paramspider, and gf patterning for API/parameter and fuzz candidate generation.
- Outputs produced:
	- recon/urls/all_urls_merged.txt
	- recon/urls/all_urls_deduped.txt
	- recon/urls/interesting/
	- recon/js/all_js_files.txt
	- recon/js/secrets/
	- recon/params/all_params.txt
	- recon/params/param_names.txt
- Findings produced: candidate attack paths for injection and logic abuse.
- Estimated time: 15 to 60 minutes depending on app complexity.
- Tips: review categorized URL buckets before phase 5 to tune targeting.

### Phase 5 — Automated Vulnerability Scanning

- Mode: Automatic
- What it does: executes template and class-focused scanners on discovered assets.
- Which tools run:
	- nuclei across severity and template subsets.
	- dalfox and related XSS helpers.
	- sqlmap for SQLi candidates.
	- CORS/CRLF/host-header/SSRF/takeover helpers.
	- optional Burp active scan API path when configured.
- Outputs produced:
	- scans/nuclei/
	- scans/burp/
	- vulns/xss/
	- vulns/sqli/
	- vulns/ssrf/
	- vulns/cors/
	- vulns/takeover/
	- .n0rmxl/findings.db
- Findings produced: severity-tagged vulnerabilities with evidence and reproducible commands.
- Estimated time: 20 minutes to multiple hours, profile-dependent.
- Tips: use slow profile for sensitive production targets and aggressive only where allowed.

### Phase 6 — Manual Exploitation Wizard

- Mode: Interactive
- What it does: provides guided exploitation sequences for 30+ vulnerability classes while keeping operator control.
- Which tools and helpers run:
	- exploit modules by vulnerability class.
	- payload and template command expansion.
	- optional proxy/Burp-aware execution path.
	- evidence capture and finding-state updates.
- Outputs produced:
	- notes/phase6_wizard_plan.md
	- notes/phase6_exploit_playbook.md
	- notes/phase6_evidence_checklist.md
	- updated records in .n0rmxl/findings.db
- Findings produced: confirmed/duplicate/chained status updates with improved impact confidence.
- Estimated time: highly variable, analyst-driven.
- Tips: prioritize critical and high findings first, then chain candidates.

### Phase 7 — Post-Exploitation & Impact Demonstration

- Mode: Semi-automatic
- What it does: validates impact paths, builds chain narratives, and strengthens report-grade evidence.
- Key actions:
	- chain analysis and impact narrative generation.
	- CVSS update and severity confidence pass.
	- screenshot capture for confirmed findings.
	- report-ready impact summary generation.
- Outputs produced:
	- reports/chains.md
	- reports/phase7_impact_summary.md
	- reports/phase7_cvss_summary.md
	- screenshots/confirmed/
- Findings produced: better prioritized and better justified findings.
- Estimated time: 10 to 40 minutes plus manual verification.
- Tips: keep evidence concise and reproducible for faster triage acceptance.

### Phase 8 — Cloud, Mobile & Thick Client Testing

- Mode: Semi-automatic
- What it does: extends coverage into cloud exposures plus mobile/thick-client workflow scaffolding.
- Which tools and guides run:
	- cloud enum and cloud storage checks.
	- cloud-focused template scans.
	- mobile endpoint extraction and testing guide generation.
	- thick-client analysis guide generation.
- Outputs produced:
	- vulns/cloud/
	- scans/mobile/testing_guide.md
	- scans/thick_client/testing_guide.md
	- recon/urls/mobile_endpoints.txt
- Findings produced: cloud misconfig and cross-surface risk candidates.
- Estimated time: 10 to 45 minutes baseline, more for manual validation.
- Tips: keep cloud checks scoped to authorized org assets.

### Phase 9 — Report Writing & Bounty Collection

- Mode: Automatic
- What it does: renders final report artifacts from findings database state.
- Which report generators run:
	- markdown renderer.
	- html renderer.
	- pdf renderer with fallback behavior when dependencies differ by host.
	- executive summary formatter.
- Outputs produced:
	- reports/report.md
	- reports/report.html
	- reports/report.pdf
	- reports/executive_summary.md
- Findings produced: none new; this phase packages and presents evidence.
- Estimated time: under 5 minutes in most runs.
- Tips: rerun this phase after manual confirmation updates to refresh deliverables.

## 11. Stealth Profiles

Stealth profile values are part of runtime scheduling and scanner tuning.

| Setting | slow | normal | aggressive |
|---|---:|---:|---:|
| Threads | 5 | 50 | 200 |
| Rate limit (rps) | 10 | 100 | unlimited |
| DNS resolvers | trusted | all | all |
| Nuclei rate (rps) | 5 | 50 | 150 |
| nmap timing | T1 | T3 | T4 |
| Delay between jobs | 5s | 1s | 0s |
| Rotate User-Agent | yes | yes | no |
| Randomize job order | yes | no | no |

When to use each profile:

- slow: stealth-sensitive production targets.
- normal: default bug bounty usage.
- aggressive: high-permission or speed-priority contexts.

## 12. Configuration Reference

Default config location:

```text
~/.config/n0rmxl/config.yaml
```

Config override environment variable:

```bash
export N0RMXL_CONFIG=/path/to/custom-config.yaml
```

Annotated example:

```yaml
version: "1"
workspace_root: ~/bounty
vault_path: ~/.config/n0rmxl/vault.enc
stealth_profile: normal
screenshot_tool: gowitness

burp:
	enabled: false
	api_url: http://127.0.0.1:1337
	proxy_host: 127.0.0.1
	proxy_port: 8080

notify:
	min_severity: high
	telegram:
		enabled: false
	slack:
		enabled: false
	discord:
		enabled: false

tools:
	go_bin: ~/go/bin
	python_bin: /usr/bin/python3
	git_clones: ~/.local/share/n0rmxl/tools

wordlists:
	dns_large: ~/.local/share/n0rmxl/wordlists/dns/best-dns-wordlist.txt
	dns_medium: ~/.local/share/n0rmxl/wordlists/dns/commonspeak2-subdomains.txt
	dns_small: ~/.local/share/n0rmxl/wordlists/dns/best-dns-wordlist.txt
	dir_large: ~/.local/share/n0rmxl/wordlists/web/raft-large-directories.txt
	dir_medium: ~/.local/share/n0rmxl/wordlists/web/raft-medium-directories.txt
	files_large: ~/.local/share/n0rmxl/wordlists/web/raft-large-files.txt
	params: ~/.local/share/n0rmxl/wordlists/params/burp-parameter-names.txt
	lfi: ~/.local/share/n0rmxl/wordlists/fuzzing/LFI-Jhaddix.txt
	xss: ~/.local/share/n0rmxl/wordlists/fuzzing/XSS-Jhaddix.txt
	resolvers: ~/.local/share/n0rmxl/wordlists/dns/resolvers.txt
	api_routes: ~/.local/share/n0rmxl/wordlists/api/api-routes.txt
```

Field reference:

| Key | Purpose |
|---|---|
| workspace_root | Root folder where target subdirectories are created |
| vault_path | Encrypted secrets file path |
| stealth_profile | Global runtime profile default |
| burp.enabled | Enables Burp-aware integration behavior |
| notify.min_severity | Notification threshold filter |
| tools.* | Binary and clone roots used by installer/runtime |
| wordlists.* | Wordlist locations used in discovery and fuzzing jobs |

## 13. API Keys & Vault Setup

The vault prevents plaintext secret sprawl while keeping workflows practical.

Encryption design:

- Cipher: AES-256-GCM
- Key derivation: Argon2id
- File: ~/.config/n0rmxl/vault.enc

Create or unlock the vault:

```bash
n0rmxl vault
```

Unlock and inject environment variables into current session context:

```bash
n0rmxl vault --unlock
```

Important key groups to maintain:

- Recon and source APIs: shodan, censys_id, censys_secret, virustotal, chaos, github_token, securitytrails, binaryedge, hunter.
- Notifications: telegram_bot_token, telegram_chat_id, slack_webhook, discord_webhook.
- Burp: burp_api_key where API auth is required.

Where to get keys:

- Telegram: @BotFather for bot token, chat ID via bot interaction lookup.
- Slack: incoming webhook from workspace app settings.
- Discord: channel webhooks under Integrations.
- GitHub token: Personal Access Token from developer settings.
- Security APIs: account dashboards for each provider.

If the vault is locked or keys are absent, key-dependent jobs skip gracefully with reduced coverage.

## 14. Notifications Setup

Enable notification channels in config, then store credentials in vault.

### Telegram setup

1. Create a bot with BotFather.
2. Get token and destination chat ID.
3. Enable telegram in config and store secrets in vault.

### Slack setup

1. Create incoming webhook URL in Slack app settings.
2. Enable slack in config.
3. Store webhook in vault.

### Discord setup

1. Create webhook on target channel.
2. Enable discord in config.
3. Store webhook in vault.

Severity filtering:

- Set notify.min_severity to critical, high, medium, low, or info.

Notification payload pattern includes:

- Severity
- Title
- Target/URL/parameter/tool
- CVSS and payload context where available

## 15. Burp Suite Integration

N0RMXL supports two integration modes.

### Proxy routing mode

- Configure Burp proxy host and port in Settings > Burp or config.
- Jobs can route HTTP(S) through Burp for interception.

### API mode

- Configure Burp API URL (default http://127.0.0.1:1337).
- N0RMXL can trigger scans, poll status, and pull issues for findings normalization.
- Burp scan integration aligns primarily with phase 5.

Quick configuration baseline:

```yaml
burp:
	enabled: true
	api_url: http://127.0.0.1:1337
	proxy_host: 127.0.0.1
	proxy_port: 8080
```

Connection test workflow:

- Open Settings > Burp.
- Verify host/port/API URL.
- Run a health check and confirm reachable endpoint.

## 16. Workspace & Output Files

Each target uses a dedicated workspace under:

```text
~/bounty/<target>/
```

Annotated structure:

```text
~/bounty/example.com/
├── .n0rmxl/
│   ├── checkpoint.db                # SQLite: phase and tool completion state
│   ├── findings.db                  # SQLite: normalized findings + evidence metadata
│   ├── config.yaml                  # Target-specific resolved runtime config
│   └── runtime.json                 # Session/runtime metadata
├── scope.txt                        # Scope definition
├── recon/
│   ├── subs/
│   │   ├── subfinder.txt
│   │   ├── assetfinder.txt
│   │   ├── crtsh.txt
│   │   ├── all_subs_merged.txt      # phase 1 merged/deduped set
│   │   └── final_subs.txt           # phase 2 resolved set
│   ├── ips/
│   │   ├── asn.txt
│   │   ├── asn_ips.txt
│   │   └── rdns.txt
│   ├── urls/
│   │   ├── all_urls_merged.txt
│   │   ├── all_urls_deduped.txt
│   │   └── interesting/
│   │       ├── sqli.txt
│   │       ├── xss.txt
│   │       ├── ssrf.txt
│   │       ├── lfi.txt
│   │       ├── idor.txt
│   │       ├── redirect.txt
│   │       ├── rce.txt
│   │       └── ssti.txt
│   ├── js/
│   │   ├── all_js_files.txt
│   │   ├── js_endpoints.txt
│   │   └── secrets/
│   ├── params/
│   │   ├── all_params.txt
│   │   └── param_names.txt
│   └── interesting/
├── scans/
│   ├── http/
│   │   ├── live_hosts.txt
│   │   └── httpx_results.json
│   ├── ports/
│   │   ├── naabu_top1000.txt
│   │   └── nmap/
│   ├── nuclei/
│   ├── tech/
│   ├── burp/
│   ├── fuzz/
│   │   ├── dirs/
│   │   └── vhosts/
│   ├── mobile/
│   └── thick_client/
├── vulns/
│   ├── xss/
│   ├── sqli/
│   ├── ssrf/
│   ├── cors/
│   ├── jwt/
│   ├── takeover/
│   ├── cloud/
│   ├── smuggling/
│   └── misc/
├── loot/
│   ├── credentials/
│   │   ├── candidates.txt
│   │   └── valid_creds.txt
│   └── git_dumps/
├── screenshots/
│   └── confirmed/                   # proof screenshots for confirmed findings
├── notes/
│   ├── phase6_wizard_plan.md
│   ├── phase6_exploit_playbook.md
│   └── phase6_evidence_checklist.md
└── reports/
	├── report.md
	├── report.html
	├── report.pdf
	├── executive_summary.md
	├── chains.md
	├── phase7_impact_summary.md
	└── phase7_cvss_summary.md
```

Checkpoint and findings notes:

- checkpoint.db stores phase and tool progress for resume behavior.
- findings.db stores normalized findings with severity, CVSS, evidence, remediation, and metadata.

Useful sqlite inspection examples:

```bash
sqlite3 ~/bounty/example.com/.n0rmxl/checkpoint.db "SELECT phase, status, updated_at FROM phase_status ORDER BY phase;"
sqlite3 ~/bounty/example.com/.n0rmxl/checkpoint.db "SELECT phase, tool_name, status, items_found FROM tool_status ORDER BY phase, tool_name LIMIT 50;"
```

## 17. Findings Database

Primary finding fields include:

- ID
- Phase
- VulnClass
- Target
- Host
- URL
- Method
- Parameter
- Payload
- Severity
- CVSS
- Title
- Description
- Evidence
- CurlCmd
- Screenshot
- Tool
- Timestamp
- Tags
- Remediation
- Confirmed
- Duplicate
- ChainedWith

Quick sqlite query example:

```bash
sqlite3 ~/bounty/example.com/.n0rmxl/findings.db \
"SELECT severity, vuln_class, url \
 FROM findings \
 ORDER BY CASE severity \
	 WHEN 'critical' THEN 0 \
	 WHEN 'high' THEN 1 \
	 WHEN 'medium' THEN 2 \
	 WHEN 'low' THEN 3 \
	 ELSE 4 END, cvss DESC;"
```

Useful follow-up queries:

```bash
sqlite3 ~/bounty/example.com/.n0rmxl/findings.db \
"SELECT vuln_class, COUNT(*) FROM findings GROUP BY vuln_class ORDER BY COUNT(*) DESC;"

sqlite3 ~/bounty/example.com/.n0rmxl/findings.db \
"SELECT id, title, severity, confirmed FROM findings WHERE confirmed=1;"
```

## 18. Reports

Phase 9 renders report artifacts from findings database state.

Generated files:

1. reports/report.md
2. reports/report.html
3. reports/report.pdf
4. reports/executive_summary.md

Regenerate reports without rerunning all phases:

```bash
n0rmxl report example.com
```

Report content includes:

- Executive summary
- Scope and methodology
- Severity and class distributions
- Reproducible findings with evidence
- Remediation guidance

Submission tips for HackerOne/Bugcrowd style workflows:

- Keep each finding independently reproducible.
- Include impact-focused narrative before payload detail.
- Attach concise screenshots and curl proof blocks.

## 19. Resume & Checkpoint System

Resume logic is based on checkpoint data under each target workspace.

How it works:

- Phase and tool status are persisted continuously.
- Re-running the same target skips completed work where applicable.
- You can rerun selected phases with explicit phase flags.

Examples:

```bash
n0rmxl run example.com --phases 5
n0rmxl run example.com --phases 0,1,2 --no-tui
```

Force a full restart for one target:

```bash
rm -rf ~/bounty/example.com/.n0rmxl
```

## 20. Phase 6 Exploit Wizard — Deep Dive

Phase 6 is designed for guided exploitation with human judgment in the loop.

Launch paths:

```bash
n0rmxl
n0rmxl run example.com --phases 6
```

Core interaction loop:

1. Select vulnerability class.
2. Select candidate finding.
3. Review step-by-step command set.
4. Edit payloads/commands where needed.
5. Execute and capture evidence.
6. Mark finding confirmed, duplicate, or chained.

Covered vulnerability classes include:

- SQL injection
- XSS (reflected, stored, DOM, blind)
- SSRF
- LFI/path traversal
- IDOR
- JWT attacks
- XXE
- SSTI
- CORS misconfiguration
- HTTP request smuggling
- GraphQL attacks
- Race conditions
- OAuth flow abuse
- File upload bypass
- Subdomain takeover
- Command injection
- Deserialization
- WebSocket abuse
- S3/cloud misconfiguration
- Business logic flaws
- Host header injection
- Prototype pollution
- Dependency confusion
- Web cache poisoning
- Clickjacking
- Open redirect
- Information disclosure
- PostMessage abuse
- CSRF testing patterns
- Miscellaneous class templates

Per-class quick guidance:

| Class | Focus | Practical tip |
|---|---|---|
| SQL injection | DB query manipulation and extraction risk | Start with low-risk confirm payloads before deep dumps |
| XSS | Browser-side script execution | Test reflected first, then stored and DOM paths |
| SSRF | Internal network and metadata access | Validate callbacks and metadata endpoints carefully |
| LFI/path traversal | Arbitrary file read paths | Compare baseline and payload response sizes |
| IDOR | Authorization bypass on object references | Use two-account test design for clean proof |
| JWT attacks | Token validation and signing weaknesses | Preserve original token and log each mutation |
| XXE | XML parser external entity abuse | Include safe blind proof before escalating claims |
| SSTI | Server template engine code paths | Confirm engine behavior with harmless math probes |
| CORS | Cross-origin trust misconfiguration | Prove credentialed read impact with concise PoC |
| Request smuggling | Front/back-end parser mismatch | Capture timing and differential response evidence |
| GraphQL attacks | Query schema abuse and auth gaps | Map schema exposure before auth bypass attempts |
| Race conditions | Concurrent request state corruption | Use repeatable burst tests with clear success criteria |
| OAuth abuse | Flow and redirect weaknesses | Document full auth flow and redirect logic chain |
| File upload bypass | Content/type/extension validation bypass | Preserve original upload and transformed payload evidence |
| Subdomain takeover | Dangling DNS claimability | Show claim proof with hosted artifact and screenshot |
| Command injection | Shell meta-character execution paths | Prefer non-destructive command probes |
| Deserialization | Unsafe object parsing behavior | Identify framework and gadget family before payloading |
| WebSocket abuse | Real-time channel auth/state flaws | Capture handshake plus message replay evidence |
| S3/cloud misconfig | Public bucket/object policy flaws | Record exact ACL/policy state and object access proof |
| Business logic | Workflow and rule bypass | Reproduce with minimal request set and clear impact |
| Host header injection | Trust boundary issues in host headers | Validate password-reset and absolute-link abuse |
| Prototype pollution | Client/server object mutation | Demonstrate polluted key propagation and effect |
| Dependency confusion | Package namespace hijack risk | Prove naming overlap without publishing malicious packages |
| Web cache poisoning | Cache key and response contamination | Capture cache hit sequence showing poisoned response |
| Clickjacking | UI embedding and frame-control gaps | Add a minimal iframe PoC and header proof |
| Open redirect | Redirect target control | Show post-auth or trust-boundary impact, not just redirect |
| Information disclosure | Sensitive data leakage | Tie leaked data directly to exploitability |
| PostMessage abuse | Insecure cross-window message handling | Demonstrate origin check weakness with controlled sender |
| CSRF patterns | State-changing request forgery | Verify token absence or validation bypass path |
| Misc templates | Edge-case class coverage | Use this bucket for structured follow-up, not noise |

Artifacts generated during phase 6 workflows commonly include:

- notes/phase6_wizard_plan.md
- notes/phase6_exploit_playbook.md
- notes/phase6_evidence_checklist.md

Practical tips:

- Prioritize critical and high findings first.
- Save reproducible command history for each confirmed issue.
- Capture a screenshot and response proof for every accepted finding.

## 21. Campaign Mode — Multi-Target Operations

Campaign mode helps you operate across many targets with shared visibility.

Preparation pattern:

- Place one target directory under workspace root for each target.
- Ensure each target has scope and baseline setup.

CLI usage:

```bash
n0rmxl campaign
n0rmxl campaign --run-all --phases 0,1,2 --parallel 2
n0rmxl campaign --run-all --resume --retry-failed
n0rmxl campaign --show-state
```

State file behavior:

- Default: ~/.local/share/n0rmxl/campaign_state.json
- Supports resume, failed-target retries, and queue limiting.

Campaign table tracks target, phase progress, status, findings totals, and severity counts.

## 22. Headless / CI Mode

Use no-tui mode for automation pipelines and scheduled jobs.

Examples:

```bash
n0rmxl run target.com --phases 0,1,2,3,4,5 --no-tui --profile normal 2>&1 | tee scan.log

n0rmxl smoke target.com --preflight-only --no-tui --install=false --strict=true

n0rmxl install --check
```

Repository Makefile pipeline helpers:

```bash
make build
make test
make test-race
make smoke-strict
make ci
```

GitHub Actions style example:

```yaml
name: n0rmxl-ci
on: [push, pull_request]
jobs:
	validate:
		runs-on: ubuntu-latest
		steps:
			- uses: actions/checkout@v4
			- uses: actions/setup-go@v5
				with:
					go-version: '1.26.1'
			- run: go build ./...
			- run: go vet ./...
			- run: go test -count=1 -timeout 180s ./...
			- run: go test -race -count=1 -timeout 180s ./...
			- run: go run ./cmd/n0rmxl smoke --preflight-only --no-tui --install=false --strict=true --target example.com --phases 0
```

## 23. Extending N0RMXL

### Add installer tools

Tool registries live in:

- internal/installer/go_tools.go
- internal/installer/python_tools.go
- internal/installer/system_tools.go
- internal/installer/wordlists.go

Add a tool by defining job metadata, check behavior, and install function.

### Add or adjust phase jobs

- Phase mapping entrypoint: internal/phases/registry.go
- Each phase package exposes a Jobs function returning engine jobs.
- Keep jobs small, focused, and output-path deterministic.

### Customize wordlists and scope

- Override wordlist paths in config.yaml.
- Define wildcard/explicit/IP/out-of-scope boundaries in target scope data.

### Extend findings and reports

- Finding model: internal/models/finding.go
- DB persistence: internal/models/db.go
- Report generation: phase 9 report pipeline packages.

## 24. Troubleshooting

### Tool not found

```bash
n0rmxl install --check
echo $PATH
```

Ensure Go bin path and installed tool paths are available in runtime environment.

### Installer failures

- Confirm Go and Python versions.
- Confirm package manager permissions.
- Re-run install for idempotent recovery.

### Python tools fail to install

- Verify Python binary path in config (`tools.python_bin`) matches `command -v python3`.
- Confirm pip works directly: `python3 -m pip --version`.
- Upgrade packaging stack: `python3 -m pip install --upgrade pip setuptools wheel`.
- Ensure CLI paths are exported: `~/.local/bin` and `~/go/bin` in PATH.
- Re-run `n0rmxl install --check`, then `n0rmxl install`.
- On Ubuntu 23.04+/Debian 12+, externally-managed Python may require installer pip flags; N0RMXL already uses pip compatibility flags, so ensure you are using the project installer commands unchanged.

### Vault unlock issues

- Wrong passphrase returns decrypt failure.
- Restore from backup or create a new vault if recovery is not possible.

### Phase appears stalled

- Use Ctrl+C to stop.
- Resume with the same run command and selected phases.
- Check logs under data dir for recent errors.

### Nuclei templates out of date

```bash
nuclei -update-templates
```

### Low finding volume

- Verify API keys in vault.
- Re-run installer health checks.
- Re-run discovery with broader phase set.
- Use aggressive profile only when scope and target policy allow.

### SQLite errors

- Check free disk space.
- Ensure workspace is writable.
- Remove target .n0rmxl state only when a reset is acceptable.

### Burp proxy integration problems

- Confirm Burp is running and listening on configured host:port.
- Verify Burp API URL if using API mode.
- Test with a small run first.

## 25. Contributing

Contributions are welcome across tooling, exploit modules, reporting, and stability.

Typical flow:

```bash
git clone https://github.com/0xN0RMXL/n0rmxl-automation-framework-tui
cd n0rmxl
make build
make test
make ci
```

Contribution priorities:

- New tool integrations with robust fallback behavior.
- New phase 6 exploit modules and better evidence workflows.
- Better wordlists and discovery categorization.
- Performance and reliability improvements.
- Test coverage and deterministic pipeline behavior.

Quality expectations:

- Standard Go style and formatting.
- Keep modules cohesive and testable.
- Avoid introducing unsafe or destructive behavior.

## 26. Legal Disclaimer

N0RMXL is for authorized security testing and bug bounty programs only.

- Always verify scope and permissions before running any scan.
- Never run against targets without explicit authorization.
- Prefer the slow profile on production systems unless policy allows otherwise.
- Use this framework for education, validation, and approved security assessment.
- The authors and contributors are not responsible for misuse.

Use responsibly, report ethically, and respect program rules.

