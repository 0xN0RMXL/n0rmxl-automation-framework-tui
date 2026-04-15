package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
)

type goToolSpec struct {
	name        string
	importPath  string
	binary      string
	description string
}

var goTools = []goToolSpec{
	{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "subfinder", "Fast passive subdomain enumeration"},
	{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest", "httpx", "Fast HTTP probing toolkit"},
	{"nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "nuclei", "Template-based vulnerability scanner"},
	{"katana", "github.com/projectdiscovery/katana/cmd/katana@latest", "katana", "Modern crawling and spidering framework"},
	{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "dnsx", "DNS toolkit with resolver support"},
	{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "naabu", "Fast TCP port scanner"},
	{"alterx", "github.com/projectdiscovery/alterx/cmd/alterx@latest", "alterx", "Subdomain permutation generator"},
	{"asnmap", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest", "asnmap", "ASN and network mapping"},
	{"uncover", "github.com/projectdiscovery/uncover/cmd/uncover@latest", "uncover", "Search engine based host discovery"},
	{"tlsx", "github.com/projectdiscovery/tlsx/cmd/tlsx@latest", "tlsx", "TLS metadata extraction"},
	{"cdncheck", "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest", "cdncheck", "CDN detection helper"},
	{"interactsh-client", "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest", "interactsh-client", "Out-of-band interaction client"},
	{"shuffledns", "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", "shuffledns", "High-speed DNS bruteforcing"},
	{"mapcidr", "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest", "mapcidr", "CIDR and IP range tooling"},
	{"notify", "github.com/projectdiscovery/notify/cmd/notify@latest", "notify", "Cross-channel notifications"},
	{"pdtm", "github.com/projectdiscovery/pdtm/cmd/pdtm@latest", "pdtm", "ProjectDiscovery tool manager"},
	{"assetfinder", "github.com/tomnomnom/assetfinder@latest", "assetfinder", "Related domain discovery"},
	{"waybackurls", "github.com/tomnomnom/waybackurls@latest", "waybackurls", "URL extraction from Wayback"},
	{"anew", "github.com/tomnomnom/anew@latest", "anew", "Deduplicate and append lines"},
	{"gf", "github.com/tomnomnom/gf@latest", "gf", "Pattern wrapper around grep"},
	{"unfurl", "github.com/tomnomnom/unfurl@latest", "unfurl", "URL parser and component extractor"},
	{"qsreplace", "github.com/tomnomnom/qsreplace@latest", "qsreplace", "Query string value replacement"},
	{"urinteresting", "github.com/tomnomnom/hacks/urinteresting@latest", "urinteresting", "Interesting URL filter"},
	{"gau", "github.com/lc/gau/v2/cmd/gau@latest", "gau", "URL aggregation from archival sources"},
	{"gauplus", "github.com/bp0lr/gauplus@latest", "gauplus", "Enhanced gau URL collection"},
	{"subjs", "github.com/lc/subjs@latest", "subjs", "JavaScript URL harvesting"},
	{"hakrawler", "github.com/hakluke/hakrawler@latest", "hakrawler", "Simple crawler"},
	{"gospider", "github.com/jaeles-project/gospider@latest", "gospider", "Fast recursive web spider"},
	{"puredns", "github.com/d3mondev/puredns/v2@latest", "puredns", "DNS resolver with wildcard filtering"},
	{"hakrevdns", "github.com/hakluke/hakrevdns@latest", "hakrevdns", "Reverse DNS lookups"},
	{"hakip2host", "github.com/hakluke/hakip2host@latest", "hakip2host", "IP-to-hostname mapping"},
	{"gotator", "github.com/Josue87/gotator@latest", "gotator", "Wordlist permutations"},
	{"haktrails", "github.com/hakluke/haktrails@latest", "haktrails", "SecurityTrails API client"},
	{"github-subdomains", "github.com/gwen001/github-subdomains@latest", "github-subdomains", "GitHub code-search subdomain discovery"},
	{"gitlab-subdomains", "github.com/gwen001/gitlab-subdomains@latest", "gitlab-subdomains", "GitLab code-search subdomain discovery"},
	{"csprecon", "github.com/edoardottt/csprecon/cmd/csprecon@latest", "csprecon", "CSP header-based recon"},
	{"shosubgo", "github.com/incogbyte/shosubgo@latest", "shosubgo", "Shodan-driven subdomain discovery"},
	{"originiphunter", "github.com/rix4uni/originiphunter@latest", "originiphunter", "Origin IP discovery behind CDN"},
	{"dalfox", "github.com/hahwul/dalfox/v2@latest", "dalfox", "XSS scanner"},
	{"Gxss", "github.com/KathanP19/Gxss@latest", "Gxss", "Reflected parameter detector"},
	{"kxss", "github.com/Emoe/kxss@latest", "kxss", "Interesting character reflection detector"},
	{"airixss", "github.com/ferreiraklet/airixss@latest", "airixss", "XSS helper"},
	{"crlfuzz", "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest", "crlfuzz", "CRLF injection scanner"},
	{"ppmap", "github.com/kleiton0x00/ppmap@latest", "ppmap", "Prototype pollution mapper"},
	{"byp4xx", "github.com/lobuhi/byp4xx@latest", "byp4xx", "HTTP 40x bypass helper"},
	{"subzy", "github.com/PentestPad/subzy@latest", "subzy", "Subdomain takeover checker"},
	{"ffuf", "github.com/ffuf/ffuf/v2@latest", "ffuf", "Content discovery fuzzer"},
	{"gobuster", "github.com/OJ/gobuster/v3@latest", "gobuster", "Directory and DNS bruteforce tool"},
	{"webanalyze", "github.com/rverton/webanalyze/cmd/webanalyze@latest", "webanalyze", "Technology fingerprinting"},
	{"fingerprintx", "github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest", "fingerprintx", "Service fingerprinting"},
	{"jsleak", "github.com/channyein1337/jsleak@latest", "jsleak", "JavaScript secrets discovery"},
	{"amass", "github.com/owasp-amass/amass/v4/cmd/amass@latest", "amass", "OWASP Amass DNS enumeration"},
}

func RegisterGoTools(i *Installer) {
	cfg := i.cfg

	for _, t := range goTools {
		tool := t
		if strings.TrimSpace(tool.importPath) == "" {
			continue
		}
		i.Register(&ToolJob{
			Name:        tool.name,
			Category:    "go",
			Description: tool.description,
			Required:    false,
			CheckFunc:   goToolCheckFunc(tool.binary, cfg),
			InstallFunc: func(ctx context.Context, job *ToolJob) error {
				return installGoTool(ctx, tool.importPath, cfg)
			},
		})
	}

	i.Register(&ToolJob{
		Name:        "urldedupe",
		Category:    "go",
		Description: "URL deduplication utility",
		Required:    false,
		CheckFunc:   goToolCheckFunc("urldedupe", cfg),
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			return buildAndInstallFromGit(ctx, "https://github.com/ameenmaali/urldedupe.git", "urldedupe", cfg)
		},
	})

	i.Register(&ToolJob{
		Name:        "related-domains",
		Category:    "go",
		Description: "Related domain discovery",
		Required:    false,
		CheckFunc:   goToolCheckFunc("related-domains", cfg),
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			return buildAndInstallFromGit(ctx, "https://github.com/gwen001/related-domains.git", "related-domains", cfg)
		},
	})

	i.Register(&ToolJob{
		Name:        "bxss",
		Category:    "go",
		Description: "Blind XSS injector",
		Required:    false,
		CheckFunc:   goToolCheckFunc("bxss", cfg),
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			return buildAndInstallFromGit(ctx, "https://github.com/ethicalhackingplayground/bxss.git", "bxss", cfg)
		},
	})

	i.Register(&ToolJob{
		Name:        "mantra",
		Category:    "go",
		Description: "Secrets and URL extraction",
		Required:    false,
		CheckFunc:   goToolCheckFunc("mantra", cfg),
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			if err := installGoTool(ctx, "github.com/brosck/mantra@latest", cfg); err == nil {
				return nil
			}
			return buildAndInstallFromGit(ctx, "https://github.com/MrEmpy/mantra.git", "mantra", cfg)
		},
	})

	i.Register(&ToolJob{
		Name:        "kiterunner",
		Category:    "go",
		Description: "API route discovery",
		Required:    false,
		CheckFunc: func() bool {
			return goToolCheckFunc("kr", cfg)() || goToolCheckFunc("kiterunner", cfg)()
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			return installKiterunner(ctx, cfg)
		},
	})

	i.Register(&ToolJob{
		Name:        "headi",
		Category:    "go",
		Description: "Header injection scanner",
		Required:    false,
		CheckFunc:   goToolCheckFunc("headi", cfg),
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			if err := installGoTool(ctx, "github.com/mlcsec/headi@latest", cfg); err == nil {
				return nil
			}
			if err := installGoTool(ctx, "github.com/mlcsec/headi@v0.0.0-20240627112013-3ae1f741321a", cfg); err == nil {
				return nil
			}
			return buildAndInstallFromGitWithGoFlags(ctx, "https://github.com/mlcsec/headi.git", "headi", cfg, []string{"GOFLAGS=-mod=mod"})
		},
	})

	i.Register(&ToolJob{
		Name:        "h2csmuggler",
		Category:    "go",
		Description: "HTTP/2 request smuggling helper",
		Required:    false,
		CheckFunc:   goToolCheckFunc("h2csmuggler", cfg),
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			if err := installGoTool(ctx, "github.com/BishopFox/h2csmuggler@latest", cfg); err == nil {
				return nil
			}
			return buildAndInstallFromGitWithGoFlags(ctx, "https://github.com/BishopFox/h2csmuggler.git", "h2csmuggler", cfg, []string{"GOTOOLCHAIN=auto"})
		},
	})

	i.Register(&ToolJob{
		Name:        "gowitness",
		Category:    "go",
		Description: "Web screenshot capture utility",
		Required:    false,
		CheckFunc:   goToolCheckFunc("gowitness", cfg),
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			if err := installGoTool(ctx, "github.com/sensepost/gowitness@latest", cfg); err == nil {
				return nil
			}
			if err := installGoTool(ctx, "github.com/sensepost/gowitness@v2.5.1", cfg); err == nil {
				job.Output = "installed gowitness v2.5.1 fallback"
				return nil
			}
			return buildAndInstallFromGit(ctx, "https://github.com/sensepost/gowitness.git", "gowitness", cfg)
		},
	})

	i.Register(&ToolJob{
		Name:        "jsecret",
		Category:    "go",
		Description: "Legacy JS secret scanner placeholder",
		Required:    false,
		CheckFunc: func() bool {
			return false
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			job.Status = StatusSkipped
			job.Output = "jsecret is unavailable (repository deleted/private). Coverage is provided by jsleak and mantra."
			return nil
		},
	})

	i.Register(&ToolJob{
		Name:        "racepwn",
		Category:    "go",
		Description: "Race-condition helper placeholder",
		Required:    false,
		CheckFunc: func() bool {
			return false
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			scriptPath, created, err := ensureRaceCurlWrapper()
			if err != nil {
				return err
			}
			job.Status = StatusSkipped
			if created {
				job.Output = "racepwn is unavailable (repository deleted). Created race_curl.sh wrapper at " + scriptPath
				return nil
			}
			job.Output = "racepwn is unavailable (repository deleted). Using race_curl.sh wrapper at " + scriptPath
			return nil
		},
	})

	i.Register(&ToolJob{
		Name:        "nuclei-templates",
		Category:    "post-go",
		Description: "Nuclei template database update",
		Required:    false,
		CheckFunc: func() bool {
			home, err := os.UserHomeDir()
			if err != nil {
				return false
			}
			_, err = os.Stat(filepath.Join(home, "nuclei-templates"))
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			nucleiBin, err := findBinary("nuclei", cfg)
			if err != nil {
				return fmt.Errorf("nuclei not found in PATH or GOPATH/bin: %w", err)
			}

			goPath := resolveGOPATH(cfg)
			binPath := filepath.Join(goPath, "bin")

			cmd := exec.CommandContext(ctx, nucleiBin, "-update-templates")
			cmd.Env = append(os.Environ(),
				"GOPATH="+goPath,
				"GOBIN="+binPath,
				"PATH="+binPath+string(os.PathListSeparator)+os.Getenv("PATH"),
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("nuclei -update-templates failed: %w\n%s", err, strings.TrimSpace(string(out)))
			}
			return nil
		},
	})
}

func installKiterunner(ctx context.Context, cfg *config.Config) error {
	if runtime.GOOS == "linux" {
		arch, err := detectMachineArch(ctx)
		if err == nil {
			if archiveURL, ok := kiterunnerArchiveForArch(arch); ok {
				tmpDir, err := os.MkdirTemp("", "kiterunner-*")
				if err == nil {
					defer os.RemoveAll(tmpDir)

					tarPath := filepath.Join(tmpDir, "kr.tar.gz")
					if err := downloadFile(ctx, archiveURL, tarPath); err == nil {
						extract := exec.CommandContext(ctx, "tar", "-xzf", tarPath, "-C", tmpDir)
						if out, err := extract.CombinedOutput(); err == nil {
							for _, name := range []string{"kr", "kiterunner"} {
								src := filepath.Join(tmpDir, name)
								if _, statErr := os.Stat(src); statErr != nil {
									continue
								}
								target := installedBinaryPath("kr", cfg)
								if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
									break
								}
								if err := copyFile(src, target); err == nil {
									_ = os.Chmod(target, 0o755)
									return nil
								}
							}
						} else {
							_ = out
						}
					}
				}
			}
		}
	}

	return buildKiterunnerFromSource(ctx, cfg)
}

func kiterunnerArchiveForArch(arch string) (string, bool) {
	norm := strings.ToLower(strings.TrimSpace(arch))
	switch {
	case strings.Contains(norm, "arm64"), strings.Contains(norm, "aarch64"):
		return "https://github.com/assetnote/kiterunner/releases/latest/download/kr_linux_arm64.tar.gz", true
	case strings.Contains(norm, "amd64"), strings.Contains(norm, "x86_64"):
		return "https://github.com/assetnote/kiterunner/releases/latest/download/kr_linux_amd64.tar.gz", true
	default:
		return "", false
	}
}

func buildKiterunnerFromSource(ctx context.Context, cfg *config.Config) error {
	repoDir := filepath.Join(defaultDataDir(), "tools", "kiterunner")
	if _, err := os.Stat(repoDir); err == nil {
		pull := exec.CommandContext(ctx, "git", "-C", repoDir, "pull", "--ff-only")
		pull.Env = buildGitEnv(os.Environ())
		_, _ = pull.CombinedOutput()
	} else if err := gitCloneShallow(ctx, "https://github.com/assetnote/kiterunner.git", repoDir, false); err != nil {
		return err
	}

	env, err := goInstallEnv(cfg, nil)
	if err != nil {
		return err
	}

	target := installedBinaryPath("kr", cfg)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	goBin := findGoBinary()
	attempts := [][]string{
		{"build", "-v", "-o", target, "./cmd/kr"},
		{"build", "-v", "-o", target, "./cmd/kiterunner"},
		{"build", "-v", "-o", target, "."},
		{"install", "-v", "./..."},
	}

	failures := make([]string, 0, len(attempts))
	for _, args := range attempts {
		cmd := exec.CommandContext(ctx, goBin, args...)
		cmd.Dir = repoDir
		cmd.Env = env
		out, runErr := cmd.CombinedOutput()
		if runErr == nil {
			if goToolCheckFunc("kr", cfg)() || goToolCheckFunc("kiterunner", cfg)() {
				return nil
			}
			if _, statErr := os.Stat(target); statErr == nil {
				return nil
			}
		}
		failures = append(failures, strings.TrimSpace(string(out)))
	}

	return fmt.Errorf("kiterunner build failed after all fallbacks: %s", strings.Join(failures, " | "))
}

func ensureRaceCurlWrapper() (string, bool, error) {
	scriptDir := filepath.Join(defaultDataDir(), "scripts")
	if err := os.MkdirAll(scriptDir, 0o755); err != nil {
		return "", false, err
	}

	scriptPath := filepath.Join(scriptDir, "race_curl.sh")
	if _, err := os.Stat(scriptPath); err == nil {
		return scriptPath, false, nil
	}

	content := "#!/usr/bin/env bash\n" +
		"# race_curl.sh - basic race-condition helper\n" +
		"# Usage: race_curl.sh <url> <method> <data> <concurrency>\n" +
		"URL=\"${1:-https://target.local/redeem}\"\n" +
		"METHOD=\"${2:-POST}\"\n" +
		"DATA=\"${3:-amount=1}\"\n" +
		"CONCURRENCY=\"${4:-30}\"\n" +
		"seq \"$CONCURRENCY\" | xargs -P \"$CONCURRENCY\" -I{} curl -ks -X \"$METHOD\" \"$URL\" -d \"$DATA\" -o /dev/null -w \"%{http_code} %{time_total}s\\n\"\n"

	if err := os.WriteFile(scriptPath, []byte(content), 0o755); err != nil {
		return "", false, err
	}
	return scriptPath, true, nil
}
