package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	{"gowitness", "github.com/sensepost/gowitness@latest", "gowitness", "Web screenshot capture utility"},
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
	{"bxss", "github.com/ethicalhackingplayground/bxss/v2/cmd/bxss@latest", "bxss", "Blind XSS injector"},
	{"crlfuzz", "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest", "crlfuzz", "CRLF injection scanner"},
	{"ppmap", "github.com/kleiton0x00/ppmap@latest", "ppmap", "Prototype pollution mapper"},
	{"headi", "github.com/mlcsec/headi@latest", "headi", "Header injection scanner"},
	{"byp4xx", "github.com/lobuhi/byp4xx@latest", "byp4xx", "HTTP 40x bypass helper"},
	{"subzy", "github.com/PentestPad/subzy@latest", "subzy", "Subdomain takeover checker"},
	{"h2csmuggler", "github.com/BishopFox/h2csmuggler@latest", "h2csmuggler", "HTTP/2 request smuggling helper"},
	{"ffuf", "github.com/ffuf/ffuf/v2@latest", "ffuf", "Content discovery fuzzer"},
	{"gobuster", "github.com/OJ/gobuster/v3@latest", "gobuster", "Directory and DNS bruteforce tool"},
	{"webanalyze", "github.com/rverton/webanalyze/cmd/webanalyze@latest", "webanalyze", "Technology fingerprinting"},
	{"fingerprintx", "github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest", "fingerprintx", "Service fingerprinting"},
	{"jsleak", "github.com/channyein1337/jsleak@latest", "jsleak", "JavaScript secrets discovery"},
	{"mantra", "github.com/brosck/mantra@latest", "mantra", "Secrets and URL extraction"},
	{"kiterunner", "github.com/assetnote/kiterunner/cmd/kiterunner@latest", "kiterunner", "API route discovery"},
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
		if _, err := os.Stat(candidate); err == nil {
			return true
		}
		return false
	}
}

func installGoTool(ctx context.Context, importPath string, cfg *config.Config) error {
	path := strings.TrimSpace(importPath)
	if path == "" {
		return fmt.Errorf("empty go import path")
	}

	goPath := resolveGOPATH(cfg)
	if goPath == "" {
		return fmt.Errorf("unable to resolve GOPATH")
	}
	binPath := filepath.Join(goPath, "bin")
	if err := os.MkdirAll(binPath, 0o755); err != nil {
		return fmt.Errorf("failed to create go bin directory: %w", err)
	}

	cmd := exec.CommandContext(ctx, "go", "install", "-v", path)
	cmd.Env = append(os.Environ(),
		"GOPATH="+goPath,
		"GOBIN="+binPath,
		"PATH="+binPath+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GOFLAGS=-mod=mod",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go install %s failed: %w\noutput: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
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
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%s not found", trimmed)
}
