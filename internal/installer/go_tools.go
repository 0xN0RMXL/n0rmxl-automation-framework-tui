package installer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type GoTool struct {
	Name string
	Path string
}

var goTools = []GoTool{
	{Name: "pdtm", Path: "github.com/projectdiscovery/pdtm/cmd/pdtm"},
	{Name: "subfinder", Path: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"},
	{Name: "httpx", Path: "github.com/projectdiscovery/httpx/cmd/httpx"},
	{Name: "nuclei", Path: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"},
	{Name: "katana", Path: "github.com/projectdiscovery/katana/cmd/katana"},
	{Name: "dnsx", Path: "github.com/projectdiscovery/dnsx/cmd/dnsx"},
	{Name: "naabu", Path: "github.com/projectdiscovery/naabu/v2/cmd/naabu"},
	{Name: "asnmap", Path: "github.com/projectdiscovery/asnmap/cmd/asnmap"},
	{Name: "uncover", Path: "github.com/projectdiscovery/uncover/cmd/uncover"},
	{Name: "tlsx", Path: "github.com/projectdiscovery/tlsx/cmd/tlsx"},
	{Name: "mapcidr", Path: "github.com/projectdiscovery/mapcidr/cmd/mapcidr"},
	{Name: "interactsh-client", Path: "github.com/projectdiscovery/interactsh/cmd/interactsh-client"},
	{Name: "notify", Path: "github.com/projectdiscovery/notify/cmd/notify"},
	{Name: "csprecon", Path: "github.com/edoardottt/csprecon/cmd/csprecon"},
	{Name: "assetfinder", Path: "github.com/tomnomnom/assetfinder"},
	{Name: "chaos", Path: "github.com/projectdiscovery/chaos-client/cmd/chaos"},
	{Name: "github-subdomains", Path: "github.com/gwen001/github-subdomains"},
	{Name: "gitlab-subdomains", Path: "github.com/gwen001/gitlab-subdomains"},
	{Name: "related-domains", Path: "github.com/gwen001/related-domains"},
	{Name: "shosubgo", Path: "github.com/incogbyte/shosubgo"},
	{Name: "puredns", Path: "github.com/d3mondev/puredns/v2"},
	{Name: "shuffledns", Path: "github.com/projectdiscovery/shuffledns/cmd/shuffledns"},
	{Name: "hakrevdns", Path: "github.com/hakluke/hakrevdns"},
	{Name: "hakip2host", Path: "github.com/hakluke/hakip2host"},
	{Name: "dnsbruter", Path: "github.com/ImAyrix/dnsbruter"},
	{Name: "gotator", Path: "github.com/Josue87/gotator"},
	{Name: "alterx", Path: "github.com/projectdiscovery/alterx/cmd/alterx"},
	{Name: "hakrawler", Path: "github.com/hakluke/hakrawler"},
	{Name: "subjs", Path: "github.com/lc/subjs"},
	{Name: "gau", Path: "github.com/lc/gau/v2/cmd/gau"},
	{Name: "gauplus", Path: "github.com/bp0lr/gauplus"},
	{Name: "hakcheckurl", Path: "github.com/hakluke/hakcheckurl"},
	{Name: "urldedupe", Path: "github.com/ameenmaali/urldedupe"},
	{Name: "qsreplace", Path: "github.com/tomnomnom/qsreplace"},
	{Name: "fff", Path: "github.com/tomnomnom/fff"},
	{Name: "ffuf", Path: "github.com/ffuf/ffuf/v2"},
	{Name: "kiterunner", Path: "github.com/assetnote/kiterunner/cmd/kr"},
	{Name: "gf", Path: "github.com/tomnomnom/gf"},
	{Name: "x8", Path: "github.com/Sh1Yo/x8"},
	{Name: "dalfox", Path: "github.com/hahwul/dalfox/v2"},
	{Name: "Gxss", Path: "github.com/KathanP19/Gxss"},
	{Name: "kxss", Path: "github.com/Emoe/kxss"},
	{Name: "airixss", Path: "github.com/ferreiraklet/airixss"},
	{Name: "bxss", Path: "github.com/ethicalhackingplayground/bxss"},
	{Name: "crlfuzz", Path: "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz"},
	{Name: "ppmap", Path: "github.com/kleinik0x00/ppmap"},
	{Name: "headi", Path: "github.com/mlcsec/headi"},
	{Name: "byp4xx", Path: "github.com/lobuhi/byp4xx"},
	{Name: "mantra", Path: "github.com/MrEmpy/mantra"},
	{Name: "jsleak", Path: "github.com/channyein1337/jsleak"},
	{Name: "subzy", Path: "github.com/PentestPad/subzy"},
	{Name: "graphw00f", Path: "github.com/dolevf/graphw00f/cmd/graphw00f"},
	{Name: "grpc-gateway", Path: "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway"},
	{Name: "gowitness", Path: "github.com/sensepost/gowitness"},
	{Name: "webanalyze", Path: "github.com/rverton/webanalyze/cmd/webanalyze"},
	{Name: "fingerprintx", Path: "github.com/praetorian-inc/fingerprintx/cmd/fingerprintx"},
	{Name: "originiphunter", Path: "github.com/rix4uni/originiphunter"},
	{Name: "anew", Path: "github.com/tomnomnom/anew"},
	{Name: "unfurl", Path: "github.com/tomnomnom/unfurl"},
	{Name: "haktrails", Path: "github.com/hakluke/haktrails"},
	{Name: "nrich", Path: "gitlab.com/shodan-public/nrich"},
}

func RegisterGoTools(i *Installer) {
	for _, tool := range goTools {
		goTool := tool
		i.Register(&ToolJob{
			Name:        goTool.Name,
			Category:    "go",
			Description: "Go tool " + goTool.Name,
			Required:    false,
			CheckFunc: func() bool {
				_, err := exec.LookPath(goTool.Name)
				return err == nil
			},
			InstallFunc: func(ctx context.Context, job *ToolJob) error {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				goPath := filepath.Join(home, "go")
				goBin := filepath.Join(home, "go", "bin")
				if err := os.MkdirAll(goBin, 0o755); err != nil {
					return err
				}
				cmd := goInstallCommand(goPath, goBin, goTool.Path)
				_, err = runShellCommand(ctx, cmd)
				return err
			},
		})
	}

	i.Register(&ToolJob{
		Name:        "nuclei-templates",
		Category:    "go",
		Description: "Update nuclei templates",
		Required:    false,
		CheckFunc: func() bool {
			_, err := exec.LookPath("nuclei")
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			_, err := runShellCommand(ctx, "nuclei -update-templates")
			return err
		},
	})
}

func goInstallCommand(goPath string, goBin string, pkg string) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("$env:GOPATH='%s' ; $env:PATH='%s;%s' ; go install -v %s@latest", goPath, os.Getenv("PATH"), goBin, pkg)
	}
	return fmt.Sprintf("GOPATH=%s PATH=%s:%s go install -v %s@latest", goPath, os.Getenv("PATH"), goBin, pkg)
}
