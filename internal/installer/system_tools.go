package installer

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

var systemPackages = []string{
	"nmap",
	"masscan",
	"curl",
	"jq",
	"python3-pip",
	"git",
	"golang",
	"ruby-dev",
	"build-essential",
	"sqlmap",
	"seclists",
	"libpcap-dev",
	"dnsutils",
	"whois",
	"netcat-openbsd",
	"wget",
	"unzip",
	"whatweb",
	"amass",
	"findomain",
	"awscli",
}

func RegisterSystemTools(i *Installer) {
	for _, pkg := range systemPackages {
		packageName := pkg
		i.Register(&ToolJob{
			Name:        packageName,
			Category:    "system",
			Description: "System package " + packageName,
			Required:    false,
			CheckFunc: func() bool {
				if runtime.GOOS != "linux" {
					return false
				}
				tool := mapSystemPackageToBinary(packageName)
				_, err := exec.LookPath(tool)
				return err == nil
			},
			InstallFunc: func(ctx context.Context, job *ToolJob) error {
				if runtime.GOOS != "linux" {
					return fmt.Errorf("system package install is only supported on linux")
				}
				cmd := fmt.Sprintf("sudo apt-get update ; sudo apt-get install -y %s", packageName)
				if _, err := runShellCommand(ctx, cmd); err != nil {
					fallback := fmt.Sprintf("apt-get update ; apt-get install -y %s", packageName)
					if _, err2 := runShellCommand(ctx, fallback); err2 != nil {
						return err
					}
				}
				return nil
			},
		})
	}

	i.Register(&ToolJob{
		Name:        "wpscan",
		Category:    "system",
		Description: "Install wpscan via Ruby gem",
		Required:    false,
		CheckFunc: func() bool {
			_, err := exec.LookPath("wpscan")
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			if runtime.GOOS != "linux" {
				return fmt.Errorf("wpscan install is only supported on linux")
			}
			if _, err := runShellCommand(ctx, "sudo gem install wpscan"); err != nil {
				_, err = runShellCommand(ctx, "gem install wpscan")
				return err
			}
			return nil
		},
	})

	i.Register(&ToolJob{
		Name:        "feroxbuster",
		Category:    "system",
		Description: "Install feroxbuster binary",
		Required:    false,
		CheckFunc: func() bool {
			_, err := exec.LookPath("feroxbuster")
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			if runtime.GOOS != "linux" {
				return fmt.Errorf("feroxbuster install is only supported on linux")
			}
			cmd := "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash"
			_, err := runShellCommand(ctx, cmd)
			return err
		},
	})

	i.Register(&ToolJob{
		Name:        "rustscan",
		Category:    "system",
		Description: "Install rustscan binary",
		Required:    false,
		CheckFunc: func() bool {
			_, err := exec.LookPath("rustscan")
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			if runtime.GOOS != "linux" {
				return fmt.Errorf("rustscan install is only supported on linux")
			}
			cmd := "tmp=$(mktemp -d) ; cd $tmp ; wget -q https://github.com/RustScan/RustScan/releases/latest/download/rustscan_amd64.deb ; sudo dpkg -i rustscan_amd64.deb || dpkg -i rustscan_amd64.deb"
			_, err := runShellCommand(ctx, cmd)
			return err
		},
	})
}

func mapSystemPackageToBinary(pkg string) string {
	switch pkg {
	case "python3-pip":
		return "pip3"
	case "golang":
		return "go"
	case "ruby-dev":
		return "ruby"
	case "build-essential":
		return "gcc"
	case "dnsutils":
		return "dig"
	case "netcat-openbsd":
		return "nc"
	case "awscli":
		return "aws"
	default:
		return pkg
	}
}
