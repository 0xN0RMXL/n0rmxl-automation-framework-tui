package installer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type aptPackageSpec struct {
	name        string
	pkg         string
	binary      string
	description string
}

func RegisterSystemTools(i *Installer) {
	if runtime.GOOS != "linux" {
		return
	}

	aptPkgs := []aptPackageSpec{
		{"nmap", "nmap", "nmap", "Network mapper and port scanner"},
		{"masscan", "masscan", "masscan", "Mass IP port scanner"},
		{"curl", "curl", "curl", "URL transfer tool"},
		{"jq", "jq", "jq", "JSON processor"},
		{"python3-pip", "python3-pip", "pip3", "Python package installer"},
		{"git", "git", "git", "Version control system"},
		{"ruby-dev", "ruby-dev", "", "Ruby development headers"},
		{"ruby-full", "ruby-full", "ruby", "Ruby runtime"},
		{"build-essential", "build-essential", "gcc", "Build toolchain"},
		{"sqlmap", "sqlmap", "sqlmap", "SQL injection automation tool"},
		{"libpcap-dev", "libpcap-dev", "", "Packet capture development headers"},
		{"dnsutils", "dnsutils", "dig", "DNS utilities"},
		{"whois", "whois", "whois", "WHOIS client"},
		{"netcat-openbsd", "netcat-openbsd", "nc", "TCP/IP swiss-army knife"},
		{"wget", "wget", "wget", "Downloader"},
		{"unzip", "unzip", "unzip", "ZIP extractor"},
		{"whatweb", "whatweb", "whatweb", "Web technology fingerprinting"},
		{"golang-go", "golang-go", "go", "Go compiler and tooling"},
		{"cargo", "cargo", "cargo", "Rust package manager"},
	}

	for _, pkg := range aptPkgs {
		p := pkg
		i.Register(&ToolJob{
			Name:        p.name,
			Category:    "system",
			Description: p.description,
			Required:    false,
			CheckFunc: func() bool {
				if p.binary != "" {
					if _, err := exec.LookPath(p.binary); err == nil {
						return true
					}
				}
				cmd := exec.Command("dpkg", "-s", p.pkg)
				return cmd.Run() == nil
			},
			InstallFunc: func(ctx context.Context, job *ToolJob) error {
				return aptInstall(ctx, p.pkg, i)
			},
		})
	}

	i.Register(&ToolJob{
		Name:        "seclists",
		Category:    "system",
		Description: "SecLists wordlist collection",
		Required:    false,
		CheckFunc: func() bool {
			paths := []string{
				"/usr/share/seclists",
				"/usr/share/wordlists/seclists",
				filepath.Join(os.Getenv("HOME"), "seclists"),
			}
			for _, p := range paths {
				if _, err := os.Stat(p); err == nil {
					return true
				}
			}
			return false
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			if err := aptInstall(ctx, "seclists", i); err == nil {
				return nil
			}
			dest := "/usr/share/seclists"
			if _, err := os.Stat(dest); err == nil {
				return nil
			}
			return gitCloneShallow(ctx, "https://github.com/danielmiessler/SecLists.git", dest, true)
		},
	})

	i.Register(&ToolJob{
		Name:        "wpscan",
		Category:    "system",
		Description: "WPScan WordPress vulnerability scanner",
		Required:    false,
		CheckFunc: func() bool {
			_, err := exec.LookPath("wpscan")
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			if _, err := exec.LookPath("gem"); err != nil {
				if err := aptInstall(ctx, "ruby-full", i); err != nil {
					return fmt.Errorf("ruby install failed: %w", err)
				}
				if err := aptInstall(ctx, "ruby-dev", i); err != nil {
					return fmt.Errorf("ruby-dev install failed: %w", err)
				}
				if err := aptInstall(ctx, "build-essential", i); err != nil {
					return fmt.Errorf("build-essential install failed: %w", err)
				}
			}

			cmd := exec.CommandContext(ctx, "sudo", "gem", "install", "--no-document", "wpscan")
			if out, err := cmd.CombinedOutput(); err != nil {
				cmd2 := exec.CommandContext(ctx, "gem", "install", "--no-document", "wpscan")
				if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
					return fmt.Errorf("gem install wpscan failed: %w\n%s\n%s", err2, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
				}
			}
			return nil
		},
	})

	i.Register(&ToolJob{
		Name:        "feroxbuster",
		Category:    "binary",
		Description: "Feroxbuster recursive content discovery",
		Required:    false,
		CheckFunc: func() bool {
			_, err := exec.LookPath("feroxbuster")
			if err == nil {
				return true
			}
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return false
			}
			_, err = os.Stat(filepath.Join(home, ".local", "bin", "feroxbuster"))
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			scriptPath := filepath.Join(os.TempDir(), "ferox-install.sh")
			if err := downloadFile(ctx, "https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh", scriptPath); err != nil {
				return fmt.Errorf("feroxbuster script download failed: %w", err)
			}
			defer os.Remove(scriptPath)
			if err := os.Chmod(scriptPath, 0o755); err != nil {
				return err
			}

			cmd := exec.CommandContext(ctx, "sudo", "bash", scriptPath, "-b", "/usr/local/bin/")
			if out, err := cmd.CombinedOutput(); err == nil {
				return nil
			} else {
				home, _ := os.UserHomeDir()
				localBin := filepath.Join(home, ".local", "bin")
				_ = os.MkdirAll(localBin, 0o755)
				cmd2 := exec.CommandContext(ctx, "bash", scriptPath, "-b", localBin+"/")
				if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
					return fmt.Errorf("feroxbuster install failed: %w\n%s\n%s", err2, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
				}
			}
			return nil
		},
	})

	i.Register(&ToolJob{
		Name:        "rustscan",
		Category:    "binary",
		Description: "RustScan fast port scanner",
		Required:    false,
		CheckFunc: func() bool {
			_, err := exec.LookPath("rustscan")
			if err == nil {
				return true
			}
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return false
			}
			_, err = os.Stat(filepath.Join(home, ".cargo", "bin", "rustscan"))
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			arch, err := detectMachineArch(ctx)
			if err != nil {
				return err
			}

			issues := make([]string, 0, 3)
			debPath := filepath.Join(os.TempDir(), "rustscan.deb")
			defer os.Remove(debPath)

			if _, err := downloadFirstAvailable(ctx, rustscanDebCandidates(arch), debPath); err == nil {
				if installErr := installDebPackage(ctx, debPath); installErr == nil {
					return nil
				} else {
					issues = append(issues, "deb install failed: "+installErr.Error())
				}
			} else {
				issues = append(issues, "deb download failed: "+err.Error())
			}

			if err := installRustscanWithCargo(ctx, i); err == nil {
				return nil
			} else {
				issues = append(issues, "cargo fallback failed: "+err.Error())
			}

			return fmt.Errorf("rustscan install failed after fallbacks: %s", strings.Join(issues, " | "))
		},
	})

	i.Register(&ToolJob{
		Name:        "findomain",
		Category:    "binary",
		Description: "Findomain cross-platform subdomain enumerator",
		Required:    false,
		CheckFunc: func() bool {
			_, err := exec.LookPath("findomain")
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			archOut, err := exec.CommandContext(ctx, "uname", "-m").Output()
			if err != nil {
				return fmt.Errorf("failed to detect arch: %w", err)
			}
			arch := strings.TrimSpace(string(archOut))

			url := "https://github.com/findomain/findomain/releases/latest/download/findomain-linux-i386.zip"
			switch arch {
			case "x86_64":
				url = "https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip"
			case "aarch64", "arm64":
				url = "https://github.com/findomain/findomain/releases/latest/download/findomain-aarch64.zip"
			}

			zipPath := filepath.Join(os.TempDir(), "findomain.zip")
			if err := downloadFile(ctx, url, zipPath); err != nil {
				return fmt.Errorf("findomain download failed: %w", err)
			}
			defer os.Remove(zipPath)

			unzipCmd := exec.CommandContext(ctx, "unzip", "-o", "-j", zipPath, "-d", os.TempDir())
			if out, err := unzipCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("findomain unzip failed: %w\n%s", err, strings.TrimSpace(string(out)))
			}

			tmpBin := filepath.Join(os.TempDir(), "findomain")
			if err := installBinary(ctx, tmpBin, "/usr/local/bin/findomain"); err != nil {
				return err
			}
			if err := ensureExecutable(ctx, "/usr/local/bin/findomain"); err != nil {
				return err
			}
			return nil
		},
	})

	i.Register(&ToolJob{
		Name:        "awscli",
		Category:    "binary",
		Description: "AWS CLI installer",
		Required:    false,
		CheckFunc: func() bool {
			_, err := exec.LookPath("aws")
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			pipCmd := exec.CommandContext(ctx, "pip3", "install", "--break-system-packages", "--quiet", "awscli")
			if err := pipCmd.Run(); err == nil {
				return nil
			}
			return installAWSCLIv2(ctx)
		},
	})

	i.Register(&ToolJob{
		Name:        "nrich",
		Category:    "binary",
		Description: "Shodan nrich binary",
		Required:    false,
		CheckFunc: func() bool {
			_, err := exec.LookPath("nrich")
			if err == nil {
				return true
			}
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return false
			}
			_, err = os.Stat(filepath.Join(home, ".local", "bin", "nrich"))
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			arch, err := detectMachineArch(ctx)
			if err != nil {
				return err
			}

			issues := make([]string, 0, 3)
			assetURL, assetKind, resolveErr := resolveLatestNrichAsset(ctx, arch)
			if resolveErr != nil {
				issues = append(issues, "api asset lookup failed: "+resolveErr.Error())
				for _, legacy := range legacyNrichDebCandidates(arch) {
					assetURL = legacy
					assetKind = "deb"
					tmpDeb := filepath.Join(os.TempDir(), "nrich.deb")
					if err := downloadFile(ctx, assetURL, tmpDeb); err != nil {
						issues = append(issues, fmt.Sprintf("legacy download failed (%s): %s", assetURL, err.Error()))
						continue
					}
					if installErr := installDebPackage(ctx, tmpDeb); installErr == nil {
						_ = os.Remove(tmpDeb)
						return nil
					} else {
						issues = append(issues, fmt.Sprintf("legacy deb install failed (%s): %s", assetURL, installErr.Error()))
					}
					_ = os.Remove(tmpDeb)
				}
				return fmt.Errorf("nrich install failed after fallbacks: %s", strings.Join(issues, " | "))
			}

			tmpPath := filepath.Join(os.TempDir(), "nrich.tmp")
			if assetKind == "deb" {
				tmpPath = filepath.Join(os.TempDir(), "nrich.deb")
			}
			defer os.Remove(tmpPath)

			if err := downloadFile(ctx, assetURL, tmpPath); err != nil {
				return fmt.Errorf("nrich download failed: %w", err)
			}

			if assetKind == "deb" {
				if err := installDebPackage(ctx, tmpPath); err != nil {
					return fmt.Errorf("nrich deb install failed: %w", err)
				}
				return nil
			}

			if err := installBinary(ctx, tmpPath, "/usr/local/bin/nrich"); err != nil {
				return err
			}
			if err := ensureExecutable(ctx, "/usr/local/bin/nrich"); err != nil {
				return err
			}
			return nil
		},
	})

	i.Register(&ToolJob{
		Name:        "massdns",
		Category:    "binary",
		Description: "MassDNS high-performance resolver",
		Required:    false,
		CheckFunc: func() bool {
			_, err := exec.LookPath("massdns")
			return err == nil
		},
		InstallFunc: func(ctx context.Context, job *ToolJob) error {
			dest := filepath.Join(defaultDataDir(), "tools", "massdns")
			if err := gitCloneShallow(ctx, "https://github.com/blechschmidt/massdns.git", dest, false); err != nil {
				return err
			}

			makeCmd := exec.CommandContext(ctx, "make", "-C", dest)
			if out, err := makeCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("massdns build failed: %w\n%s", err, strings.TrimSpace(string(out)))
			}

			binSrc := filepath.Join(dest, "bin", "massdns")
			if err := installBinary(ctx, binSrc, "/usr/local/bin/massdns"); err != nil {
				return err
			}
			return ensureExecutable(ctx, "/usr/local/bin/massdns")
		},
	})
}

func aptInstall(ctx context.Context, pkg string, inst *Installer) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("apt install is only supported on linux")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if inst == nil || inst.consumeAptUpdateAttempt() {
		if err := runAptWithFallback(ctx, 4*time.Minute, "update"); err != nil {
			return fmt.Errorf("apt update failed: %w", err)
		}
	}

	if err := runAptWithFallback(ctx, 10*time.Minute, "install", "-y", pkg); err != nil {
		return fmt.Errorf("apt install %s failed: %w", pkg, err)
	}
	return nil
}

func runAptWithFallback(ctx context.Context, timeout time.Duration, args ...string) error {
	if len(args) == 0 {
		return fmt.Errorf("apt arguments cannot be empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	env := append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
	)
	attempts := []struct {
		bin  string
		args []string
	}{
		{bin: "sudo", args: append([]string{"-n", "apt-get"}, args...)},
		{bin: "apt-get", args: args},
	}

	failures := make([]string, 0, len(attempts))
	for _, attempt := range attempts {
		cmdCtx := ctx
		cancel := func() {}
		if timeout > 0 {
			cmdCtx, cancel = context.WithTimeout(ctx, timeout)
		}

		cmd := exec.CommandContext(cmdCtx, attempt.bin, attempt.args...)
		cmd.Env = env
		cmd.Stdin = strings.NewReader("")
		out, err := cmd.CombinedOutput()
		cancel()
		if err == nil {
			return nil
		}

		output := strings.TrimSpace(string(out))
		if output == "" {
			output = err.Error()
		}
		failures = append(failures, fmt.Sprintf("%s %s => %s", attempt.bin, strings.Join(attempt.args, " "), output))

		if cmdCtx.Err() != nil {
			break
		}
	}

	if len(failures) == 0 {
		return fmt.Errorf("all apt attempts failed")
	}
	return fmt.Errorf("%s", strings.Join(failures, " | "))
}

func downloadFile(ctx context.Context, url, dest string) error {
	cmd := exec.CommandContext(ctx, "curl", "-fsSL", "-o", dest, url)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("curl download failed for %s: %w\n%s", url, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func installBinary(ctx context.Context, src, dest string) error {
	if err := copyFile(src, dest); err == nil {
		return nil
	}

	cmd := exec.CommandContext(ctx, "sudo", "cp", src, dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install binary %s -> %s failed: %w\n%s", src, dest, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureExecutable(ctx context.Context, path string) error {
	if err := os.Chmod(path, 0o755); err == nil {
		return nil
	}

	cmd := exec.CommandContext(ctx, "sudo", "chmod", "755", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chmod 755 %s failed: %w\n%s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func gitCloneShallow(ctx context.Context, repoURL, dest string, withSudo bool) error {
	if _, err := os.Stat(dest); err == nil {
		return nil
	}

	_ = os.MkdirAll(filepath.Dir(dest), 0o755)

	clone := exec.CommandContext(ctx, "git", "clone", "--depth", "1", repoURL, dest)
	out, err := clone.CombinedOutput()
	if err == nil {
		return nil
	}

	if !withSudo {
		return fmt.Errorf("git clone failed for %s: %w\n%s", repoURL, err, strings.TrimSpace(string(out)))
	}

	clone2 := exec.CommandContext(ctx, "sudo", "git", "clone", "--depth", "1", repoURL, dest)
	out2, err2 := clone2.CombinedOutput()
	if err2 != nil {
		return fmt.Errorf("git clone failed for %s: %w\n%s\n%s", repoURL, err2, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
	}
	return nil
}

func detectMachineArch(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "uname", "-m").Output()
	if err == nil {
		arch := strings.ToLower(strings.TrimSpace(string(out)))
		if arch != "" {
			return arch, nil
		}
	}
	if strings.TrimSpace(runtime.GOARCH) == "" {
		return "", fmt.Errorf("failed to detect architecture")
	}
	return strings.ToLower(strings.TrimSpace(runtime.GOARCH)), nil
}

func isArmArch(arch string) bool {
	arch = strings.ToLower(strings.TrimSpace(arch))
	return strings.Contains(arch, "arm64") || strings.Contains(arch, "aarch64")
}

func rustscanDebCandidates(arch string) []string {
	if isArmArch(arch) {
		return []string{
			"https://github.com/RustScan/RustScan/releases/latest/download/rustscan_linux_arm64.deb",
			"https://github.com/RustScan/RustScan/releases/latest/download/rustscan_arm64.deb",
		}
	}

	return []string{
		"https://github.com/RustScan/RustScan/releases/latest/download/rustscan_linux_amd64.deb",
		"https://github.com/RustScan/RustScan/releases/latest/download/rustscan_amd64.deb",
		"https://github.com/RustScan/RustScan/releases/latest/download/rustscan_x86_64.deb",
	}
}

func downloadFirstAvailable(ctx context.Context, urls []string, dest string) (string, error) {
	attempts := make([]string, 0, len(urls))
	for _, candidate := range urls {
		url := strings.TrimSpace(candidate)
		if url == "" {
			continue
		}
		if err := downloadFile(ctx, url, dest); err == nil {
			return url, nil
		} else {
			attempts = append(attempts, fmt.Sprintf("%s => %s", url, err.Error()))
		}
	}
	if len(attempts) == 0 {
		return "", fmt.Errorf("no candidate URLs provided")
	}
	return "", fmt.Errorf("all download attempts failed: %s", strings.Join(attempts, " | "))
}

func installDebPackage(ctx context.Context, debPath string) error {
	cmd := exec.CommandContext(ctx, "sudo", "dpkg", "-i", debPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	cmd2 := exec.CommandContext(ctx, "dpkg", "-i", debPath)
	out2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		return fmt.Errorf("dpkg install failed: %w\n%s\n%s", err2, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
	}
	return nil
}

func installRustscanWithCargo(ctx context.Context, inst *Installer) error {
	if _, err := exec.LookPath("cargo"); err != nil {
		if installErr := aptInstall(ctx, "cargo", inst); installErr != nil {
			return fmt.Errorf("cargo not found and apt install failed: %w", installErr)
		}
	}

	cmd := exec.CommandContext(ctx, "cargo", "install", "--locked", "rustscan")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cargo install rustscan failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	home, homeErr := os.UserHomeDir()
	if homeErr != nil {
		return nil
	}

	src := filepath.Join(home, ".cargo", "bin", "rustscan")
	if _, err := os.Stat(src); err != nil {
		return nil
	}

	if err := installBinary(ctx, src, "/usr/local/bin/rustscan"); err == nil {
		return ensureExecutable(ctx, "/usr/local/bin/rustscan")
	}

	localBinDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(localBinDir, 0o755); err != nil {
		return nil
	}
	dest := filepath.Join(localBinDir, "rustscan")
	if err := copyFile(src, dest); err != nil {
		return nil
	}
	return ensureExecutable(ctx, dest)
}

type gitlabReleaseAsset struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	DirectAssetURL string `json:"direct_asset_url"`
}

type gitlabReleasePayload struct {
	Assets struct {
		Links []gitlabReleaseAsset `json:"links"`
	} `json:"assets"`
}

func resolveLatestNrichAsset(ctx context.Context, arch string) (string, string, error) {
	const releaseAPI = "https://gitlab.com/api/v4/projects/shodan-public%2Fnrich/releases/permalink/latest"

	var payload gitlabReleasePayload
	if err := fetchJSON(ctx, releaseAPI, &payload); err != nil {
		return "", "", err
	}

	preferArm := isArmArch(arch)
	for _, kind := range []string{"deb", "bin"} {
		for _, asset := range payload.Assets.Links {
			name := strings.ToLower(strings.TrimSpace(asset.Name))
			if name == "" {
				continue
			}

			url := strings.TrimSpace(asset.DirectAssetURL)
			if url == "" {
				url = strings.TrimSpace(asset.URL)
			}
			if url == "" {
				continue
			}

			if preferArm {
				if !(strings.Contains(name, "arm64") || strings.Contains(name, "aarch64")) {
					continue
				}
			} else {
				if !(strings.Contains(name, "x86_64") || strings.Contains(name, "amd64")) {
					continue
				}
			}

			switch kind {
			case "deb":
				if strings.HasSuffix(name, ".deb") {
					return url, "deb", nil
				}
			case "bin":
				if strings.Contains(name, "linux") && !strings.HasSuffix(name, ".deb") && !strings.HasSuffix(name, ".rpm") {
					return url, "binary", nil
				}
			}
		}
	}

	return "", "", fmt.Errorf("no matching nrich asset found for arch %s", arch)
}

func legacyNrichDebCandidates(arch string) []string {
	if isArmArch(arch) {
		return []string{
			"https://gitlab.com/shodan-public/nrich/-/releases/permalink/latest/downloads/nrich_latest_arm64.deb",
			"https://gitlab.com/shodan-public/nrich/-/releases/permalink/latest/downloads/nrich_arm64.deb",
		}
	}
	return []string{
		"https://gitlab.com/shodan-public/nrich/-/releases/permalink/latest/downloads/nrich_latest_amd64.deb",
		"https://gitlab.com/shodan-public/nrich/-/releases/permalink/latest/downloads/nrich_amd64.deb",
		"https://gitlab.com/shodan-public/nrich/-/releases/permalink/latest/downloads/nrich_latest_x86_64.deb",
	}
}

func fetchJSON(ctx context.Context, url string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "n0rmxl-installer/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return err
	}
	return nil
}

func installAWSCLIv2(ctx context.Context) error {
	tmpDir, err := os.MkdirTemp("", "awscli-install-*")
	if err != nil {
		return fmt.Errorf("failed to create awscli temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archOut, err := exec.CommandContext(ctx, "uname", "-m").Output()
	if err != nil {
		return fmt.Errorf("failed to detect arch: %w", err)
	}
	arch := strings.TrimSpace(string(archOut))

	url := "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
	if strings.Contains(arch, "aarch64") || strings.Contains(arch, "arm64") {
		url = "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip"
	}

	zipPath := filepath.Join(tmpDir, "awscliv2.zip")
	if err := downloadFile(ctx, url, zipPath); err != nil {
		return err
	}

	unzip := exec.CommandContext(ctx, "unzip", "-q", zipPath, "-d", tmpDir)
	if out, err := unzip.CombinedOutput(); err != nil {
		return fmt.Errorf("awscli unzip failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	install := exec.CommandContext(ctx, "sudo", filepath.Join(tmpDir, "aws", "install"), "--update")
	if out, err := install.CombinedOutput(); err != nil {
		install2 := exec.CommandContext(ctx, filepath.Join(tmpDir, "aws", "install"), "--update")
		if out2, err2 := install2.CombinedOutput(); err2 != nil {
			return fmt.Errorf("awscli installer failed: %w\n%s\n%s", err2, strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
		}
	}
	return nil
}
