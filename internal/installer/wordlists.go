package installer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

type WordlistJob struct {
	Name string
	URL  string
	Path string
}

var wordlistDownloads = []WordlistJob{
	{
		Name: "best-dns-wordlist",
		URL:  "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt",
		Path: "wordlists/dns/best-dns-wordlist.txt",
	},
	{
		Name: "resolvers",
		URL:  "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
		Path: "wordlists/dns/resolvers.txt",
	},
	{
		Name: "resolvers-trusted",
		URL:  "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt",
		Path: "wordlists/dns/resolvers-trusted.txt",
	},
	{
		Name: "commonspeak2-subdomains",
		URL:  "https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt",
		Path: "wordlists/dns/commonspeak2-subdomains.txt",
	},
	{
		Name: "burp-parameter-names",
		URL:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt",
		Path: "wordlists/params/burp-parameter-names.txt",
	},
	{
		Name: "lfi-jhaddix",
		URL:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
		Path: "wordlists/fuzzing/LFI-Jhaddix.txt",
	},
	{
		Name: "xss-jhaddix",
		URL:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt",
		Path: "wordlists/fuzzing/XSS-Jhaddix.txt",
	},
	{
		Name: "raft-medium-directories",
		URL:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
		Path: "wordlists/web/raft-medium-directories.txt",
	},
	{
		Name: "raft-large-directories",
		URL:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
		Path: "wordlists/web/raft-large-directories.txt",
	},
	{
		Name: "raft-large-files",
		URL:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt",
		Path: "wordlists/web/raft-large-files.txt",
	},
	{
		Name: "3-digits-000-999",
		URL:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/3-digits-000-999.txt",
		Path: "wordlists/fuzzing/3-digits-000-999.txt",
	},
	{
		Name: "jwt-common-secrets",
		URL:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
		Path: "wordlists/passwords/jwt-common-secrets.txt",
	},
	{
		Name: "api-routes",
		URL:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
		Path: "wordlists/api/api-routes.txt",
	},
}

func RegisterWordlists(i *Installer) {
	for _, wl := range wordlistDownloads {
		job := wl
		i.Register(&ToolJob{
			Name:        job.Name,
			Category:    "wordlist",
			Description: "Download wordlist " + job.Name,
			Required:    false,
			CheckFunc: func() bool {
				path := filepath.Join(defaultDataDir(), filepath.FromSlash(job.Path))
				_, err := os.Stat(path)
				return err == nil
			},
			InstallFunc: func(ctx context.Context, item *ToolJob) error {
				target := filepath.Join(defaultDataDir(), filepath.FromSlash(job.Path))
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					return err
				}
				return downloadWordlist(ctx, job.URL, target)
			},
		})
	}
}

func downloadWordlist(ctx context.Context, sourceURL string, targetPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	out, err := os.Create(targetPath)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}
	return nil
}
