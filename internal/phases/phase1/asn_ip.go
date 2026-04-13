package phase1

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
)

func buildASNIPJobs(ctx phase1Context) ([]*engine.Job, string) {
	jobs := make([]*engine.Job, 0, 7)

	asnmap := engine.NewJob(1, "asnmap", "asnmap", []string{"-d", ctx.domain, "-silent", "-o", ctx.asnOut})
	asnmap.Description = "Map ASN data for target domain"
	asnmap.OutputFile = ctx.asnOut
	asnmap.Timeout = 10 * time.Minute
	asnmap.Execute = func(execCtx context.Context, j *engine.Job) error {
		if strings.TrimSpace(os.Getenv("PDCP_API_KEY")) == "" {
			markSkipped(j, "PDCP_API_KEY not set, skipping asnmap")
			return nil
		}
		return runCommand(execCtx, ctx.runCfg, "asnmap", []string{"-d", ctx.domain, "-silent", "-o", j.OutputFile})
	}
	asnmap.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, asnmap)

	asnmapIPs := engine.NewJob(1, "asnmap-ips", "", nil)
	asnmapIPs.Description = "Resolve ASN ranges into IP data"
	asnmapIPs.OutputFile = ctx.asnIPsOut
	asnmapIPs.DependsOn = []string{asnmap.ID}
	asnmapIPs.Timeout = 10 * time.Minute
	asnmapIPs.Execute = func(execCtx context.Context, j *engine.Job) error {
		asns := parseASNNumbersFromFile(ctx.asnOut)
		if len(asns) == 0 {
			markSkipped(j, "no ASN values found from asnmap output")
			return nil
		}
		dnsxAvailable := true
		if _, err := exec.LookPath("dnsx"); err != nil {
			dnsxAvailable = false
			j.LogLine("[WARN] dnsx not found, ASN host resolution fallback will be limited")
		}
		allLines := make([]string, 0, 2048)
		dnsxResolvedLines := make([]string, 0, 2048)
		for _, asn := range asns {
			lines, err := collectCommandLines(execCtx, ctx.runCfg, "asnmap", []string{"-a", "AS" + asn, "-silent"}, "")
			if err != nil {
				j.LogLine("[WARN] asn expansion failed for AS" + asn + ": " + err.Error())
				continue
			}
			allLines = append(allLines, lines...)
			if dnsxAvailable && len(lines) > 0 {
				stream := strings.Join(lines, "\n") + "\n"
				resolved, resolveErr := collectCommandLines(execCtx, ctx.runCfg, "dnsx", []string{"-silent", "-resp-only"}, stream)
				if resolveErr != nil {
					j.LogLine("[WARN] dnsx resolution failed for AS" + asn + ": " + resolveErr.Error())
				} else {
					dnsxResolvedLines = append(dnsxResolvedLines, resolved...)
				}
			}
		}
		if len(allLines) == 0 {
			markSkipped(j, "no ASN expansion data produced")
			return nil
		}
		ipLines := make([]string, 0, len(allLines)+len(dnsxResolvedLines))
		rangeLines := make([]string, 0, len(allLines))
		ipLines = append(ipLines, extractIPsFromLines(dnsxResolvedLines)...)
		for _, line := range allLines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			host := hostFromAny(line)
			if ip := net.ParseIP(host); ip != nil {
				ipLines = append(ipLines, ip.String())
				continue
			}
			if strings.Contains(line, "/") {
				candidate := strings.TrimSpace(strings.Split(line, " ")[0])
				if _, _, err := net.ParseCIDR(candidate); err == nil {
					rangeLines = append(rangeLines, candidate)
				}
			}
		}
		if len(ipLines) == 0 && len(rangeLines) == 0 {
			markSkipped(j, "no IP or CIDR entries extracted from ASN expansion")
			return nil
		}
		if len(ipLines) > 0 {
			if err := writeUniqueLines(ctx.asnIPsOut, ipLines); err != nil {
				return err
			}
		}
		if len(rangeLines) > 0 {
			if err := writeUniqueLines(ctx.ipRangesOut, rangeLines); err != nil {
				return err
			}
		}
		return nil
	}
	asnmapIPs.ParseOutput = func(_ *engine.Job) int {
		return countFileLines(ctx.asnIPsOut) + countFileLines(ctx.ipRangesOut)
	}
	jobs = append(jobs, asnmapIPs)

	amassIntel := engine.NewJob(1, "amass-intel", "amass", nil)
	amassIntel.Description = "Organization-level reconnaissance via amass intel"
	amassIntel.OutputFile = filepath.Join(ctx.subsDir, "amass_intel.txt")
	amassIntel.Timeout = 10 * time.Minute
	amassIntel.Execute = func(execCtx context.Context, j *engine.Job) error {
		if strings.TrimSpace(ctx.orgName) == "" {
			markSkipped(j, "organization name not set; skipping amass intel")
			return nil
		}
		return runCommand(execCtx, ctx.runCfg, "amass", []string{"intel", "-org", ctx.orgName, "-o", j.OutputFile})
	}
	amassIntel.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, amassIntel)

	uncover := engine.NewJob(1, "uncover", "uncover", nil)
	uncover.Description = "Search internet datasets for related hosts"
	uncover.OutputFile = filepath.Join(ctx.subsDir, "uncover.txt")
	uncover.Timeout = 10 * time.Minute
	uncover.Execute = func(execCtx context.Context, j *engine.Job) error {
		all := make([]string, 0, 1024)
		sslRows, err := collectCommandLines(execCtx, ctx.runCfg, "uncover", []string{"-q", "ssl:" + ctx.domain, "-e", "shodan,censys,fofa", "-silent"}, "")
		if err == nil {
			all = append(all, sslRows...)
		} else {
			j.LogLine("[WARN] uncover ssl query failed: " + err.Error())
		}
		if strings.TrimSpace(ctx.orgName) != "" {
			orgRows, orgErr := collectCommandLines(execCtx, ctx.runCfg, "uncover", []string{"-q", "org:\"" + ctx.orgName + "\"", "-e", "shodan,censys,fofa", "-silent"}, "")
			if orgErr == nil {
				all = append(all, orgRows...)
			} else {
				j.LogLine("[WARN] uncover org query failed: " + orgErr.Error())
			}
		}
		if len(all) == 0 {
			markSkipped(j, "uncover produced no results")
			return nil
		}
		filtered := make([]string, 0, len(all))
		for _, row := range all {
			normalized := normalizeSubdomain(hostFromAny(row), ctx.domain)
			if normalized != "" {
				filtered = append(filtered, normalized)
			}
		}
		if len(filtered) == 0 {
			markSkipped(j, "uncover results were out-of-scope")
			return nil
		}
		return writeUniqueLines(j.OutputFile, filtered)
	}
	uncover.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, uncover)

	hakrevdns := engine.NewJob(1, "hakrevdns", "hakrevdns", []string{"-d"})
	hakrevdns.Description = "Reverse DNS on discovered IP ranges"
	hakrevdns.OutputFile = ctx.rdnsOut
	hakrevdns.DependsOn = []string{asnmapIPs.ID}
	hakrevdns.Timeout = 10 * time.Minute
	hakrevdns.Execute = func(execCtx context.Context, j *engine.Job) error {
		inputFile := pickExisting(ctx.ipRangesOut, ctx.asnIPsOut)
		if inputFile == "" {
			markSkipped(j, "no IP range input available for hakrevdns")
			return nil
		}
		inputLines := readNonEmptyLines(inputFile)
		if len(inputLines) == 0 {
			markSkipped(j, "no IP data available for hakrevdns")
			return nil
		}
		stream := strings.Join(inputLines, "\n") + "\n"
		if _, err := exec.LookPath("mapcidr"); err == nil {
			expanded, mapErr := collectCommandLines(execCtx, ctx.runCfg, "mapcidr", []string{"-silent"}, stream)
			if mapErr == nil && len(expanded) > 0 {
				stream = strings.Join(expanded, "\n") + "\n"
			}
		}
		rdnsLines, err := collectCommandLines(execCtx, ctx.runCfg, "hakrevdns", []string{"-d"}, stream)
		if err != nil {
			return err
		}
		filtered := make([]string, 0, len(rdnsLines))
		for _, line := range rdnsLines {
			normalized := normalizeSubdomain(hostFromAny(line), ctx.domain)
			if normalized != "" {
				filtered = append(filtered, normalized)
			}
		}
		if len(filtered) == 0 {
			markSkipped(j, "hakrevdns produced no in-scope domains")
			return nil
		}
		return writeUniqueLines(j.OutputFile, filtered)
	}
	hakrevdns.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, hakrevdns)

	shodanSubs := engine.NewJob(1, "shodan-subs", "shosubgo", nil)
	shodanSubs.Description = "Subdomain discovery from Shodan"
	shodanSubs.OutputFile = filepath.Join(ctx.subsDir, "shodan_subs.txt")
	shodanSubs.Timeout = 10 * time.Minute
	shodanSubs.Execute = func(execCtx context.Context, j *engine.Job) error {
		key := firstNonEmptyEnv("SHODAN_API_KEY", "SHODAN_KEY")
		if key == "" {
			markSkipped(j, "SHODAN_API_KEY not set, skipping shosubgo")
			return nil
		}
		return runStdoutToFile(execCtx, ctx.runCfg, "shosubgo", []string{"-d", ctx.domain, "-s", key}, j.OutputFile)
	}
	shodanSubs.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, shodanSubs)

	csprecon := engine.NewJob(1, "csprecon", "csprecon", nil)
	csprecon.Description = "Extract CSP-linked domains"
	csprecon.OutputFile = filepath.Join(ctx.subsDir, "csp_domains.txt")
	csprecon.Timeout = 10 * time.Minute
	csprecon.Execute = func(execCtx context.Context, j *engine.Job) error {
		if err := runCommandWithStdinToFile(execCtx, ctx.runCfg, "csprecon", []string{}, ctx.domain+"\n", j.OutputFile); err != nil {
			return err
		}
		rows := readNonEmptyLines(j.OutputFile)
		filtered := make([]string, 0, len(rows))
		for _, row := range rows {
			normalized := normalizeSubdomain(hostFromAny(row), ctx.domain)
			if normalized != "" {
				filtered = append(filtered, normalized)
			}
		}
		if len(filtered) == 0 {
			markSkipped(j, "csprecon produced no in-scope domains")
			return nil
		}
		return writeUniqueLines(j.OutputFile, filtered)
	}
	csprecon.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, csprecon)

	return jobs, asnmapIPs.ID
}

