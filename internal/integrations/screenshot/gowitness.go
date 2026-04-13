package screenshot

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Screenshotter struct {
	gowitness string
	outputDir string
}

func NewScreenshotter(outputDir string) *Screenshotter {
	outputDir = strings.TrimSpace(outputDir)
	if outputDir == "" {
		outputDir = filepath.ToSlash(filepath.Join(".", "screenshots"))
	}
	return &Screenshotter{
		gowitness: "gowitness",
		outputDir: outputDir,
	}
}

func (s *Screenshotter) Screenshot(rawURL string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("screenshotter is nil")
	}
	if !s.IsAvailable() {
		return "", fmt.Errorf("gowitness is not available in PATH")
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("url is required")
	}
	if err := os.MkdirAll(s.outputDir, 0o755); err != nil {
		return "", err
	}
	before := latestPNG(s.outputDir)
	cmd := exec.Command(s.gowitness, "single", "-u", rawURL, "-P", s.outputDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("gowitness single failed: %s", msg)
	}
	after := latestPNG(s.outputDir)
	if after == "" {
		return "", nil
	}
	if before != "" && before == after {
		return after, nil
	}
	return after, nil
}

func (s *Screenshotter) ScreenshotList(urlFile string, outputDir string) error {
	if s == nil {
		return fmt.Errorf("screenshotter is nil")
	}
	if !s.IsAvailable() {
		return fmt.Errorf("gowitness is not available in PATH")
	}
	urlFile = strings.TrimSpace(urlFile)
	if urlFile == "" {
		return fmt.Errorf("url file is required")
	}
	outputDir = strings.TrimSpace(outputDir)
	if outputDir == "" {
		outputDir = s.outputDir
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	cmd := exec.Command(s.gowitness, "file", "-f", urlFile, "-P", outputDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("gowitness file failed: %s", msg)
	}
	return nil
}

func (s *Screenshotter) IsAvailable() bool {
	if s == nil {
		return false
	}
	_, err := exec.LookPath(s.gowitness)
	return err == nil
}

func latestPNG(root string) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return ""
	}
	var bestPath string
	var bestTime time.Time
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".png" {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil {
			return nil
		}
		if info.ModTime().After(bestTime) {
			bestTime = info.ModTime()
			bestPath = path
		}
		return nil
	})
	return bestPath
}
