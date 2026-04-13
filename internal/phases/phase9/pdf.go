package phase9

import (
	"fmt"
	"os/exec"
)

func generatePDF(htmlFile string, outputFile string) error {
	for _, candidate := range []string{"chromium", "chromium-browser", "google-chrome", "chrome"} {
		if _, err := exec.LookPath(candidate); err == nil {
			args := []string{"--headless", "--disable-gpu", "--print-to-pdf=" + outputFile, htmlFile}
			if err := exec.Command(candidate, args...).Run(); err == nil {
				return nil
			}
		}
	}
	if _, err := exec.LookPath("wkhtmltopdf"); err == nil {
		if err := exec.Command("wkhtmltopdf", "--quiet", htmlFile, outputFile).Run(); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no PDF renderer available (chromium/chrome/wkhtmltopdf)")
}
