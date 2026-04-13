package phase9

import (
	"html"
	"os"
	"strings"
)

func generateHTML(markdownFile string, outputFile string) error {
	raw, err := os.ReadFile(markdownFile)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	var body strings.Builder
	inCode := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			if inCode {
				body.WriteString("</code></pre>")
				inCode = false
			} else {
				body.WriteString("<pre><code>")
				inCode = true
			}
			continue
		}
		if inCode {
			body.WriteString(html.EscapeString(line) + "\n")
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "### "):
			body.WriteString("<h3>" + html.EscapeString(strings.TrimPrefix(trimmed, "### ")) + "</h3>")
		case strings.HasPrefix(trimmed, "## "):
			body.WriteString("<h2>" + html.EscapeString(strings.TrimPrefix(trimmed, "## ")) + "</h2>")
		case strings.HasPrefix(trimmed, "# "):
			body.WriteString("<h1>" + html.EscapeString(strings.TrimPrefix(trimmed, "# ")) + "</h1>")
		case strings.HasPrefix(trimmed, "- "):
			body.WriteString("<li>" + html.EscapeString(strings.TrimPrefix(trimmed, "- ")) + "</li>")
		case trimmed == "":
			body.WriteString("<br/>")
		default:
			body.WriteString("<p>" + html.EscapeString(trimmed) + "</p>")
		}
	}
	doc := "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>N0RMXL Report</title><style>body{font-family:Segoe UI,Arial,sans-serif;background:#0f1115;color:#e6edf3;line-height:1.5;padding:24px}h1,h2,h3{color:#f85149}pre{background:#161b22;border:1px solid #30363d;padding:12px;overflow:auto}li{margin:4px 0}p{margin:8px 0}a{color:#58a6ff}</style></head><body>" + body.String() + "</body></html>"
	return writeText(outputFile, doc)
}
