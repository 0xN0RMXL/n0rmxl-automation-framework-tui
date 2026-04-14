package screens

import (
	"fmt"
	"strings"
)

const (
	minTerminalWidth  = 72
	minTerminalHeight = 20
)

func clampInt(value int, low int, high int) int {
	if high < low {
		high = low
	}
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func screenContentWidth(width int) int {
	if width <= 0 {
		return 80
	}
	w := width - 4
	if w < 24 {
		return 24
	}
	return w
}

func screenContentHeight(height int) int {
	if height <= 0 {
		return 24
	}
	h := height - 4
	if h < 8 {
		return 8
	}
	return h
}

func splitColumns(total int, minLeft int, minRight int, gap int) (int, int, bool) {
	if gap < 0 {
		gap = 0
	}
	if total < (minLeft + minRight + gap) {
		return total, total, true
	}

	left := (total - gap) / 2
	right := total - gap - left

	if left < minLeft {
		left = minLeft
		right = total - gap - left
	}
	if right < minRight {
		right = minRight
		left = total - gap - right
	}
	if left < minLeft || right < minRight {
		return total, total, true
	}
	return left, right, false
}

func responsiveSizeNotice(width int, height int) string {
	return fmt.Sprintf("Terminal is too small for the full layout (%dx%d). Minimum recommended size is %dx%d.", width, height, minTerminalWidth, minTerminalHeight)
}

func truncateText(value string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maxWidth {
		return value
	}
	if maxWidth == 1 {
		return string(runes[:1])
	}
	return string(runes[:maxWidth-1]) + "…"
}
