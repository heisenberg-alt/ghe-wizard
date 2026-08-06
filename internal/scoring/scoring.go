// Package scoring centralizes the score-to-grade mapping so every surface
// (reports, badges, notifications, dashboard) uses identical thresholds.
package scoring

// Grade thresholds (inclusive lower bounds).
const (
	thresholdA = 90
	thresholdB = 75
	thresholdC = 60
	thresholdD = 40
)

// Letter returns the A–F grade for a 0–100 score.
func Letter(score int) string {
	switch {
	case score >= thresholdA:
		return "A"
	case score >= thresholdB:
		return "B"
	case score >= thresholdC:
		return "C"
	case score >= thresholdD:
		return "D"
	default:
		return "F"
	}
}

// Color returns a hex color aligned with the grade (green→red).
func Color(score int) string {
	switch {
	case score >= thresholdB: // A, B
		return "#2ea043"
	case score >= thresholdC: // C
		return "#d29922"
	case score >= thresholdD: // D
		return "#db6d28"
	default: // F
		return "#f85149"
	}
}
