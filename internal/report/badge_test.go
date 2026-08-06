package report

import (
	"strings"
	"testing"
)

func TestBadge(t *testing.T) {
	svg := Badge(53)
	for _, want := range []string{"<svg", "53/100", "GHE best practices", "</svg>"} {
		if !strings.Contains(svg, want) {
			t.Errorf("badge missing %q", want)
		}
	}
	// Grade color for a D (40-59) should be the "error" orange.
	if !strings.Contains(Badge(45), "#db6d28") {
		t.Error("expected grade-D color in badge")
	}
	if !strings.Contains(Badge(95), "#2ea043") {
		t.Error("expected grade-A green in badge")
	}
}
