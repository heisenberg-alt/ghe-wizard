package report

import (
	"fmt"
	"html"
)

// Badge renders a small Shields-style SVG badge showing the score and grade,
// colored by grade. It is self-contained (no external assets).
func Badge(score int) string {
	g := grade(score)
	right := fmt.Sprintf("%d/100 %s", score, g.letter)
	label := "GHE best practices"

	// Approximate text widths (6px/char at 11px font) for layout.
	lw := 7*len(label)/1 + 10 // label side padding
	if lw < 118 {
		lw = 118
	}
	rw := 7*len(right)/1 + 10
	if rw < 78 {
		rw = 78
	}
	total := lw + rw

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">
<title>%s: %s</title>
<linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">
<rect width="%d" height="20" fill="#555"/>
<rect x="%d" width="%d" height="20" fill="%s"/>
<rect width="%d" height="20" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
<text x="%d" y="14">%s</text>
<text x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
<text x="%d" y="14">%s</text>
</g>
</svg>`,
		total, html.EscapeString(label), html.EscapeString(right),
		html.EscapeString(label), html.EscapeString(right),
		total,
		lw,
		lw, rw, g.color,
		total,
		lw/2, html.EscapeString(label),
		lw/2, html.EscapeString(label),
		lw+rw/2, html.EscapeString(right),
		lw+rw/2, html.EscapeString(right),
	)
}
