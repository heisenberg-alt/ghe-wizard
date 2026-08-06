package web

import "io/fs"

// fsSub returns the embedded UI directory rooted so index.html is served at "/".
func fsSub() (fs.FS, error) {
	return fs.Sub(uiFS, "ui")
}
