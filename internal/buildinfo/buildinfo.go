// Package buildinfo exposes version metadata, injected at build time via
// -ldflags "-X". It falls back to Go module build info when not injected.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// These are overridden at build time:
//
//	go build -ldflags "-X github.com/ghe-wizard/ghe-wizard/internal/buildinfo.Version=v1.1.0 \
//	  -X github.com/ghe-wizard/ghe-wizard/internal/buildinfo.Commit=$(git rev-parse --short HEAD) \
//	  -X github.com/ghe-wizard/ghe-wizard/internal/buildinfo.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var (
	Version = ""
	Commit  = ""
	Date    = ""
)

// Info is a structured view of the build metadata.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the resolved build info, falling back to VCS data embedded by
// the Go toolchain when explicit ldflags were not provided.
func Get() Info {
	i := Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if i.Version == "" && bi.Main.Version != "" {
			i.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if i.Commit == "" && len(s.Value) >= 7 {
					i.Commit = s.Value[:7]
				}
			case "vcs.time":
				if i.Date == "" {
					i.Date = s.Value
				}
			}
		}
	}
	if i.Version == "" {
		i.Version = "dev"
	}
	if i.Commit == "" {
		i.Commit = "none"
	}
	if i.Date == "" {
		i.Date = "unknown"
	}
	return i
}

// String renders a one-line human-readable version banner.
func (i Info) String() string {
	return fmt.Sprintf("ghe-wizard %s (commit %s, built %s, %s %s/%s)",
		i.Version, i.Commit, i.Date, i.GoVersion, i.OS, i.Arch)
}
