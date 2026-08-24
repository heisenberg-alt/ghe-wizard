package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/ghe-wizard/ghe-wizard/internal/usage"
)

// cmdUsage renders the Copilot usage, spend & ROI report (Phase C surface).
func cmdUsage(args []string) error {
	fs := flag.NewFlagSet("usage", flag.ExitOnError)
	o := registerCommonFlags(fs)
	format := fs.String("format", "md", "output format: md|json|csv (csv = the reclaim list)")
	out := fs.String("out", "", "write output to a file instead of stdout")
	_ = fs.Parse(args)
	return runUsageReport(o, *format, *out)
}

// cmdSeats is the reclaim-focused shortcut: the usage report defaulting to
// the reclaim-list CSV.
func cmdSeats(args []string) error {
	fs := flag.NewFlagSet("seats", flag.ExitOnError)
	o := registerCommonFlags(fs)
	format := fs.String("format", "csv", "output format: csv|md|json")
	out := fs.String("out", "", "write output to a file instead of stdout")
	_ = fs.Parse(args)
	return runUsageReport(o, *format, *out)
}

func runUsageReport(o *commonOpts, format, out string) error {
	a, err := buildAssessment(o)
	if err != nil {
		return err
	}
	ctx := context.Background()
	rep, err := usage.Collect(ctx, a.eng.API(), a.cfg)
	if err != nil {
		return err
	}
	var data string
	switch format {
	case "md":
		data = rep.Markdown()
	case "json":
		b, err := rep.JSON()
		if err != nil {
			return err
		}
		data = string(b)
	case "csv":
		data = rep.ReclaimCSV()
	default:
		return fmt.Errorf("unknown format %q (use md, json or csv)", format)
	}
	if out != "" {
		if err := os.WriteFile(out, []byte(data), 0o600); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", out)
	} else {
		fmt.Print(data)
	}
	if len(rep.Reclaim) > 0 {
		fmt.Fprintf(os.Stderr, "%d reclaimable seat(s); reclaim via: ghe-wizard apply --rules SEAT-01,SEAT-02,SEAT-03 --allow-destructive --dry-run\n",
			len(rep.Reclaim))
	}
	return nil
}
