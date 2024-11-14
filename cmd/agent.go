package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"

	"github.com/bamboo-firewall/agent/buildinfo"
	"github.com/bamboo-firewall/agent/config"
	"github.com/bamboo-firewall/agent/internal/daemon"
)

func main() {
	var (
		pathConfig  string
		versionFlag bool
	)
	flag.StringVar(&pathConfig, "config-file", "", "path to env config file")
	flag.BoolVar(&versionFlag, "version", false, "Show version information.")
	flag.Parse()

	if versionFlag {
		version := fmt.Sprintf("Version: \t %s \nBranch: \t %s\nBuild: \t %s\nOrganization: \t %s", buildinfo.Version, buildinfo.GitBranch, buildinfo.BuildDate, buildinfo.Organization)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 0, ' ', tabwriter.TabIndent)
		fmt.Fprintln(w, version)
		w.Flush()
		os.Exit(0)
	}

	cfg, err := config.New(pathConfig)
	if err != nil {
		slog.Warn("read config from file fail", "error", err)
	}

	var logLevel slog.Level
	if cfg.Debug {
		logLevel = slog.LevelDebug
	} else {
		logLevel = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))
	daemon.Run(cfg)
}
