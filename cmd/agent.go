package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/bamboo-firewall/agent/config"
	"github.com/bamboo-firewall/agent/internal/daemon"
)

func main() {
	var pathConfig string
	flag.StringVar(&pathConfig, "config-file", "", "path to env config file")
	flag.Parse()

	cfg, err := config.New(pathConfig)
	if err != nil {
		slog.Warn("read config from file fail", "error", err)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	daemon.Run(cfg)
}
