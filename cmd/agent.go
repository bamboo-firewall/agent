package main

import (
	"log/slog"
	"os"

	"github.com/bamboo-firewall/agent/internal/daemon"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	daemon.Run()
}
