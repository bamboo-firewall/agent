package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/spf13/viper"

	"github.com/bamboo-firewall/agent/config"
	"github.com/bamboo-firewall/agent/internal/daemon"
)

func main() {
	var pathConfig string
	flag.StringVar(&pathConfig, "config-file", "", "path to env config file")
	flag.Parse()

	cfg, err := loadConfig(pathConfig)
	if err != nil {
		slog.Warn("read config from file fail", "error", err)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	daemon.Run(cfg)
}

func loadConfig(path string) (config.Config, error) {
	viper.AutomaticEnv()
	if path != "" {
		viper.SetConfigFile(path)
		if err := viper.ReadInConfig(); err != nil {
			return config.Config{}, err
		}
	}
	return config.Config{
		APIServerAddress:           viper.GetString("API_SERVER_ADDRESS"),
		APIServerIPv4:              viper.GetString("API_SERVER_IPV4"),
		IPTablesLockSecondsTimeout: viper.GetInt("IPTABLES_LOCK_SECONDS_TIMEOUT"),
		HostName:                   viper.GetString("HOST_NAME"),
		DatastoreRefreshInterval:   viper.GetDuration("DATASTORE_REFRESH_INTERVAL"),
		DataplaneRefreshInterval:   viper.GetDuration("DATAPLANE_REFRESH_INTERVAL"),
	}, nil
}
