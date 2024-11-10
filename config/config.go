package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	APIServerAddress           string
	APIServerIPv4              string
	IPTablesLockSecondsTimeout int
	DatastoreRefreshInterval   time.Duration
	DataplaneRefreshInterval   time.Duration
	Debug                      bool
}

func New(path string) (Config, error) {
	viper.AutomaticEnv()
	if path != "" {
		viper.SetConfigFile(path)
		if err := viper.ReadInConfig(); err != nil {
			return Config{}, err
		}
	}
	return Config{
		APIServerAddress:           viper.GetString("API_SERVER_ADDRESS"),
		APIServerIPv4:              viper.GetString("API_SERVER_IPV4"),
		IPTablesLockSecondsTimeout: viper.GetInt("IPTABLES_LOCK_SECONDS_TIMEOUT"),
		DatastoreRefreshInterval:   viper.GetDuration("DATASTORE_REFRESH_INTERVAL"),
		DataplaneRefreshInterval:   viper.GetDuration("DATAPLANE_REFRESH_INTERVAL"),
		Debug:                      viper.GetBool("DEBUG"),
	}, nil
}
