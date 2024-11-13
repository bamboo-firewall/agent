package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	APIServerAddress           string
	APIServerIPv4              string
	TenantID                   uint64
	HostIP                     string
	IPV6Support                bool
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
		TenantID:                   viper.GetUint64("TENANT_ID"),
		HostIP:                     viper.GetString("HOST_IPV4"),
		IPV6Support:                viper.GetBool("IPV6_SUPPORT"),
		IPTablesLockSecondsTimeout: viper.GetInt("IPTABLES_LOCK_SECONDS_TIMEOUT"),
		DatastoreRefreshInterval:   viper.GetDuration("DATASTORE_REFRESH_INTERVAL"),
		DataplaneRefreshInterval:   viper.GetDuration("DATAPLANE_REFRESH_INTERVAL"),
		Debug:                      viper.GetBool("DEBUG"),
	}, nil
}
