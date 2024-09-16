package config

import "time"

type Config struct {
	APIServerAddress           string
	APIServerIPv4              string
	IPTablesLockSecondsTimeout int
	HostName                   string
	DatastoreRefreshInterval   time.Duration
	DataplaneRefreshInterval   time.Duration
}
