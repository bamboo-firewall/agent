package daemon

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bamboo-firewall/agent/config"
	"github.com/bamboo-firewall/agent/internal/dataplane/linux"
	"github.com/bamboo-firewall/agent/pkg/apiserver/client"
	"github.com/bamboo-firewall/agent/pkg/apiserver/dto"
	"github.com/bamboo-firewall/agent/pkg/model"
	"github.com/bamboo-firewall/agent/pkg/utils"
)

const (
	defaultDatastoreRefreshInterval = 5 * time.Second
)

type dataplaneDriver interface {
	SendMessage(msg interface{}) error
	ReceiveMessage() (interface{}, error)
	Start()
}

type apiServer interface {
	FetchHostEndpointPolicy(ctx context.Context, hostName string) (*dto.HostEndpointPolicy, error)
}

type dataplaneConnector struct {
	dataplane                  dataplaneDriver
	apiServer                  apiServer
	hostEndpointPolicyMetadata *model.HostEndpointPolicyMetadata
	hostName                   string
	dataStoreRefreshInterval   time.Duration
	ctx                        context.Context
	ctxCancelFunc              context.CancelFunc
}

func Run(conf config.Config) {
	ctx, cancel := context.WithCancel(context.Background())
	dataplane, err := linux.NewInternalDataplane(ctx, conf)
	if err != nil {
		log.Fatal(err)
	}
	as := client.NewAPIServer(conf.APIServerAddress)
	if err = as.Ping(ctx); err != nil {
		log.Fatal(err)
	}
	var datastoreRefreshInterval time.Duration
	if conf.DatastoreRefreshInterval <= 0 {
		datastoreRefreshInterval = defaultDatastoreRefreshInterval
	} else {
		datastoreRefreshInterval = conf.DatastoreRefreshInterval
	}
	connector := &dataplaneConnector{
		dataplane:                dataplane,
		apiServer:                as,
		hostName:                 conf.HostName,
		dataStoreRefreshInterval: datastoreRefreshInterval,
		ctx:                      ctx,
		ctxCancelFunc:            cancel,
	}

	go interruptHandle(connector)

	var wg sync.WaitGroup
	wg.Add(2)

	// start interval sync to dataplane
	go func() {
		defer wg.Done()
		connector.dataplane.Start()
	}()
	// start interval sync message from api-server
	go func() {
		defer wg.Done()
		connector.sendMessageToDataplaneDriver()
	}()

	wg.Wait()
	slog.Info("agent exited")
}

func interruptHandle(dc *dataplaneConnector) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	slog.Debug("listening signal...")
	s := <-c
	slog.Info("shutting down server ...", "received signal.", s)

	dc.ctxCancelFunc()
}

func (dc *dataplaneConnector) sendMessageToDataplaneDriver() {
	timer := time.NewTimer(dc.dataStoreRefreshInterval)
	for {
		var (
			hostEndpointPolicy *dto.HostEndpointPolicy
			err                error
		)
		utils.ResetTimer(timer, dc.dataStoreRefreshInterval)
		select {
		case <-timer.C:
			hostEndpointPolicy, err = dc.apiServer.FetchHostEndpointPolicy(dc.ctx, dc.hostName)
			if err != nil {
				// ToDo: check connection or handle error need to retry or not
				slog.Error("fetch host endpoint policies error:", "err", err)
				continue
			}
		case <-dc.ctx.Done():
			slog.Info("stop fetch agent")
			return
		}
		if !dc.isNeedUpdatePolicy(hostEndpointPolicy.MetaData) {
			continue
		}
		dc.hostEndpointPolicyMetadata = &model.HostEndpointPolicyMetadata{
			HEPVersions: hostEndpointPolicy.MetaData.HEPVersions,
			GNPVersions: hostEndpointPolicy.MetaData.GNPVersions,
			GNSVersions: hostEndpointPolicy.MetaData.GNSVersions,
		}

		if err = dc.dataplane.SendMessage(hostEndpointPolicy); err != nil {
			slog.Info("send message error:", "err", err)
		}
	}
}

func (dc *dataplaneConnector) isNeedUpdatePolicy(newVersion dto.HostEndPointPolicyMetadata) bool {
	if dc.hostEndpointPolicyMetadata == nil {
		return true
	}
	newGNPVersions := newVersion.GNPVersions
	newHEPVersions := dc.hostEndpointPolicyMetadata.HEPVersions
	newGNSVersions := newVersion.GNSVersions
	if len(newGNPVersions) != len(dc.hostEndpointPolicyMetadata.GNPVersions) {
		return true
	}
	if len(newHEPVersions) != len(dc.hostEndpointPolicyMetadata.HEPVersions) {
		return true
	}
	if len(newGNSVersions) != len(dc.hostEndpointPolicyMetadata.GNSVersions) {
		return true
	}
	for currentUUID, currentVersion := range dc.hostEndpointPolicyMetadata.GNPVersions {
		_, ok := newGNPVersions[currentUUID]
		if !ok || currentVersion != newGNPVersions[currentUUID] {
			return true
		}
	}
	for currentUUID, currentVersion := range dc.hostEndpointPolicyMetadata.HEPVersions {
		_, ok := newHEPVersions[currentUUID]
		if !ok || currentVersion != newHEPVersions[currentUUID] {
			return true
		}
	}
	for currentUUID, currentVersion := range dc.hostEndpointPolicyMetadata.GNSVersions {
		_, ok := newGNSVersions[currentUUID]
		if !ok || currentVersion != newGNSVersions[currentUUID] {
			return true
		}
	}
	return false
}
