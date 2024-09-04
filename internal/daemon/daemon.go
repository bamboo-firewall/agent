package daemon

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/bamboo-firewall/agent/internal/dataplane/linux"
	"github.com/bamboo-firewall/agent/pkg/apiserver/client"
	"github.com/bamboo-firewall/agent/pkg/utils"
)

type dataplaneDriver interface {
	SendMessage(msg interface{}) error
	ReceiveMessage() (interface{}, error)
	Start()
}

type apiServer interface {
	FetchNewPolicy() (interface{}, error)
}

type dataplaneConnector struct {
	dataplane     dataplaneDriver
	apiServer     apiServer
	ctx           context.Context
	ctxCancelFunc context.CancelFunc
}

func Run() {
	ctx, cancel := context.WithCancel(context.Background())
	connector := &dataplaneConnector{
		dataplane:     linux.NewInternalDataplane(ctx),
		apiServer:     client.NewAPIServer(),
		ctx:           ctx,
		ctxCancelFunc: cancel,
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

	slog.Debug("Listening Signal...")
	s := <-c
	slog.Info("Shutting down Server ...", "Received signal.", s)

	dc.ctxCancelFunc()
}

func (dc *dataplaneConnector) sendMessageToDataplaneDriver() {
	intervalTime := 5 * time.Second
	timer := time.NewTimer(intervalTime)
	for {
		var (
			msg interface{}
			err error
		)
		utils.ResetTimer(timer, intervalTime)
		select {
		case <-timer.C:
			msg, err = dc.apiServer.FetchNewPolicy()
			if err != nil {
				// ToDo: check connection or handle error need to retry or not
				slog.Info("fetch new policy error:", err)
				continue
			}
		case <-dc.ctx.Done():
			slog.Info("stop fetch agent")
			return
		}
		if msg == nil {
			continue
		}
		if err = dc.dataplane.SendMessage(msg); err != nil {
			slog.Info("send message error:", err)
		}
	}
}
