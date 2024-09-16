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
	FetchPolicies(ctx context.Context, hostName string) (*dto.FetchPoliciesOutput, error)
}

type dataplaneConnector struct {
	dataplane                dataplaneDriver
	apiServer                apiServer
	hostName                 string
	dataStoreRefreshInterval time.Duration
	ctx                      context.Context
	ctxCancelFunc            context.CancelFunc
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

	slog.Debug("Listening Signal...")
	s := <-c
	slog.Info("Shutting down Server ...", "Received signal.", s)

	dc.ctxCancelFunc()
}

func (dc *dataplaneConnector) sendMessageToDataplaneDriver() {
	timer := time.NewTimer(dc.dataStoreRefreshInterval)
	for {
		var (
			msg *dto.FetchPoliciesOutput
			err error
		)
		utils.ResetTimer(timer, dc.dataStoreRefreshInterval)
		select {
		case <-timer.C:
			msg, err = dc.apiServer.FetchPolicies(dc.ctx, dc.hostName)
			if err != nil {
				// ToDo: check connection or handle error need to retry or not
				slog.Error("fetch new policy error:", err)
				continue
			}
		case <-dc.ctx.Done():
			slog.Info("stop fetch agent")
			return
		}
		policy := convertAPIToAgentModel(msg)
		if policy == nil {
			continue
		}
		slog.Info("policy", "policy", policy)

		// convert rule here
		if err = dc.dataplane.SendMessage(policy); err != nil {
			slog.Info("send message error:", err)
		}
	}
}

func convertAPIToAgentModel(agentDTO *dto.FetchPoliciesOutput) *model.Agent {
	if agentDTO == nil {
		return nil
	}
	if !agentDTO.IsNew {
		return nil
	}
	agentPolicy := new(model.AgentPolicy)
	for _, policy := range agentDTO.GNPs {
		inboundRules := make([]*model.Rule, 0)
		outboundRules := make([]*model.Rule, 0)
		for _, rule := range policy.Spec.Ingress {
			inboundRules = append(inboundRules, &model.Rule{
				Action:    rule.Action,
				IPVersion: 4,
				//Metadata:                rule.Metadata,
				Protocol:                rule.Protocol,
				SrcNets:                 rule.Source.Nets,
				SrcPorts:                rule.Source.Ports,
				SrcNamedPortIpSetIDs:    nil,
				DstNets:                 rule.Destination.Nets,
				DstPorts:                rule.Destination.Ports,
				DstNamedPortIpSetIDs:    nil,
				NotProtocol:             "",
				NotSrcNets:              nil,
				NotSrcPorts:             nil,
				NotSrcNamedPortIpSetIDs: nil,
				NotDstNets:              nil,
				NotDstPorts:             nil,
				NotDstNamedPortIpSetIDs: nil,
			})
		}

		for _, rule := range policy.Spec.Egress {
			outboundRules = append(outboundRules, &model.Rule{
				Action:    rule.Action,
				IPVersion: 4,
				//Metadata:                rule.Metadata,
				Protocol:                rule.Protocol,
				SrcNets:                 rule.Source.Nets,
				SrcPorts:                rule.Source.Ports,
				SrcNamedPortIpSetIDs:    nil,
				DstNets:                 rule.Destination.Nets,
				DstPorts:                rule.Destination.Ports,
				DstNamedPortIpSetIDs:    nil,
				NotProtocol:             "",
				NotSrcNets:              nil,
				NotSrcPorts:             nil,
				NotSrcNamedPortIpSetIDs: nil,
				NotDstNets:              nil,
				NotDstPorts:             nil,
				NotDstNamedPortIpSetIDs: nil,
			})
		}
		agentPolicy.Policies = append(agentPolicy.Policies, &model.Policy{
			ID:            policy.ID,
			InboundRules:  inboundRules,
			OutboundRules: outboundRules,
		})
	}
	agentIPSet := new(model.AgentIPSet)
	for _, ipset := range agentDTO.GNSs {
		agentIPSet.IPSets = append(agentIPSet.IPSets, &model.IPSet{
			ID:        ipset.ID,
			Version:   ipset.Version,
			Name:      ipset.Metadata.Name,
			IPVersion: ipset.Metadata.IPVersion,
			Members:   ipset.Spec.Nets,
		})
	}
	return &model.Agent{
		Policy: agentPolicy,
		IPSet:  agentIPSet,
	}
}
