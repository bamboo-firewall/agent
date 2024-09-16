package linux

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bamboo-firewall/agent/config"
	"github.com/bamboo-firewall/agent/internal/dataplane/linux/manager"
	"github.com/bamboo-firewall/agent/internal/dataplane/linux/rulerenderer"
	"github.com/bamboo-firewall/agent/pkg/generictables"
	"github.com/bamboo-firewall/agent/pkg/ipset"
	"github.com/bamboo-firewall/agent/pkg/iptables"
	"github.com/bamboo-firewall/agent/pkg/utils"
)

const (
	defaultDataplaneRefreshInterval = 5 * time.Second
)

type Manager interface {
	OnUpdate(msg interface{})
}

type InternalDataplane struct {
	parentCtx     context.Context
	toDataplane   chan interface{}
	fromDataplane chan interface{}

	// allTables contains filterTables
	allTables []generictables.Table

	filterTables []generictables.Table

	ipsets []*ipset.IPSet

	managers []Manager

	// datastoreInSync set to true after we receive message from datastore
	datastoreInSync bool

	// dataplaneNeedsSync set to true when a certain period of time allows
	dataplaneNeedsSync bool

	// dataplaneRefreshInterval interval time to refresh dataplane
	dataplaneRefreshInterval time.Duration

	// apiServerIPV4 allow agent call to api-server
	apiServerIPV4 string
}

func NewInternalDataplane(parentCtx context.Context, conf config.Config) (*InternalDataplane, error) {
	dp := &InternalDataplane{
		parentCtx:     parentCtx,
		toDataplane:   make(chan interface{}),
		fromDataplane: make(chan interface{}),
	}

	if conf.DataplaneRefreshInterval <= 0 {
		dp.dataplaneRefreshInterval = defaultDataplaneRefreshInterval
	} else {
		dp.dataplaneRefreshInterval = conf.DataplaneRefreshInterval
	}

	ipsetV4, err := ipset.NewIPSet(generictables.IPFamily4)
	if err != nil {
		return nil, fmt.Errorf("new ipset v4 failed: %w", err)
	}
	ipsetV6, err := ipset.NewIPSet(generictables.IPFamily6)
	if err != nil {
		return nil, fmt.Errorf("new ipset v6 failed: %w", err)
	}

	filerTableIPV4, err := iptables.NewTable(
		generictables.TableFilter,
		generictables.HashPrefix,
		iptables.WithIPFamily(generictables.IPFamily4),
		iptables.WithLockSecondsTimeout(conf.IPTablesLockSecondsTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("new iptables v4 failed: %w", err)
	}
	filterTableIPV6, err := iptables.NewTable(
		generictables.TableFilter,
		generictables.HashPrefix,
		iptables.WithIPFamily(generictables.IPFamily6),
		iptables.WithLockSecondsTimeout(conf.IPTablesLockSecondsTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("new iptables v6 failed: %w", err)
	}

	ruleRenderer := rulerenderer.NewRenderer(generictables.LogPrefix)

	dp.managers = append(dp.managers,
		manager.NewIPSet(ipsetV4),
		manager.NewIPSet(ipsetV6),
		manager.NewPolicy(filerTableIPV4, generictables.IPFamily4, conf.APIServerIPv4, ruleRenderer),
		manager.NewPolicy(filterTableIPV6, generictables.IPFamily6, conf.APIServerIPv4, ruleRenderer),
	)

	dp.filterTables = append(dp.filterTables,
		filerTableIPV4,
		filterTableIPV6,
	)
	dp.ipsets = append(dp.ipsets, ipsetV4, ipsetV6)

	dp.allTables = append(dp.allTables, dp.filterTables...)
	return dp, nil
}

func (dp *InternalDataplane) Start() {
	dp.setStaticConfigForDataplane()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		dp.intervalUpdateDataplane()
	}()
	wg.Wait()
}

func (dp *InternalDataplane) setStaticConfigForDataplane() {
	dp.setStaticIptables()
}

func (dp *InternalDataplane) setStaticIptables() {
	for _, filterTable := range dp.filterTables {
		filterTable.SetDefaultRuleOfDefaultChain(generictables.DefaultChainInput, generictables.Rule{
			Match:   iptables.NewMatch(),
			Action:  iptables.NewAction().Jump(generictables.OurDefaultInputChain),
			Comment: []string{"Jump to bamboo input chain"},
		})

		filterTable.SetDefaultRuleOfDefaultChain(generictables.DefaultChainOutput, generictables.Rule{
			Match:   iptables.NewMatch(),
			Action:  iptables.NewAction().Jump(generictables.OurDefaultOutputChain),
			Comment: []string{"Jump to bamboo output chain"},
		})
	}
}

func (dp *InternalDataplane) intervalUpdateDataplane() {
	// implement interval algorithm call to get data from dataplane
	timer := time.NewTimer(dp.dataplaneRefreshInterval)
	for {
		utils.ResetTimer(timer, dp.dataplaneRefreshInterval)
		select {
		case msg := <-dp.toDataplane:
			dp.processMsgToManager(msg)
		case <-timer.C:
			dp.dataplaneNeedsSync = true
		case <-dp.parentCtx.Done():
			slog.Info("stop interval update dataplane")
			return
		}
		if dp.datastoreInSync && dp.dataplaneNeedsSync {
			dp.apply()
		}
	}
}

func (dp *InternalDataplane) processMsgToManager(msg interface{}) {
	dp.datastoreInSync = true
	dp.dataplaneNeedsSync = true
	var wgManager sync.WaitGroup
	for _, m := range dp.managers {
		wgManager.Add(1)
		go func(m Manager) {
			defer wgManager.Done()
			m.OnUpdate(msg)
		}(m)
	}
	wgManager.Wait()
}

func (dp *InternalDataplane) apply() {
	dp.dataplaneNeedsSync = false

	var wgIPSet sync.WaitGroup
	for _, set := range dp.ipsets {
		wgIPSet.Add(1)
		go func(set *ipset.IPSet) {
			defer wgIPSet.Done()
			set.Apply()
		}(set)
	}
	wgIPSet.Wait()

	var wgTable = sync.WaitGroup{}
	for _, table := range dp.allTables {
		wgTable.Add(1)
		go func(table generictables.Table) {
			defer wgTable.Done()
			table.Apply()
		}(table)
	}
	wgTable.Wait()
}

func (dp *InternalDataplane) SendMessage(msg interface{}) error {
	dp.toDataplane <- msg
	return nil
}

func (dp *InternalDataplane) ReceiveMessage() (interface{}, error) {
	return <-dp.fromDataplane, nil
}
