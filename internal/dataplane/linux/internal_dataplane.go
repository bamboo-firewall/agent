package linux

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/bamboo-firewall/agent/internal/dataplane/linux/manager"
	"github.com/bamboo-firewall/agent/pkg/generictables"
	"github.com/bamboo-firewall/agent/pkg/iptables"
	"github.com/bamboo-firewall/agent/pkg/utils"
)

type Manager interface {
	OnUpdate(msg interface{})
}

type InternalDataplane struct {
	parentCtx     context.Context
	toDataplane   chan interface{}
	fromDataplane chan interface{}

	// allTables contains mangleTables, natTables, rawTables, filterTables
	allTables []generictables.Table

	mangleTables []generictables.Table
	natTables    []generictables.Table
	rawTables    []generictables.Table

	filterTables []generictables.Table

	managers []Manager

	// datastoreInSync set to true after we receive message from datastore
	datastoreInSync bool

	// dataplaneNeedsSync set to true when a certain period of time allows
	dataplaneNeedsSync bool
}

func NewInternalDataplane(parentCtx context.Context) *InternalDataplane {
	dp := &InternalDataplane{
		parentCtx:     parentCtx,
		toDataplane:   make(chan interface{}),
		fromDataplane: make(chan interface{}),
	}

	mangleTableIPV4 := iptables.NewTable("mangle")
	natTableIPV4 := iptables.NewTable("nat")
	rawTableIPV4 := iptables.NewTable("raw")
	filerTableIPV4 := iptables.NewTable("filter")

	dp.managers = append(dp.managers, manager.NewPolicy(rawTableIPV4, mangleTableIPV4, filerTableIPV4))

	dp.mangleTables = append(dp.mangleTables, mangleTableIPV4)
	dp.natTables = append(dp.natTables, natTableIPV4)
	dp.rawTables = append(dp.rawTables, rawTableIPV4)
	dp.filterTables = append(dp.filterTables, filerTableIPV4)

	dp.allTables = append(dp.allTables, dp.mangleTables...)
	dp.allTables = append(dp.allTables, dp.natTables...)
	dp.allTables = append(dp.allTables, dp.rawTables...)
	dp.allTables = append(dp.allTables, dp.filterTables...)
	return dp
}

func (dp *InternalDataplane) Start() {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		dp.intervalUpdateDataplane()
	}()
	wg.Wait()
}

func (dp *InternalDataplane) intervalUpdateDataplane() {
	// implement interval algorithm call to get data from dataplane
	intervalTime := 5 * time.Second
	timer := time.NewTimer(intervalTime)
	for {
		utils.ResetTimer(timer, intervalTime)
		slog.Info("aaaa")
		select {
		case msg := <-dp.toDataplane:
			slog.Info("bbbb")
			dp.processMsgToManager(msg)
		case <-timer.C:
			dp.dataplaneNeedsSync = true
		case <-dp.parentCtx.Done():
			slog.Info("stop interval update dataplane")
			return
		}
		slog.Info("cccc", "dataplaneNeedsSync", dp.dataplaneNeedsSync, "datastoreInSync", dp.datastoreInSync)
		if dp.datastoreInSync && dp.dataplaneNeedsSync {
			dp.apply()
		}
	}
}

func (dp *InternalDataplane) processMsgToManager(msg interface{}) {
	dp.datastoreInSync = true
	dp.dataplaneNeedsSync = true
	var wgManager sync.WaitGroup
	for _, manager := range dp.managers {
		wgManager.Add(1)
		go func(manager Manager) {
			defer wgManager.Done()
			manager.OnUpdate(msg)
		}(manager)
	}
	wgManager.Wait()
}

func (dp *InternalDataplane) apply() {
	dp.dataplaneNeedsSync = false

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
