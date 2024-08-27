package linux

import (
	"github.com/bamboo-firewall/agent/generictables"
	"github.com/bamboo-firewall/agent/iptables"
)

type InternalDataplane struct {
	toDataplane   chan interface{}
	fromDataplane chan interface{}

	mangleTables []generictables.Table
	natTables    []generictables.Table
	rawTables    []generictables.Table
	filerTables  []generictables.Table
}

func NewInternalDataplane() *InternalDataplane {
	dp := &InternalDataplane{}

	mangleTableIPV4 := iptables.NewTable("mangle")
	natTableIPV4 := iptables.NewTable("nat")
	rawTableIPV4 := iptables.NewTable("raw")
	filerTableIPV4 := iptables.NewTable("filter")

	dp.mangleTables = append(dp.mangleTables, mangleTableIPV4)
	dp.natTables = append(dp.natTables, natTableIPV4)
	dp.rawTables = append(dp.rawTables, rawTableIPV4)
	dp.filerTables = append(dp.filerTables, filerTableIPV4)

	return dp
}

func (dp *InternalDataplane) Start() {
	for _, table := range dp.filerTables {
		table.Apply()
	}
}

func (dp *InternalDataplane) IntervalUpdateDataplane() {
	// implement interval algorithm call to get data from dataplane
	for {

	}
}

func (dp *InternalDataplane) SendMessage(msg interface{}) error {
	dp.toDataplane <- msg
	return nil
}

func (dp *InternalDataplane) ReceiveMessage() (interface{}, error) {
	return <-dp.fromDataplane, nil
}
