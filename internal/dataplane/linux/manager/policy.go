package manager

import (
	"github.com/bamboo-firewall/agent/pkg/generictables"
	"github.com/bamboo-firewall/agent/pkg/model"
)

type Table interface {
	UpdateChains(chains []*generictables.Chain)
}

type RuleRenderer interface {
	PolicyToIptablesChains(policyID int, policy *model.Policy, ipVersion uint8) []*generictables.Chain
}

type policy struct {
	rawTable    Table
	mangleTable Table
	filterTable Table

	ruleRenderer RuleRenderer
	ipVersion    uint8
}

func NewPolicy(rawTable, mangleTable, filterTable Table) *policy {
	return &policy{
		rawTable:    rawTable,
		mangleTable: mangleTable,
		filterTable: filterTable,
	}
}

func (p *policy) OnUpdate(msg interface{}) {
	switch m := msg.(type) {
	case *model.Policy:
		chains := p.ruleRenderer.PolicyToIptablesChains(8, m, p.ipVersion)

		p.rawTable.UpdateChains(chains)
		p.mangleTable.UpdateChains(chains)
		p.filterTable.UpdateChains(chains)
	}
}
