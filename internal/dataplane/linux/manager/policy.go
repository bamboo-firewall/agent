package manager

import (
	"github.com/bamboo-firewall/agent/pkg/generictables"
	"github.com/bamboo-firewall/agent/pkg/model"
)

type RuleRenderer interface {
	PoliciesToIptablesChains(agentPolicy *model.AgentPolicy, ipVersion int, apiServerIPV4 string) []*generictables.Chain
}

type policy struct {
	filterTable generictables.Table

	ruleRenderer  RuleRenderer
	ipVersion     int
	apiServerIPV4 string
}

func NewPolicy(filterTable generictables.Table, ipVersion int, apiServerIPV4 string, renderer RuleRenderer) *policy {
	return &policy{
		filterTable:   filterTable,
		ruleRenderer:  renderer,
		ipVersion:     ipVersion,
		apiServerIPV4: apiServerIPV4,
	}
}

func (p *policy) OnUpdate(msg interface{}) {
	switch m := msg.(type) {
	case *model.Agent:
		chains := p.ruleRenderer.PoliciesToIptablesChains(m.Policy, p.ipVersion, p.apiServerIPV4)

		p.filterTable.UpdateChains(chains)
	}
}
