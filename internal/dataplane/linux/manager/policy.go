package manager

import (
	"github.com/bamboo-firewall/agent/pkg/apiserver/dto"
	"github.com/bamboo-firewall/agent/pkg/generictables"
)

type RuleRenderer interface {
	PoliciesToIptablesChains(policies []*dto.ParsedGNP, ipVersion int, apiServerIPV4 string) []*generictables.Chain
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
	case *dto.HostEndpointPolicy:
		chains := p.ruleRenderer.PoliciesToIptablesChains(m.ParsedGNPs, p.ipVersion, p.apiServerIPV4)

		p.filterTable.UpdateChains(chains)
	}
}
