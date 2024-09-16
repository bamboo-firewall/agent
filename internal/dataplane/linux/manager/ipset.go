package manager

import (
	"github.com/bamboo-firewall/agent/pkg/ipset"
	"github.com/bamboo-firewall/agent/pkg/model"
)

type IPSet struct {
	ipVersion int
	ipset     *ipset.IPSet
}

func NewIPSet(ipset *ipset.IPSet) *IPSet {
	return &IPSet{
		ipset:     ipset,
		ipVersion: ipset.GetIPVersion(),
	}
}

func (i *IPSet) OnUpdate(msg interface{}) {
	switch m := msg.(type) {
	case *model.Agent:
		sets := i.networkSetsToIPSets(m.IPSet)

		i.ipset.UpdateIPSet(sets)
	}
}

func (i *IPSet) networkSetsToIPSets(agentSets *model.AgentIPSet) map[string]map[string]struct{} {
	sets := make(map[string]map[string]struct{})
	for _, agentSet := range agentSets.IPSets {
		if agentSet.IPVersion != i.ipVersion {
			continue
		}

		members := make(map[string]struct{})
		for _, member := range agentSet.Members {
			members[member] = struct{}{}
		}

		sets[ipset.IPSetNamePrefix+agentSet.Name] = members
	}

	return sets
}
