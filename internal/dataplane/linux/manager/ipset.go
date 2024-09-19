package manager

import (
	"github.com/bamboo-firewall/agent/pkg/apiserver/dto"
	"github.com/bamboo-firewall/agent/pkg/ipset"
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
	case *dto.FetchPoliciesOutput:
		sets := i.networkSetsToIPSets(m.ParsedSets)

		i.ipset.UpdateIPSet(sets)
	}
}

func (i *IPSet) networkSetsToIPSets(parsedSets []*dto.ParsedSet) map[string]map[string]struct{} {
	sets := make(map[string]map[string]struct{})
	for _, parsedSet := range parsedSets {
		if parsedSet.IPVersion != i.ipVersion {
			continue
		}

		members := make(map[string]struct{})
		for _, net := range parsedSet.Nets {
			members[net] = struct{}{}
		}

		sets[ipset.IPSetNamePrefix+parsedSet.Name] = members
	}

	return sets
}
