package manager

import (
	"log/slog"

	"github.com/bamboo-firewall/agent/pkg/apiserver/dto"
	"github.com/bamboo-firewall/agent/pkg/generictables"
	"github.com/bamboo-firewall/agent/pkg/ipset"
	"github.com/bamboo-firewall/agent/pkg/net"
)

const (
	sourceSetHEP = "hep"
	sourceSetGNS = "gns"
)

type IPSet struct {
	ipset               *ipset.IPSet
	ipsetNameConvention *ipset.NameConvention
}

func NewIPSet(ipset *ipset.IPSet, ipsetNameConvention *ipset.NameConvention) *IPSet {
	return &IPSet{
		ipset:               ipset,
		ipsetNameConvention: ipsetNameConvention,
	}
}

func (i *IPSet) OnUpdate(msg interface{}) {
	switch m := msg.(type) {
	case *dto.HostEndpointPolicy:
		sets := i.networkSetsToIPSets(m.ParsedHEPs, m.ParsedGNSs)

		i.ipset.UpdateIPSet(sets)
	}
}

func (i *IPSet) networkSetsToIPSets(parsedHEPs []*dto.ParsedHEP, parsedGNSs []*dto.ParsedGNS) map[string]map[string]struct{} {
	sets := make(map[string]map[string]struct{})
	var index int
	for _, parsedHEP := range parsedHEPs {
		var ips []string
		if i.ipset.GetIPVersion() == generictables.IPFamily4 && len(parsedHEP.IPsV4) > 0 {
			ips = parsedHEP.IPsV4
		} else if i.ipset.GetIPVersion() == generictables.IPFamily6 && len(parsedHEP.IPsV6) > 0 {
			ips = parsedHEP.IPsV6
		} else {
			continue
		}

		members := make(map[string]struct{})
		for _, ip := range ips {
			_, ipnet, err := net.ParseCIDROrIP(ip)
			if err != nil {
				slog.Warn("malformed ip", "ip", ip)
				continue
			}
			members[ipnet.String()] = struct{}{}
		}

		mainName := i.ipsetNameConvention.SetMainNameOfSet(parsedHEP.UUID, index, i.ipset.GetIPVersion(), sourceSetHEP, parsedHEP.Name)

		sets[mainName] = members
		index++
	}

	index = 0
	for _, parsedGNS := range parsedGNSs {
		var nets []string
		if i.ipset.GetIPVersion() == generictables.IPFamily4 {
			nets = parsedGNS.NetsV4
		} else if i.ipset.GetIPVersion() == generictables.IPFamily6 {
			nets = parsedGNS.NetsV6
		} else {
			continue
		}

		members := make(map[string]struct{})
		for _, net := range nets {
			members[net] = struct{}{}
		}

		mainName := i.ipsetNameConvention.SetMainNameOfSet(parsedGNS.UUID, index, i.ipset.GetIPVersion(), sourceSetGNS, parsedGNS.Name)

		sets[mainName] = members
		index++
	}

	return sets
}
