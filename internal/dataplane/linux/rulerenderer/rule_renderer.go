package rulerenderer

import (
	"github.com/bamboo-firewall/agent/pkg/generictables"
	"github.com/bamboo-firewall/agent/pkg/ipset"
	"github.com/bamboo-firewall/agent/pkg/iptables"
)

type DefaultRuleRenderer struct {
	generictables.ActionFactory

	logPrefix string

	NewMatch            func() generictables.MatchCriteria
	ipsetNameConvention *ipset.NameConvention
}

func NewRenderer(logPrefix string, ipsetNameConvention *ipset.NameConvention) *DefaultRuleRenderer {
	return &DefaultRuleRenderer{
		logPrefix:     logPrefix,
		ActionFactory: iptables.NewAction(),
		// ToDo: check config is iptables or nftables
		NewMatch: func() generictables.MatchCriteria {
			return iptables.NewMatch()
		},
		ipsetNameConvention: ipsetNameConvention,
	}
}
