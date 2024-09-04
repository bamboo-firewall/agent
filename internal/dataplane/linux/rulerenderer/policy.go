package rulerenderer

import (
	"fmt"

	"github.com/bamboo-firewall/agent/pkg/generictables"
	"github.com/bamboo-firewall/agent/pkg/model"
)

func (r *DefaultRuleRenderer) PolicyToIptablesChains(policyID int, policy *model.Policy, ipVersion uint8) []*generictables.Chain {
	inbound := generictables.Chain{
		Name:  fmt.Sprint(policyID),
		Rules: r.rulesToIptablesRules(policy.InboundRules, ipVersion),
	}
	outbound := generictables.Chain{
		Name:  fmt.Sprint(policyID),
		Rules: r.rulesToIptablesRules(policy.OutboundRules, ipVersion),
	}
	return []*generictables.Chain{&inbound, &outbound}
}

func (r *DefaultRuleRenderer) rulesToIptablesRules(rules []*model.Rule, ipVersion uint8, chainComments ...string) []generictables.Rule {
	var iptablesRules []generictables.Rule
	for _, rule := range rules {
		iptablesRules = append(iptablesRules, r.ruleToIptablesRules(rule, ipVersion)...)
	}

	// ToDo: Strip off any return rules at the end of the chain. No matter their match criteria, they're effectively no-ops

	if len(chainComments) > 0 {
		if len(iptablesRules) == 0 {
			iptablesRules = append(iptablesRules, generictables.Rule{})
		}
		iptablesRules[0].Comment = append(iptablesRules[0].Comment, chainComments...)
	}
	return iptablesRules
}

func (r *DefaultRuleRenderer) ruleToIptablesRules(rule *model.Rule, ipVersion uint8) []generictables.Rule {
	return []generictables.Rule{}
}
