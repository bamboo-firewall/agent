package rulerenderer

import (
	"fmt"

	"github.com/bamboo-firewall/agent/pkg/generictables"
	"github.com/bamboo-firewall/agent/pkg/model"
)

func (r *DefaultRuleRenderer) PoliciesToIptablesChains(agentPolicy *model.AgentPolicy, ipVersion int, apiServerIPV4 string) []*generictables.Chain {
	// For each policy
	// our default table(contains default rules and jump to each policy)
	var chains []*generictables.Chain
	rulesJumpToOurInputChain := make([]generictables.Rule, 0)
	rulesJumpToOurOutputChain := make([]generictables.Rule, 0)
	for i, policy := range agentPolicy.Policies {
		if len(policy.InboundRules) > 0 {
			chainName := generictables.OurInputChainPrefix + fmt.Sprint(i) // using name?
			inbound := generictables.Chain{
				Name:  chainName,
				Rules: r.rulesToIptablesRules(policy.InboundRules, ipVersion),
			}
			chains = append(chains, &inbound)
			rulesJumpToOurInputChain = append(rulesJumpToOurInputChain, generictables.Rule{
				Match:   r.NewMatch(),
				Action:  r.Jump(chainName),
				Comment: nil,
			})
		}

		if len(policy.OutboundRules) > 0 {
			chainName := generictables.OurOutputChainPrefix + fmt.Sprint(i)
			outbound := generictables.Chain{
				Name:  chainName,
				Rules: r.rulesToIptablesRules(policy.OutboundRules, ipVersion),
			}
			chains = append(chains, &outbound)
			rulesJumpToOurOutputChain = append(rulesJumpToOurOutputChain, generictables.Rule{
				Match:   r.NewMatch(),
				Action:  r.Jump(chainName),
				Comment: nil,
			})
		}
	}
	ourDefaultInputRules := make([]generictables.Rule, 0)
	ourDefaultInputRules = append(ourDefaultInputRules, generictables.Rule{
		Match:   r.NewMatch().ConntrackState("ESTABLISHED,RELATED"),
		Action:  r.Allow(),
		Comment: nil,
	})
	ourDefaultInputRules = append(ourDefaultInputRules, rulesJumpToOurInputChain...)
	ourDefaultInputRules = append(ourDefaultInputRules, generictables.Rule{
		Match:   r.NewMatch(),
		Action:  r.Drop(),
		Comment: nil,
	})
	ourDefaultOutputRules := make([]generictables.Rule, 0)
	ourDefaultOutputRules = append(ourDefaultOutputRules,
		generictables.Rule{
			Match:   r.NewMatch().ConntrackState("ESTABLISHED,RELATED"),
			Action:  r.Allow(),
			Comment: nil,
		},
	)
	if ipVersion == generictables.IPFamily4 {
		ourDefaultOutputRules = append(ourDefaultOutputRules, generictables.Rule{
			Match:   r.NewMatch().Protocol("tcp").ConntrackState("NEW").DestNet(apiServerIPV4),
			Action:  r.Allow(),
			Comment: nil,
		})
	}
	// add rule allow to api-server
	ourDefaultOutputRules = append(ourDefaultOutputRules, rulesJumpToOurOutputChain...)
	ourDefaultOutputRules = append(ourDefaultOutputRules, generictables.Rule{
		Match:   r.NewMatch(),
		Action:  r.Drop(),
		Comment: nil,
	})
	chains = append(
		chains,
		&generictables.Chain{
			Name:  generictables.OurDefaultInputChain,
			Rules: ourDefaultInputRules,
		},
		&generictables.Chain{
			Name:  generictables.OurDefaultOutputChain,
			Rules: ourDefaultOutputRules,
		},
	)
	return chains
}

func (r *DefaultRuleRenderer) rulesToIptablesRules(rules []*model.Rule, ipVersion int, chainComments ...string) []generictables.Rule {
	var iptablesRules []generictables.Rule
	for _, rule := range rules {
		iptablesRules = append(iptablesRules, r.ruleToIptablesRules(rule, ipVersion)...)
	}

	if len(chainComments) > 0 {
		if len(iptablesRules) == 0 {
			iptablesRules = append(iptablesRules, generictables.Rule{})
		}
		iptablesRules[0].Comment = append(iptablesRules[0].Comment, chainComments...)
	}
	return iptablesRules
}

func (r *DefaultRuleRenderer) ruleToIptablesRules(rule *model.Rule, ipVersion int) []generictables.Rule {
	if rule.IPVersion != ipVersion {
		return nil
	}

	match := r.NewMatch()
	if rule.Protocol != "" {
		match = match.Protocol(rule.Protocol)
	}

	for _, set := range rule.SrcNamedPortIpSetIDs {
		match = match.SourceIPSet(set)
	}
	for _, set := range rule.DstNamedPortIpSetIDs {
		match = match.DestIPSet(set)
	}

	if rule.NotProtocol != "" {
		match = match.NotProtocol(rule.NotProtocol)
	}

	for _, set := range rule.NotSrcNamedPortIpSetIDs {
		match = match.NotSourceIPSet(set)
	}
	for _, set := range rule.NotDstNamedPortIpSetIDs {
		match = match.NotDestIPSet(set)
	}

	matches := make([]generictables.MatchCriteria, 0)
	for _, snet := range rule.SrcNets {
		for _, dnet := range rule.DstNets {
			matches = append(matches, match.SourceNet(snet).DestNet(dnet))
		}
	}

	rules := make([]generictables.Rule, 0)
	for i := range matches {
		rules = append(rules, generictables.Rule{
			Match:  matches[i],
			Action: r.renderRuleAction(rule.Action),
		})
	}

	return rules
}

func (r *DefaultRuleRenderer) renderRuleAction(action string) generictables.Action {
	switch action {
	case "allow":
		return r.Allow()
	case "deny":
		return r.Drop()
	case "log":
		return r.Log(r.logPrefix)
	default:
		return r.Allow()
	}
}
