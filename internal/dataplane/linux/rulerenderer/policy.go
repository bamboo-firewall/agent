package rulerenderer

import (
	"fmt"
	"strings"

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
				Rules: r.rulesToTablesRules(policy.InboundRules, ipVersion),
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
				Rules: r.rulesToTablesRules(policy.OutboundRules, ipVersion),
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

func (r *DefaultRuleRenderer) rulesToTablesRules(rules []*model.Rule, ipVersion int, chainComments ...string) []generictables.Rule {
	var iptablesRules []generictables.Rule
	for _, rule := range rules {
		iptablesRules = append(iptablesRules, r.ruleToTablesRules(rule, ipVersion)...)
	}

	if len(chainComments) > 0 {
		if len(iptablesRules) == 0 {
			iptablesRules = append(iptablesRules, generictables.Rule{})
		}
		iptablesRules[0].Comment = append(iptablesRules[0].Comment, chainComments...)
	}
	return iptablesRules
}

func (r *DefaultRuleRenderer) ruleToTablesRules(rule *model.Rule, ipVersion int) []generictables.Rule {
	if rule.IPVersion != ipVersion {
		return nil
	}

	match := r.NewMatch()
	if rule.Protocol != "" {
		match = match.Protocol(rule.Protocol)
	}
	if rule.NotProtocol != "" {
		match = match.NotProtocol(rule.NotProtocol)
	}

	var (
		srcPorts        [][]string
		dstPorts        [][]string
		isSrcPortNative bool
		isDstPortNative bool
	)
	if len(rule.SrcPorts) > 0 {
		srcPorts = splitPorts(rule.SrcPorts)
		isSrcPortNative = true
	} else {
		srcPorts = splitPorts(rule.NotSrcPorts)
		isSrcPortNative = false
	}
	if len(rule.DstPorts) > 0 {
		dstPorts = splitPorts(rule.DstPorts)
		isDstPortNative = true
	} else {
		dstPorts = splitPorts(rule.NotDstPorts)
		isDstPortNative = false
	}
	for i := 0; i < len(srcPorts) || i < len(dstPorts); i++ {
		if i < len(srcPorts) && i < len(dstPorts) {
			if isSrcPortNative {
				match = match.SourcePorts(srcPorts[i])
			} else {
				match = match.NotSourcePorts(srcPorts[i])
			}
			if isDstPortNative {
				match = match.DestPorts(dstPorts[i])
			} else {
				match = match.NotDestPorts(dstPorts[i])
			}
		} else if i < len(dstPorts) {
			if isDstPortNative {
				match = match.DestPorts(dstPorts[i])
			} else {
				match = match.NotDestPorts(dstPorts[i])
			}
		} else {
			if isSrcPortNative {
				match = match.SourcePorts(srcPorts[i])
			} else {
				match = match.NotSourcePorts(srcPorts[i])
			}
		}
	}

	var (
		srcIPSets  []string
		dstIPSets  []string
		isSrcIPSet bool
		isDstIPSet bool
	)
	if len(rule.SrcNamedPortIpSetIDs) > 0 {
		srcIPSets = rule.SrcNamedPortIpSetIDs
		isSrcIPSet = true
	} else {
		srcIPSets = rule.NotSrcNamedPortIpSetIDs
		isSrcIPSet = false
	}
	if len(rule.DstNamedPortIpSetIDs) > 0 {
		dstIPSets = rule.DstNamedPortIpSetIDs
		isDstIPSet = true
	} else {
		dstIPSets = rule.NotDstNamedPortIpSetIDs
		isDstIPSet = false
	}
	for i := 0; i < len(srcIPSets) || i < len(dstIPSets); i++ {
		if i < len(srcIPSets) && i < len(dstIPSets) {
			if isSrcIPSet {
				match = match.SourceIPSet(srcIPSets[i])
			} else {
				match = match.NotSourceIPSet(srcIPSets[i])
			}
			if isDstIPSet {
				match = match.DestIPSet(dstIPSets[i])
			} else {
				match = match.NotDestIPSet(dstIPSets[i])
			}
		} else if i < len(dstIPSets) {
			if isDstIPSet {
				match = match.DestIPSet(dstIPSets[i])
			} else {
				match = match.NotDestIPSet(dstIPSets[i])
			}
		} else {
			if isSrcIPSet {
				match = match.SourceIPSet(srcIPSets[i])
			} else {
				match = match.NotSourceIPSet(srcIPSets[i])
			}
		}
	}

	var (
		srcNets        []string
		dstNets        []string
		isSrcNetNative bool
		isDstNetNative bool
	)
	if len(rule.SrcNets) > 0 {
		srcNets = rule.SrcNets
		isSrcNetNative = true
	} else {
		srcNets = rule.NotSrcNets
		isSrcNetNative = false
	}
	if len(rule.DstNets) > 0 {
		dstNets = rule.DstNets
		isDstNetNative = true
	} else {
		dstNets = rule.NotDstNets
		isDstNetNative = false
	}

	matches := make([]generictables.MatchCriteria, 0)
	if len(srcNets) > 0 || len(dstNets) > 0 {
		if len(srcNets) > 0 && len(dstNets) > 0 {
			for _, srcNet := range srcNets {
				matchNet := match.Copy()
				if isSrcNetNative {
					matchNet = matchNet.SourceNet(srcNet)
				} else {
					matchNet = matchNet.NotSourceNet(srcNet)
				}
				for _, dstNet := range dstNets {
					matchNet2 := matchNet.Copy()
					if isDstNetNative {
						matchNet2 = matchNet2.DestNet(dstNet)
					} else {
						matchNet2 = matchNet2.NotDestNet(dstNet)
					}
					matches = append(matches, matchNet2)
				}
			}
		} else if len(srcNets) == 0 {
			for _, dstNet := range dstNets {
				matchNet := match.Copy()
				if isDstNetNative {
					matchNet = matchNet.DestNet(dstNet)
				} else {
					matchNet = matchNet.NotDestNet(dstNet)
				}
				matches = append(matches, matchNet)
			}
		} else {
			for _, srcNet := range srcNets {
				matchNet := match.Copy()
				if isSrcNetNative {
					matchNet = matchNet.SourceNet(srcNet)
				} else {
					matchNet = matchNet.NotSourceNet(srcNet)
				}
				matches = append(matches, matchNet)
			}
		}
	} else {
		matches = append(matches, match)
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

// splitPorts splits the input list of ports into groups containing up to 15 port numbers.
// iptables limit 15 ports per rule in a multiport match. A single port takes up one slot, a range of ports take 2
func splitPorts(ports []string) [][]string {
	const slotAvailablePerSplit = 15
	var (
		splits [][]string
		split  []string
	)
	remainingSlotAvailablePerSplit := slotAvailablePerSplit
	for _, port := range ports {
		var numSlots int
		portRange := strings.Split(port, ":")
		if len(portRange) > 1 {
			numSlots = 2
		} else {
			numSlots = 1
		}
		if remainingSlotAvailablePerSplit < numSlots {
			splits = append(splits, split)
			remainingSlotAvailablePerSplit = slotAvailablePerSplit
			split = nil
		}
		split = append(split, port)
		remainingSlotAvailablePerSplit -= numSlots
	}
	if split != nil {
		splits = append(splits, split)
	}
	return splits
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
