package rulerenderer

import (
	"fmt"
	"strings"

	"github.com/bamboo-firewall/agent/pkg/apiserver/dto"
	"github.com/bamboo-firewall/agent/pkg/generictables"
	"github.com/bamboo-firewall/agent/pkg/ipset"
)

func (r *DefaultRuleRenderer) PoliciesToIptablesChains(policies []*dto.ParsedPolicy, ipVersion int, apiServerIPV4 string) []*generictables.Chain {
	// For each policy
	// our default table(contains default rules and jump to each policy)
	var chains []*generictables.Chain
	rulesJumpToOurInputChain := make([]generictables.Rule, 0)
	rulesJumpToOurOutputChain := make([]generictables.Rule, 0)
	for i, policy := range policies {
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

func (r *DefaultRuleRenderer) rulesToTablesRules(rules []*dto.ParsedRule, ipVersion int, chainComments ...string) []generictables.Rule {
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

func (r *DefaultRuleRenderer) ruleToTablesRules(rule *dto.ParsedRule, ipVersion int) []generictables.Rule {
	if rule.IPVersion != ipVersion {
		return nil
	}

	mainMatch := r.NewMatch()
	if rule.Protocol != "" {
		if rule.IsProtocolNegative {
			mainMatch = mainMatch.NotProtocol(rule.Protocol)
		} else {
			mainMatch = mainMatch.Protocol(rule.Protocol)
		}
	}

	var (
		srcPorts [][]string
		dstPorts [][]string
	)
	if len(rule.SrcPorts) > 0 {
		srcPorts = splitPorts(rule.SrcPorts)
	}
	if len(rule.DstPorts) > 0 {
		dstPorts = splitPorts(rule.DstPorts)
	}
	var matchPorts []generictables.MatchCriteria
	if len(srcPorts) > 0 || len(dstPorts) > 0 {
		if len(srcPorts) > 0 && len(dstPorts) > 0 {
			for _, srcPort := range srcPorts {
				matchPort := r.NewMatch()
				if rule.IsSrcPortNegative {
					matchPort = matchPort.NotSourcePorts(srcPort)
				} else {
					matchPort = matchPort.SourcePorts(srcPort)
				}
				for _, dstPort := range dstPorts {
					matchPort2 := matchPort.Copy()
					if rule.IsDstPortNegative {
						matchPort2 = matchPort2.NotDestPorts(dstPort)
					} else {
						matchPort2 = matchPort2.DestPorts(dstPort)
					}
					matchPorts = append(matchPorts, matchPort2)
				}
			}
		} else if len(dstPorts) > 0 {
			for _, dstPort := range dstPorts {
				matchPort := r.NewMatch()
				if rule.IsDstPortNegative {
					matchPort = matchPort.NotDestPorts(dstPort)
				} else {
					matchPort = matchPort.DestPorts(dstPort)
				}
				matchPorts = append(matchPorts, matchPort)
			}
		} else {
			for _, srcPort := range srcPorts {
				matchPort := r.NewMatch()
				if rule.IsSrcPortNegative {
					matchPort = matchPort.NotSourcePorts(srcPort)
				} else {
					matchPort = matchPort.SourcePorts(srcPort)
				}
				matchPorts = append(matchPorts, matchPort)
			}
		}
	}

	var (
		srcNets []string
		dstNets []string
	)
	if len(rule.SrcNets) > 0 {
		srcNets = rule.SrcNets
	}
	if len(rule.DstNets) > 0 {
		dstNets = rule.DstNets
	}

	var matchNets []generictables.MatchCriteria
	if len(srcNets) > 0 || len(dstNets) > 0 {
		if len(srcNets) > 0 && len(dstNets) > 0 {
			for _, srcNet := range srcNets {
				matchNet := r.NewMatch()
				if rule.IsSrcNetNegative {
					matchNet = matchNet.NotSourceNet(srcNet)
				} else {
					matchNet = matchNet.SourceNet(srcNet)
				}
				for _, dstNet := range dstNets {
					matchNet2 := matchNet.Copy()
					if rule.IsDstNetNegative {
						matchNet2 = matchNet2.NotDestNet(dstNet)
					} else {
						matchNet2 = matchNet2.DestNet(dstNet)
					}
					matchNets = append(matchNets, matchNet2)
				}
			}
		} else if len(srcNets) == 0 {
			for _, dstNet := range dstNets {
				matchNet := r.NewMatch()
				if rule.IsDstNetNegative {
					matchNet = matchNet.NotDestNet(dstNet)
				} else {
					matchNet = matchNet.DestNet(dstNet)
				}
				matchNets = append(matchNets, matchNet)
			}
		} else {
			for _, srcNet := range srcNets {
				matchNet := r.NewMatch()
				if rule.IsSrcNetNegative {
					matchNet = matchNet.NotSourceNet(srcNet)
				} else {
					matchNet = matchNet.SourceNet(srcNet)
				}
				matchNets = append(matchNets, matchNet)
			}
		}
	}

	// use sets for each match
	var (
		srcIPSets []string
		dstIPSets []string
	)
	if len(rule.SrcGNSNetNames) > 0 {
		srcIPSets = rule.SrcGNSNetNames
	}
	if len(rule.DstGNSNetNames) > 0 {
		dstIPSets = rule.DstGNSNetNames
	}
	var matchSets []generictables.MatchCriteria
	if len(srcIPSets) > 0 || len(dstIPSets) > 0 {
		if len(srcIPSets) > 0 && len(dstIPSets) > 0 {
			for _, srcIP := range srcIPSets {
				matchSet := r.NewMatch().SourceIPSet(ipset.IPSetNamePrefix + srcIP)
				for _, dstIP := range dstIPSets {
					matchSets = append(matchSets, matchSet.Copy().DestIPSet(ipset.IPSetNamePrefix+dstIP))
				}
			}
		} else if len(dstIPSets) > 0 {
			for _, dstIP := range dstIPSets {
				matchSets = append(matchSets, r.NewMatch().DestIPSet(ipset.IPSetNamePrefix+dstIP))
			}
		} else {
			for _, srcIP := range srcIPSets {
				matchSets = append(matchSets, r.NewMatch().SourceIPSet(ipset.IPSetNamePrefix+srcIP))
			}
		}
	}

	matches := r.cartesianMatches(matchPorts, matchNets, matchSets)
	rules := make([]generictables.Rule, 0)
	for _, match := range matches {
		rules = append(rules, generictables.Rule{
			Match:  mainMatch.Merge(match),
			Action: r.renderRuleAction(rule.Action),
		})
	}

	return rules
}

func (r *DefaultRuleRenderer) cartesianMatches(arrayMatches ...[]generictables.MatchCriteria) []generictables.MatchCriteria {
	// remove empty array
	var nonArrayMatches [][]generictables.MatchCriteria
	for _, arrayMatch := range arrayMatches {
		if len(arrayMatch) > 0 {
			nonArrayMatches = append(nonArrayMatches, arrayMatch)
		}
	}
	resultMatches := []generictables.MatchCriteria{r.NewMatch()}
	for _, arrayMatch := range nonArrayMatches {
		var tmpMatches []generictables.MatchCriteria
		for _, resultMatch := range resultMatches {
			for _, match := range arrayMatch {
				combination := resultMatch.Copy().Merge(match)
				tmpMatches = append(tmpMatches, combination)
			}
		}
		resultMatches = tmpMatches
	}
	return resultMatches
}

func (r *DefaultRuleRenderer) cartesianRules(mainMatch generictables.MatchCriteria, action generictables.Action, matches ...[]generictables.MatchCriteria) []generictables.Rule {
	rules := make([]generictables.Rule, 1)
	for _, match := range matches {
		var tmpRules []generictables.Rule
		for _, rule := range rules {
			for _, m := range match {
				combination := generictables.Rule{
					Match:  mainMatch.Merge(rule.Match).Merge(m),
					Action: action,
				}
				tmpRules = append(tmpRules, combination)
			}
		}
		rules = tmpRules
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
