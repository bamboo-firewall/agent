package rulerenderer

import "github.com/bamboo-firewall/agent/pkg/generictables"

type DefaultRuleRenderer struct {
	generictables.ActionFactory

	NewMatch func() generictables.MathCriteria
}

func NewRenderer() *DefaultRuleRenderer {
	return &DefaultRuleRenderer{}
}
