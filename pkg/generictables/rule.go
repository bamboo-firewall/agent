package generictables

import (
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
)

const hashLength = 16

type Rule struct {
	Match   MatchCriteria
	Action  Action
	Comment []string
}

type Chain struct {
	Name  string
	Rules []Rule
}

type ruleRenderFn func(rule *Rule, chainName string) string

func RuleHashes(c *Chain, renderFn ruleRenderFn) []string {
	if c == nil {
		return nil
	}
	hashes := make([]string, len(c.Rules))

	s := sha256.New224()
	_, err := s.Write([]byte(c.Name))
	if err != nil {
		slog.Error("failed to hash chain name", "chainName", c.Name, "error", err)
		return nil
	}
	hash := s.Sum(nil)
	for i, rule := range c.Rules {
		s.Reset()
		_, err = s.Write(hash)
		if err != nil {
			slog.Error("failed to hash rule", "rule", rule, "error", err)
		}
		ruleForHashing := renderFn(&rule, c.Name)
		_, err = s.Write([]byte(ruleForHashing))
		if err != nil {
			slog.Error("failed to hash rule", "rule", rule, "error", err)
		}
		hash = s.Sum(hash[0:0])
		hashes[i] = base64.RawURLEncoding.EncodeToString(hash)[:hashLength]
	}
	return hashes
}
