package iptables

import (
	"fmt"
	"strings"

	"github.com/bamboo-firewall/agent/pkg/generictables"
)

const (
	maxCommentLength = 256
)

type Renderer interface {
	RenderAppend(rule *generictables.Rule, chainName string, hash string) string
	RenderInsert(rule *generictables.Rule, chainName string, hash string) string
	RenderInsertAtIndex(rule *generictables.Rule, chainName string, index int, hash string) string
	RenderReplace(rule *generictables.Rule, chainName string, index int, hash string) string
	RenderDelete(renderedRule string) string
	RenderDeleteAtIndex(chainName string, index int) string
	RuleHashes(c *generictables.Chain) []string
}

func NewRenderer(hashCommentPrefix string) Renderer {
	return &renderer{
		hashCommentPrefix: hashCommentPrefix,
	}
}

type renderer struct {
	hashCommentPrefix string
}

func (r *renderer) RenderAppend(rule *generictables.Rule, chainName string, hash string) string {
	var options []string
	commandOptions := fmt.Sprintf("-A %s", chainName)
	options = append(options, commandOptions)
	return r.render(options, r.commentParam(hash), rule.Match, rule.Action, rule.Comment)
}

func (r *renderer) RenderInsert(rule *generictables.Rule, chainName string, hash string) string {
	var options []string
	commandOptions := fmt.Sprintf("-I %s", chainName)
	options = append(options, commandOptions)
	return r.render(options, r.commentParam(hash), rule.Match, rule.Action, rule.Comment)
}

func (r *renderer) RenderInsertAtIndex(rule *generictables.Rule, chainName string, index int, hash string) string {
	var options []string
	commandOptions := fmt.Sprintf("-I %s %d", chainName, index)
	options = append(options, commandOptions)
	return r.render(options, r.commentParam(hash), rule.Match, rule.Action, rule.Comment)
}

func (r *renderer) RenderReplace(rule *generictables.Rule, chainName string, index int, hash string) string {
	var options []string
	commandOptions := fmt.Sprintf("-R %s %d", chainName, index)
	options = append(options, commandOptions)
	return r.render(options, r.commentParam(hash), rule.Match, rule.Action, rule.Comment)
}

func (r *renderer) RenderDelete(renderedRule string) string {
	return strings.Replace(renderedRule, "-A", "-D", 1)
}

func (r *renderer) RenderDeleteAtIndex(chainName string, index int) string {
	return fmt.Sprintf("-D %s %d", chainName, index)
}

func (r *renderer) RuleHashes(c *generictables.Chain) []string {
	renderFn := func(rule *generictables.Rule, chainName string) string {
		return r.RenderAppend(rule, chainName, "HASH")
	}
	return generictables.RuleHashes(c, renderFn)
}

func (r *renderer) render(options []string, hashCommentParameter string, match generictables.MatchCriteria, action generictables.Action, comments []string) string {
	if hashCommentParameter != "" {
		options = append(options, hashCommentParameter)
	}

	for _, comment := range comments {
		comment = r.truncateComment(comment)
		options = append(options, r.commentParam(comment))
	}

	if match != nil {
		matchParameter := match.Render()
		if matchParameter != "" {
			options = append(options, matchParameter)
		}
	}

	if action != nil {
		actionParameter := action.ToParameter()
		if actionParameter != "" {
			options = append(options, actionParameter)
		}
	}

	return strings.Join(options, " ")
}

func (r *renderer) commentParam(comment string) string {
	if comment == "HASH" || comment == "" {
		return comment
	}
	return fmt.Sprintf(`-m comment --comment "%s%s"`, r.hashCommentPrefix, comment)
}

func (r *renderer) truncateComment(s string) string {
	if len(s) > maxCommentLength {
		return s[:maxCommentLength]
	}
	return s
}
