package iptables

import (
	"fmt"

	"github.com/bamboo-firewall/agent/pkg/generictables"
)

func NewAction() generictables.ActionFactory {
	return &actionFactory{}
}

type actionFactory struct{}

func (a *actionFactory) Allow() generictables.Action {
	return AcceptAction{}
}

func (a *actionFactory) Goto(target string) generictables.Action {
	return GotoAction{
		target: target,
	}
}

func (a *actionFactory) Return() generictables.Action {
	return ReturnAction{}
}

func (a *actionFactory) Reject(with string) generictables.Action {
	return RejectAction{with: with}
}

func (a *actionFactory) Jump(target string) generictables.Action {
	return JumpToChainAction{target: target}
}

func (a *actionFactory) Log(prefix string) generictables.Action {
	return LogAction{prefix: prefix}
}

func (a *actionFactory) Drop() generictables.Action {
	return DropAction{}
}

type AcceptAction struct{}

func (a AcceptAction) ToParameter() string {
	return "-j ACCEPT"
}

func (a AcceptAction) String() string {
	return "ACCEPT"
}

type RejectAction struct {
	with string
}

func (a RejectAction) ToParameter() string {
	return fmt.Sprintf("-j REJECT --reject-with %s", a.with)
}

func (a RejectAction) String() string {
	return "REJECT"
}

type ReturnAction struct{}

func (a ReturnAction) ToParameter() string {
	return "-j RETURN"
}

func (a ReturnAction) String() string {
	return "RETURN"
}

type LogAction struct {
	prefix string
}

func (a LogAction) ToParameter() string {
	// ToDo: move log level to config or const
	return fmt.Sprintf(`-j LOG --log-prefix "%s " --log-level 5`, a.prefix)
}

func (a LogAction) String() string {
	return "LOG"
}

type GotoAction struct {
	target string
}

func (a GotoAction) ToParameter() string {
	return fmt.Sprintf("-g %s", a.target)
}

func (a GotoAction) String() string {
	return fmt.Sprintf("GOTO->%s", a.target)
}

type JumpToChainAction struct {
	target string
}

func (a JumpToChainAction) ToParameter() string {
	return fmt.Sprintf("-j %s", a.target)
}

func (a JumpToChainAction) String() string {
	return fmt.Sprintf("JUMP->%s", a.target)
}

type DropAction struct{}

func (a DropAction) ToParameter() string {
	return fmt.Sprintf("-j DROP")
}

func (a DropAction) String() string {
	return "DROP"
}
