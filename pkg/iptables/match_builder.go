package iptables

import (
	"fmt"
	"strings"

	"github.com/bamboo-firewall/agent/pkg/generictables"
)

var (
	_ generictables.MatchCriteria = (*matchBuilder)(nil)
)

func NewMatch() generictables.MatchCriteria {
	var m matchBuilder
	return m
}

type matchBuilder []string

func (m matchBuilder) Render() string {
	return strings.Join(m, " ")
}

func (m matchBuilder) String() string {
	return fmt.Sprintf("Match[%v]", []string(m))
}

func (m matchBuilder) Copy() generictables.MatchCriteria {
	var mCopy matchBuilder
	return append(mCopy, m...)
}

func (m matchBuilder) Merge(match generictables.MatchCriteria) generictables.MatchCriteria {
	if match == nil {
		return m
	}
	mBuilder := match.(matchBuilder)
	return append(m, mBuilder...)
}

func (m matchBuilder) ConntrackState(stateNames string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m conntrack --ctstate %s", stateNames))
}

func (m matchBuilder) NotConntrackState(stateNames string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m conntrack ! --ctstate %s", stateNames))
}

func (m matchBuilder) Protocol(protocol string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-p %s", protocol))
}

func (m matchBuilder) NotProtocol(protocol string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("! -p %s", protocol))
}

func (m matchBuilder) ProtocolNum(num uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-p %d", num))
}

func (m matchBuilder) NotProtocolNum(num uint8) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("! -p %d", num))
}

func (m matchBuilder) SourceNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("--source %s", net))
}

func (m matchBuilder) NotSourceNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("! --source %s", net))
}

func (m matchBuilder) DestNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("--destination %s", net))
}

func (m matchBuilder) NotDestNet(net string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("! --destination %s", net))
}

func (m matchBuilder) SourceIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set --match-set %s src", name))
}

func (m matchBuilder) NotSourceIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set ! --match-set %s src", name))
}

func (m matchBuilder) DestIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set --match-set %s dst", name))
}

func (m matchBuilder) NotDestIPSet(name string) generictables.MatchCriteria {
	return append(m, fmt.Sprintf("-m set ! --match-set %s dst", name))
}

func (m matchBuilder) SourcePorts(ports []string) generictables.MatchCriteria {
	joinPorts := strings.Join(ports, ",")
	return append(m, fmt.Sprintf("-m multiport --source-ports %s", joinPorts))
}

func (m matchBuilder) NotSourcePorts(ports []string) generictables.MatchCriteria {
	joinPorts := strings.Join(ports, ",")
	return append(m, fmt.Sprintf("-m multiport ! --source-ports %s", joinPorts))
}

func (m matchBuilder) DestPorts(ports []string) generictables.MatchCriteria {
	joinPorts := strings.Join(ports, ",")
	return append(m, fmt.Sprintf("-m multiport --destination-ports %s", joinPorts))
}

func (m matchBuilder) NotDestPorts(ports []string) generictables.MatchCriteria {
	joinPorts := strings.Join(ports, ",")
	return append(m, fmt.Sprintf("-m multiport ! --destination-ports %s", joinPorts))
}
