package generictables

type MatchCriteria interface {
	Render() string
	String() string
	Merge(match MatchCriteria) MatchCriteria
	Copy() MatchCriteria
	ConntrackState(stateNames string) MatchCriteria
	NotConntrackState(stateNames string) MatchCriteria
	Protocol(protocol interface{}) MatchCriteria
	NotProtocol(protocol interface{}) MatchCriteria
	ProtocolNum(num uint8) MatchCriteria
	NotProtocolNum(num uint8) MatchCriteria
	SourceNet(net string) MatchCriteria
	NotSourceNet(net string) MatchCriteria
	DestNet(net string) MatchCriteria
	NotDestNet(net string) MatchCriteria
	SourceIPSet(name string) MatchCriteria
	NotSourceIPSet(name string) MatchCriteria
	DestIPSet(name string) MatchCriteria
	NotDestIPSet(name string) MatchCriteria
	SourcePorts(ports []string) MatchCriteria
	NotSourcePorts(ports []string) MatchCriteria
	DestPorts(ports []string) MatchCriteria
	NotDestPorts(ports []string) MatchCriteria
}
