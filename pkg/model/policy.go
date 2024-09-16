package model

type Policy struct {
	ID            string
	UUID          string
	Version       string
	InboundRules  []*Rule
	OutboundRules []*Rule
}

type Rule struct {
	Action                  string
	IPVersion               int
	Metadata                map[string]string
	Protocol                string
	SrcNets                 []string
	SrcPorts                []string
	SrcNamedPortIpSetIDs    []string
	DstNets                 []string
	DstPorts                []string
	DstNamedPortIpSetIDs    []string
	NotProtocol             string
	NotSrcNets              []string
	NotSrcPorts             []string
	NotSrcNamedPortIpSetIDs []string
	NotDstNets              []string
	NotDstPorts             []string
	NotDstNamedPortIpSetIDs []string
}
