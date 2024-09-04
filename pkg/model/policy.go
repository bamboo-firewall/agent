package model

type Policy struct {
	InboundRules  []*Rule
	OutboundRules []*Rule
}

type Rule struct {
	Action               string
	IPVersion            string
	Protocol             string
	SrcNet               []string
	SrcPorts             []string
	SrcNamedPortIpSetIDs []string
	DstNet               []string
	DstPorts             []string
	DstNamedPortIpSetIDs []string
}
