package dto

type HostEndpoint struct {
	ID          string               `json:"id"`
	UUID        string               `json:"uuid"`
	Version     uint                 `json:"version"`
	Metadata    HostEndpointMetadata `json:"metadata" yaml:"metadata"`
	Spec        HostEndpointSpec     `json:"spec" yaml:"spec"`
	Description string               `json:"description" yaml:"description"`
}

type HostEndpointMetadata struct {
	Name   string            `json:"name" yaml:"name"`
	Labels map[string]string `json:"labels" yaml:"labels"`
}

type HostEndpointSpec struct {
	InterfaceName string                 `json:"interfaceName" yaml:"interfaceName"`
	IPs           []string               `json:"ips" yaml:"ips"`
	Ports         []HostEndpointSpecPort `json:"ports" yaml:"ports"`
}

type HostEndpointSpecPort struct {
	Name     string `json:"name" yaml:"name"`
	Port     int    `json:"port" yaml:"port"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

type FetchPoliciesOutput struct {
	MetaData       HostEndPointPolicyMetadata `json:"metadata"`
	HEP            *HostEndpoint              `json:"hostEndpoint"`
	ParsedPolicies []*ParsedPolicy            `json:"parsedPolicies"`
	ParsedSets     []*ParsedSet               `json:"parsedSets"`
}

type HostEndPointPolicyMetadata struct {
	HEPVersion  uint            `json:"hepVersion"`
	GNPVersions map[string]uint `json:"gnpVersions"`
	GNSVersions map[string]uint `json:"gnsVersions"`
}

type ParsedPolicy struct {
	UUID          string        `json:"uuid"`
	Version       uint          `json:"version"`
	Name          string        `json:"name"`
	InboundRules  []*ParsedRule `json:"inboundRules"`
	OutboundRules []*ParsedRule `json:"outboundRules"`
}

type ParsedRule struct {
	Action             string   `json:"action"`
	IPVersion          int      `json:"ipVersion"`
	Protocol           string   `json:"protocol"`
	IsProtocolNegative bool     `json:"isProtocolNegative"`
	SrcNets            []string `json:"srcNets"`
	IsSrcNetNegative   bool     `json:"isSrcNetNegative"`
	SrcGNSNetNames     []string `json:"srcGNSNetNames"`
	SrcPorts           []string `json:"srcPorts"`
	IsSrcPortNegative  bool     `json:"isSrcPortNegative"`
	DstNets            []string `json:"dstNets"`
	IsDstNetNegative   bool     `json:"isDstNetNegative"`
	DstGNSNetNames     []string `json:"dstGNSNetNames"`
	DstPorts           []string `json:"dstPorts"`
	IsDstPortNegative  bool     `json:"isDstPortNegative"`
}

type ParsedSet struct {
	Name      string   `json:"name"`
	IPVersion int      `json:"ipVersion"`
	Nets      []string `json:"nets"`
}
