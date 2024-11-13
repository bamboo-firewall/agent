package dto

const (
	ProtocolTCP     = "tcp"
	ProtocolUDP     = "udp"
	ProtocolICMP    = "icmp"
	ProtocolSCTP    = "sctp"
	ProtocolUDPLite = "udplite"
)

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

type HostEndpointPolicy struct {
	MetaData   HostEndPointPolicyMetadata `json:"metadata"`
	HEP        *HostEndpoint              `json:"hostEndpoint"`
	ParsedGNPs []*ParsedGNP               `json:"parsedGNPs"`
	ParsedHEPs []*ParsedHEP               `json:"parsedHEPs"`
	ParsedGNSs []*ParsedGNS               `json:"parsedGNSs"`
}

type HostEndPointPolicyMetadata struct {
	HEPVersions map[string]uint `json:"hepVersions"`
	GNPVersions map[string]uint `json:"gnpVersions"`
	GNSVersions map[string]uint `json:"gnsVersions"`
}

type ParsedGNP struct {
	UUID          string        `json:"uuid"`
	Version       uint          `json:"version"`
	Name          string        `json:"name"`
	InboundRules  []*ParsedRule `json:"inboundRules"`
	OutboundRules []*ParsedRule `json:"outboundRules"`
}

type ParsedRule struct {
	Action             string      `json:"action"`
	IPVersion          int         `json:"ipVersion"`
	Protocol           interface{} `json:"protocol"`
	IsProtocolNegative bool        `json:"isProtocolNegative"`
	SrcNets            []string    `json:"srcNets"`
	IsSrcNetNegative   bool        `json:"isSrcNetNegative"`
	SrcGNSUUIDs        []string    `json:"srcGNSUUIDs"`
	SrcHEPUUIDs        []string    `json:"srcHEPUUIDs"`
	SrcPorts           []string    `json:"srcPorts"`
	IsSrcPortNegative  bool        `json:"isSrcPortNegative"`
	DstNets            []string    `json:"dstNets"`
	IsDstNetNegative   bool        `json:"isDstNetNegative"`
	DstGNSUUIDs        []string    `json:"dstGNSUUIDs"`
	DstHEPUUIDs        []string    `json:"dstHEPUUIDs"`
	DstPorts           []string    `json:"dstPorts"`
	IsDstPortNegative  bool        `json:"isDstPortNegative"`
}

type ParsedHEP struct {
	UUID  string   `json:"uuid"`
	Name  string   `json:"name"`
	IPsV4 []string `json:"ipsV4"`
	IPsV6 []string `json:"ipsV6"`
}

type ParsedGNS struct {
	UUID   string   `json:"uuid"`
	Name   string   `json:"name"`
	NetsV4 []string `json:"netsV4"`
	NetsV6 []string `json:"netsV6"`
}
