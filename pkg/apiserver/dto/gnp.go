package dto

type GlobalNetworkPolicy struct {
	ID       string         `json:"id"`
	UUID     string         `json:"uuid"`
	Version  int            `json:"version"`
	Metadata PolicyMetadata `json:"metadata"`
	Spec     PolicySpec     `json:"spec"`
}

type PolicyMetadata struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

type PolicySpec struct {
	Selector string   `json:"selector"`
	Types    []string `json:"types"`
	Ingress  []Rule   `json:"ingress"`
	Egress   []Rule   `json:"egress"`
}

type Rule struct {
	Action      string       `json:"action"`
	IPVersion   int          `json:"ip_version"`
	Metadata    RuleMetadata `json:"metadata"`
	Protocol    string       `json:"protocol"`
	Source      RuleEntity   `json:"source"`
	Destination RuleEntity   `json:"destination"`
}

type RuleMetadata struct {
	Annotations map[string]string `json:"annotations"`
}

type RuleEntity struct {
	Nets  []string `json:"nets"`
	Ports []string `json:"ports"`
}
