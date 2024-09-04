package dto

type Rule struct {
	Action      string       `json:"action"`
	IPVersion   *int         `json:"ip_version"`
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
