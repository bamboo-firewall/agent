package dto

type Policy struct {
	UUID     string         `json:"uuid"`
	Version  string         `json:"version"`
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
