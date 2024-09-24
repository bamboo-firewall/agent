package dto

type GlobalNetworkSet struct {
	ID       string                   `json:"id"`
	Version  int                      `json:"version"`
	Metadata GlobalNetworkSetMetadata `json:"metadata"`
	Spec     GlobalNetworkSetSpec     `json:"spec"`
}

type GlobalNetworkSetMetadata struct {
	Name      string `json:"name"`
	IPVersion int    `json:"ipVersion"`
}

type GlobalNetworkSetSpec struct {
	Nets []string `json:"nets"`
}
