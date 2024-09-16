package dto

type HostEndpoint struct {
	ID      string
	Version int
}

type FetchPoliciesOutput struct {
	IsNew        bool                   `json:"is_new"`
	HostEndpoint *HostEndpoint          `json:"host_endpoint"`
	GNPs         []*GlobalNetworkPolicy `json:"global_network_policies"`
	GNSs         []*GlobalNetworkSet    `json:"global_network_sets"`
}
