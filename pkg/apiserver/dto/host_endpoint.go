package dto

type HostEndpoint struct {
	ID      string
	Version int
}

type FetchPoliciesOutput struct {
	IsNew        bool                   `json:"isNew"`
	HostEndpoint *HostEndpoint          `json:"hostEndpoint"`
	GNPs         []*GlobalNetworkPolicy `json:"globalNetworkPolicies"`
	GNSs         []*GlobalNetworkSet    `json:"globalNetworkSets"`
}
