package model

type AgentMetadata struct {
	HEPVersion  uint
	GNPVersions map[string]uint
	GNSVersions map[string]uint
}
