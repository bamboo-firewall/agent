package model

//type Agent struct {
//	Policy []*Policy
//	IPSet  []*IPSet
//}

type Agent struct {
	Policy *AgentPolicy
	IPSet  *AgentIPSet
}

type AgentPolicy struct {
	Policies []*Policy
}

type AgentIPSet struct {
	IPSets []*IPSet
}
