package generictables

const (
	HashPrefix = "bamboo:"
	LogPrefix  = "[bambooFW] "

	TableFilter = "filter"

	DefaultChainInput  = "INPUT"
	DefaultChainOutput = "OUTPUT"

	ChainNamePrefix = "BAMBOO-"

	OurDefaultInputChain  = ChainNamePrefix + DefaultChainInput
	OurDefaultOutputChain = ChainNamePrefix + DefaultChainOutput

	OurInputChainPrefix  = ChainNamePrefix + "PI-"
	OurOutputChainPrefix = ChainNamePrefix + "PO-"

	IPFamily4 = 4
	IPFamily6 = 6
)

type Table interface {
	SetDefaultRuleOfDefaultChain(chainName string, rule Rule)
	UpdateChains(chains []*Chain)
	Apply()
}
