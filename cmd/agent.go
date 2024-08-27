package main

import "github.com/bamboo-firewall/agent/dataplane/linux"

func main() {
	internalDataplane := linux.NewInternalDataplane()
	internalDataplane.Start()
}
