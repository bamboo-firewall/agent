package ipset

import (
	"fmt"
)

const (
	namePrefix    = "BAMBOO-"
	maxNameLength = 31
)

type NameConvention struct {
	// mainNameOfSet map uuid -> name of sets in ipset
	mainNameOfSet map[string]string
}

func NewNameConvention() *NameConvention {
	return &NameConvention{
		mainNameOfSet: make(map[string]string),
	}
}

func (i *NameConvention) SetMainNameOfSet(uuid string, index int, ipVersion int, sourceName, name string) string {
	mainNameOfSet := fmt.Sprintf("%s%sv%d-%d-%s", namePrefix, sourceName, ipVersion, index, name)
	if len(mainNameOfSet) > maxNameLength {
		mainNameOfSet = mainNameOfSet[:maxNameLength]
	}
	i.mainNameOfSet[uuid] = mainNameOfSet
	return mainNameOfSet
}

func (i *NameConvention) GetMainNameOfSetByUUID(uuid string) (mainName string, present bool) {
	mainName, present = i.mainNameOfSet[uuid]
	return
}
