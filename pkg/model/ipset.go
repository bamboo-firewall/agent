package model

type IPSet struct {
	ID        string
	Name      string
	Version   int
	IPVersion int
	Members   []string
}
