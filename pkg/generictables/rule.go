package generictables

type Rule struct {
	Match   MathCriteria
	Action  Action
	Comment []string
}

type Chain struct {
	Name  string
	Rules []Rule
}
