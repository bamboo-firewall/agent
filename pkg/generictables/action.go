package generictables

type ActionFactory interface {
	Jump(target string) Action
	Allow() Action
	Drop() Action
	Log(prefix string) Action
}

type Action interface {
	ToParameter() string
	String() string
}
