package iptables

type Renderer interface{}

func NewRenderer(hashCommentPrefix string) Renderer {
	return &renderer{
		hashCommentPrefix: hashCommentPrefix,
	}
}

type renderer struct {
	hashCommentPrefix string
}
