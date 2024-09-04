package client

import "github.com/bamboo-firewall/agent/pkg/http"

type apiServer struct {
	client *http.Client
	count  int
}

func NewAPIServer() *apiServer {
	return &apiServer{client: http.NewClient("")}
}
