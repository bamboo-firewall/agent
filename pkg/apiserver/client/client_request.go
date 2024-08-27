package client

import "github.com/bamboo-firewall/agent/pkg/http"

type apiServer struct {
	client *http.Client
}

func NewAPIServer() *apiServer {
	return &apiServer{http.NewClient("")}
}
