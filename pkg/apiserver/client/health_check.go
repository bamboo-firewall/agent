package client

import (
	"context"
	"fmt"
	"net/http"
)

func (c *apiServer) Ping(ctx context.Context) error {
	res := c.client.NewRequest().
		SetSubURL("/api/v1/ping").
		SetMethod(http.MethodGet).
		DoRequest(ctx)
	if res.Err != nil {
		return fmt.Errorf("failed to handshake to api-server: %w", res.Err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code when handshake to api-server, status code: %d, response: %s", res.StatusCode, string(res.Body))
	}
	return nil
}
