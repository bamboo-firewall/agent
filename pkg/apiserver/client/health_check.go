package client

import (
	"context"
	"fmt"
	"net/http"
)

func (c *apiServer) Ping(ctx context.Context) error {
	res := c.client.NewRequest().
		SetSubURL("/api/internal/v1/hostEndpoints/byName/my_host/fetchPolicies").
		SetMethod(http.MethodPost).
		SetBody(nil).
		DoRequest(ctx)
	if res.Err != nil {
		return fmt.Errorf("failed to fetch new policy: %w", res.Err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code when fetch new policy, status code: %d, response: %s", res.StatusCode, string(res.Body))
	}
	return nil
}
