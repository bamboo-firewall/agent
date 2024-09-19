package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bamboo-firewall/agent/pkg/apiserver/dto"
)

func (c *apiServer) FetchPolicies(ctx context.Context, hostName string) (*dto.FetchPoliciesOutput, error) {
	res := c.client.NewRequest().
		SetSubURL(fmt.Sprintf("/api/internal/v1/hostEndpoints/byName/%s/fetchPolicies", hostName)).
		SetMethod(http.MethodGet).
		DoRequest(ctx)
	if res.Err != nil {
		return nil, fmt.Errorf("failed to fetch new policy: %w", res.Err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code when fetch new policy, status code: %d, response: %s", res.StatusCode, string(res.Body))
	}

	var output *dto.FetchPoliciesOutput
	if err := json.Unmarshal(res.Body, &output); err != nil {
		return nil, fmt.Errorf("unexpected response when fetch new policy, response: %s, err: %w",
			string(res.Body), err)
	}
	return output, nil
}
