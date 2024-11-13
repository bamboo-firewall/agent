package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bamboo-firewall/agent/pkg/apiserver/dto"
	"github.com/bamboo-firewall/agent/pkg/http/ierror"
)

func (c *apiServer) FetchHostEndpointPolicy(ctx context.Context, tenantID uint64, ip string) ([]*dto.HostEndpointPolicy, error) {
	res := c.client.NewRequest().
		SetSubURL("/api/internal/v1/hostEndpoints/fetchPolicies").
		SetParams(map[string]string{
			"tenantID": fmt.Sprintf("%d", tenantID),
			"ip":       ip,
		}).
		SetMethod(http.MethodGet).
		DoRequest(ctx)
	if res.Err != nil {
		return nil, fmt.Errorf("failed to fetch policy for host endpoint: %w", res.Err)
	}
	if res.StatusCode != http.StatusOK {
		var ierr *ierror.Error
		if err := json.Unmarshal(res.Body, &ierr); err != nil {
			return nil, fmt.Errorf("unexpected status code when fetch new policy for host endpoint, status code: %d, response: %s", res.StatusCode, string(res.Body))
		}
		if ierr.Code == 0 {
			return nil, fmt.Errorf("unexpected status code when fetch new policy for host endpoint, status code: %d, response: %s", res.StatusCode, string(res.Body))
		} else {
			return nil, fmt.Errorf("unexpected status code when fetch new policy for host endpoint, status code: %d, err: %w", res.StatusCode, ierr)
		}
	}

	var output []*dto.HostEndpointPolicy
	if err := json.Unmarshal(res.Body, &output); err != nil {
		return nil, fmt.Errorf("unexpected response when fetch new policy for host endpoint, response: %s, err: %w",
			string(res.Body), err)
	}
	return output, nil
}
