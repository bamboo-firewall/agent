package client

func (c *apiServer) FetchNewPolicy() (interface{}, error) {
	if c.count == 2 {
		return nil, nil
	}
	c.count++
	return "policy here", nil
}
