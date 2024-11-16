package ierror

import "fmt"

type ErrorCode uint16
type ErrorName string

type Error struct {
	Code    ErrorCode   `json:"code"`
	Name    ErrorName   `json:"name"`
	Message string      `json:"message"`
	Detail  interface{} `json:"detail,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d:%s msg[%s]", e.Code, e.Name, e.Message)
}
