package pkg

type LNURLAuthResponseStatus string

const (
	LNURLAuthResponseStatusOK    = "OK"
	LNURLAuthResponseStatusError = "ERROR"
)

type LNURLAuthResponse struct {
	Status LNURLAuthResponseStatus `json:"status"`
	Reason string                  `json:"reason,omitempty"`
}
