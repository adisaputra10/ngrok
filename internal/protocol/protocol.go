package protocol

import "encoding/json"

// Message types for the WebSocket tunnel protocol
const (
	// Client -> Server
	TypeTunnelInit = "tunnel_init" // Initialize a new tunnel
	TypeHTTPResponse = "http_response" // Response from local service
	TypePong         = "pong"          // Keepalive response

	// Server -> Client
	TypeTunnelReady = "tunnel_ready" // Tunnel is ready
	TypeTunnelError = "tunnel_error" // Error occurred
	TypeHTTPRequest = "http_request" // Forward this HTTP request
	TypePing        = "ping"         // Keepalive
)

// Message is the top-level WebSocket message envelope
type Message struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// TunnelInitPayload is sent by the client to initialize a tunnel
type TunnelInitPayload struct {
	AuthToken string `json:"auth_token"`
	Subdomain string `json:"subdomain"`
	LocalPort int    `json:"local_port"`
	Version   string `json:"version,omitempty"`
}

// TunnelReadyPayload is sent by the server when tunnel is active
type TunnelReadyPayload struct {
	URL       string `json:"url"`
	Subdomain string `json:"subdomain"`
	TunnelID  string `json:"tunnel_id"`
}

// TunnelErrorPayload is sent by the server on error
type TunnelErrorPayload struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// HTTPRequestPayload is sent by the server to forward an HTTP request
type HTTPRequestPayload struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Host    string              `json:"host"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body,omitempty"`
}

// HTTPResponsePayload is sent by the client with the local service response
type HTTPResponsePayload struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"body,omitempty"`
}

// NewMessage creates a new protocol message with encoded payload
func NewMessage(msgType string, id string, payload interface{}) (*Message, error) {
	var raw json.RawMessage
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		raw = data
	}
	return &Message{
		Type:    msgType,
		ID:      id,
		Payload: raw,
	}, nil
}

// ParsePayload decodes the payload into the given struct
func (m *Message) ParsePayload(v interface{}) error {
	return json.Unmarshal(m.Payload, v)
}
