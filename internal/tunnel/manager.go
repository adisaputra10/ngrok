package tunnel

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"gotunnel/internal/database"
	"gotunnel/internal/models"
	"gotunnel/internal/protocol"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Manager handles all active tunnel connections
type Manager struct {
	mu      sync.RWMutex
	tunnels map[string]*Connection // subdomain -> connection
	db      database.DB
	domain  string
}

// Connection represents an active tunnel connection
type Connection struct {
	ID          string
	Subdomain   string
	UserID      int64
	Username    string
	LocalPort   int
	Conn        *websocket.Conn
	ConnectedAt time.Time
	Requests    int64
	pending     map[string]chan *protocol.HTTPResponsePayload // request ID -> response channel
	mu          sync.Mutex
	writeMu     sync.Mutex // protects concurrent WebSocket writes
	done        chan struct{}
}

// NewManager creates a new tunnel manager
func NewManager(db database.DB, domain string) *Manager {
	return &Manager{
		tunnels: make(map[string]*Connection),
		db:      db,
		domain:  domain,
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024 * 64,
	WriteBufferSize: 1024 * 64,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

// HandleWebSocket handles a new WebSocket tunnel connection
func (m *Manager) HandleWebSocket(w http.ResponseWriter, r *http.Request, user *models.User) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[tunnel] WebSocket upgrade failed: %v", err)
		return
	}

	// Read the tunnel init message
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		log.Printf("[tunnel] Failed to read init message: %v", err)
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{}) // Remove deadline

	var message protocol.Message
	if err := json.Unmarshal(msg, &message); err != nil {
		sendError(conn, "Invalid message format")
		conn.Close()
		return
	}

	if message.Type != protocol.TypeTunnelInit {
		sendError(conn, "Expected tunnel_init message")
		conn.Close()
		return
	}

	var initPayload protocol.TunnelInitPayload
	if err := message.ParsePayload(&initPayload); err != nil {
		sendError(conn, "Invalid init payload")
		conn.Close()
		return
	}

	subdomain := initPayload.Subdomain

	// Validate subdomain
	if !isValidSubdomain(subdomain) {
		sendError(conn, "Invalid subdomain. Use lowercase letters, numbers, and hyphens (1-63 chars)")
		conn.Close()
		return
	}

	// Check if subdomain is reserved by another user
	existingTunnel, err := m.db.GetTunnelBySubdomain(subdomain)
	if err == nil && existingTunnel.UserID != user.ID && existingTunnel.Reserved {
		sendError(conn, "Subdomain is reserved by another user")
		conn.Close()
		return
	}

	// Create or update tunnel record in DB
	if err != nil {
		// Tunnel doesn't exist, create it
		_, err = m.db.CreateTunnel(user.ID, subdomain, false)
		if err != nil {
			sendError(conn, "Failed to create tunnel: "+err.Error())
			conn.Close()
			return
		}
	}

	// Check if there's already an active connection for this subdomain
	m.mu.Lock()
	if existing, ok := m.tunnels[subdomain]; ok {
		// Close the existing connection (re-connect case)
		existing.Close()
		delete(m.tunnels, subdomain)
	}

	tunnelID := uuid.New().String()
	tunnelConn := &Connection{
		ID:          tunnelID,
		Subdomain:   subdomain,
		UserID:      user.ID,
		Username:    user.Username,
		LocalPort:   initPayload.LocalPort,
		Conn:        conn,
		ConnectedAt: time.Now(),
		pending:     make(map[string]chan *protocol.HTTPResponsePayload),
		done:        make(chan struct{}),
	}

	m.tunnels[subdomain] = tunnelConn
	m.mu.Unlock()

	// Update tunnel status in DB
	m.db.UpdateTunnelStatus(subdomain, "online")

	// Send tunnel ready message
	url := fmt.Sprintf("https://%s.%s", subdomain, m.domain)
	readyPayload := protocol.TunnelReadyPayload{
		URL:       url,
		Subdomain: subdomain,
		TunnelID:  tunnelID,
	}
	sendMessage(conn, protocol.TypeTunnelReady, "", readyPayload)

	log.Printf("[tunnel] %s connected: %s.%s (user: %s)", tunnelID[:8], subdomain, m.domain, user.Username)

	// Start reading responses from the client
	go m.readLoop(tunnelConn)

	// Start keepalive
	go m.keepAlive(tunnelConn)
}

// readLoop reads messages from the tunnel client
func (m *Manager) readLoop(tc *Connection) {
	defer func() {
		m.removeTunnel(tc)
	}()

	for {
		_, msg, err := tc.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[tunnel] %s read error: %v", tc.ID[:8], err)
			}
			return
		}

		var message protocol.Message
		if err := json.Unmarshal(msg, &message); err != nil {
			log.Printf("[tunnel] %s invalid message: %v", tc.ID[:8], err)
			continue
		}

		switch message.Type {
		case protocol.TypeHTTPResponse:
			var resp protocol.HTTPResponsePayload
			if err := message.ParsePayload(&resp); err != nil {
				log.Printf("[tunnel] %s invalid response payload: %v", tc.ID[:8], err)
				continue
			}

			tc.mu.Lock()
			if ch, ok := tc.pending[message.ID]; ok {
				ch <- &resp
				delete(tc.pending, message.ID)
			}
			tc.mu.Unlock()

		case protocol.TypePong:
			// Keepalive response, nothing to do

		default:
			log.Printf("[tunnel] %s unknown message type: %s", tc.ID[:8], message.Type)
		}
	}
}

// keepAlive sends periodic ping messages
func (m *Manager) keepAlive(tc *Connection) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := tc.sendMessageSafe(protocol.TypePing, "", nil); err != nil {
				return
			}
		case <-tc.done:
			return
		}
	}
}

// removeTunnel removes a tunnel connection
func (m *Manager) removeTunnel(tc *Connection) {
	m.mu.Lock()
	if existing, ok := m.tunnels[tc.Subdomain]; ok && existing.ID == tc.ID {
		delete(m.tunnels, tc.Subdomain)
	}
	m.mu.Unlock()

	tc.Close()
	m.db.UpdateTunnelStatus(tc.Subdomain, "offline")

	log.Printf("[tunnel] %s disconnected: %s.%s", tc.ID[:8], tc.Subdomain, m.domain)
}

// ForwardRequest forwards an HTTP request through the tunnel and waits for a response
func (m *Manager) ForwardRequest(subdomain string, req *protocol.HTTPRequestPayload) (*protocol.HTTPResponsePayload, error) {
	m.mu.RLock()
	tc, ok := m.tunnels[subdomain]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("tunnel not found for subdomain: %s", subdomain)
	}

	requestID := uuid.New().String()

	// Create response channel
	respCh := make(chan *protocol.HTTPResponsePayload, 1)
	tc.mu.Lock()
	tc.pending[requestID] = respCh
	tc.Requests++
	tc.mu.Unlock()

	// Send request to client
	if err := tc.sendMessageSafe(protocol.TypeHTTPRequest, requestID, req); err != nil {
		tc.mu.Lock()
		delete(tc.pending, requestID)
		tc.mu.Unlock()
		return nil, fmt.Errorf("failed to send request to client: %w", err)
	}

	// Increment DB counter
	m.db.IncrementTunnelRequests(subdomain)

	// Wait for response with timeout
	select {
	case resp := <-respCh:
		return resp, nil
	case <-time.After(60 * time.Second):
		tc.mu.Lock()
		delete(tc.pending, requestID)
		tc.mu.Unlock()
		return nil, fmt.Errorf("request timeout (60s)")
	case <-tc.done:
		return nil, fmt.Errorf("tunnel disconnected")
	}
}

// GetConnection returns the active connection for a subdomain
func (m *Manager) GetConnection(subdomain string) (*Connection, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tc, ok := m.tunnels[subdomain]
	return tc, ok
}

// GetActiveConnections returns all active tunnel connections
func (m *Manager) GetActiveConnections() []*models.ConnectionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var connections []*models.ConnectionInfo
	for _, tc := range m.tunnels {
		connections = append(connections, &models.ConnectionInfo{
			TunnelID:    tc.ID,
			Subdomain:   tc.Subdomain,
			URL:         fmt.Sprintf("https://%s.%s", tc.Subdomain, m.domain),
			LocalPort:   tc.LocalPort,
			ConnectedAt: tc.ConnectedAt,
			Requests:    tc.Requests,
			UserID:      tc.UserID,
			Username:    tc.Username,
		})
	}
	return connections
}

// GetActiveConnectionsForUser returns active connections for a specific user
func (m *Manager) GetActiveConnectionsForUser(userID int64) []*models.ConnectionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var connections []*models.ConnectionInfo
	for _, tc := range m.tunnels {
		if tc.UserID == userID {
			connections = append(connections, &models.ConnectionInfo{
				TunnelID:    tc.ID,
				Subdomain:   tc.Subdomain,
				URL:         fmt.Sprintf("https://%s.%s", tc.Subdomain, m.domain),
				LocalPort:   tc.LocalPort,
				ConnectedAt: tc.ConnectedAt,
				Requests:    tc.Requests,
				UserID:      tc.UserID,
				Username:    tc.Username,
			})
		}
	}
	return connections
}

// Close closes a tunnel connection
func (tc *Connection) Close() {
	select {
	case <-tc.done:
		// Already closed
	default:
		close(tc.done)
	}
	tc.Conn.Close()
}

// --- Helpers ---

func sendMessage(conn *websocket.Conn, msgType string, id string, payload interface{}) error {
	msg, err := protocol.NewMessage(msgType, id, payload)
	if err != nil {
		return err
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}

// sendMessageSafe writes to the WebSocket with a mutex to prevent concurrent writes
func (tc *Connection) sendMessageSafe(msgType string, id string, payload interface{}) error {
	tc.writeMu.Lock()
	defer tc.writeMu.Unlock()
	return sendMessage(tc.Conn, msgType, id, payload)
}

func sendError(conn *websocket.Conn, errMsg string) {
	sendMessage(conn, protocol.TypeTunnelError, "", protocol.TunnelErrorPayload{Error: errMsg})
}

func isValidSubdomain(s string) bool {
	if len(s) < 1 || len(s) > 63 {
		return false
	}
	for i, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		if c == '-' && i > 0 && i < len(s)-1 {
			continue
		}
		return false
	}
	return true
}
