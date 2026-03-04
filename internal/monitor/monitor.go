package monitor

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"gotunnel/internal/database"
	"gotunnel/internal/models"
)

// Service is the uptime monitoring background service
type Service struct {
	db     database.DB
	mu     sync.Mutex
	timers map[int64]*time.Ticker
	done   map[int64]chan struct{}
	client *http.Client
}

// New creates a new monitor service
func New(db database.DB) *Service {
	return &Service{
		db:     db,
		timers: make(map[int64]*time.Ticker),
		done:   make(map[int64]chan struct{}),
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// Start loads all enabled monitors and begins their check loops
func (s *Service) Start() {
	monitors, err := s.db.GetAllUptimeMonitors()
	if err != nil {
		log.Printf("[monitor] Failed to load monitors: %v", err)
		return
	}
	for _, m := range monitors {
		s.StartMonitor(m)
	}
	log.Printf("[monitor] Started %d uptime monitors", len(monitors))
}

// StartMonitor begins the check loop for a single monitor
func (s *Service) StartMonitor(m *models.UptimeMonitor) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stop existing loop if any
	if ch, ok := s.done[m.ID]; ok {
		close(ch)
	}

	interval := time.Duration(m.IntervalMin) * time.Minute
	ticker := time.NewTicker(interval)
	done := make(chan struct{})

	s.timers[m.ID] = ticker
	s.done[m.ID] = done

	go func(monitor *models.UptimeMonitor) {
		// Run immediately on start
		s.check(monitor)
		for {
			select {
			case <-ticker.C:
				// Re-fetch monitor to get latest settings
				current, err := s.db.GetUptimeMonitorByID(monitor.ID)
				if err != nil || !current.Enabled {
					return
				}
				s.check(current)
			case <-done:
				ticker.Stop()
				return
			}
		}
	}(m)
}

// StopMonitor stops the check loop for a monitor
func (s *Service) StopMonitor(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.done[id]; ok {
		close(ch)
		delete(s.done, id)
		delete(s.timers, id)
	}
}

// CheckResult holds the result of a single check
type CheckResult struct {
	Status     string
	LatencyMs  float64
	StatusCode int
	Error      string
}

// check performs a single ping+HTTP check for a monitor
func (s *Service) check(m *models.UptimeMonitor) {
	result := s.doCheck(m)

	now := time.Now()
	s.db.UpdateUptimeMonitorStatus(m.ID, result.Status, result.LatencyMs, now)
	s.db.LogUptimeCheck(m.ID, result.Status, result.LatencyMs, result.StatusCode, result.Error)

	statusIcon := "✓"
	if result.Status == "down" {
		statusIcon = "✗"
	}
	log.Printf("[monitor] %s [%s] %s — %.0fms %s", statusIcon, m.CheckType, m.URL, result.LatencyMs, result.Error)
}

// doCheck executes the actual connectivity check
func (s *Service) doCheck(m *models.UptimeMonitor) CheckResult {
	switch m.CheckType {
	case "tcp":
		return s.doTCPCheck(m)
	default:
		return s.doHTTPCheck(m)
	}
}

// doHTTPCheck performs an HTTP/HTTPS GET request (like curl)
func (s *Service) doHTTPCheck(m *models.UptimeMonitor) CheckResult {
	timeout := time.Duration(m.TimeoutSec) * time.Second
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	start := time.Now()
	resp, err := client.Get(m.URL)
	latency := float64(time.Since(start).Milliseconds())

	if err != nil {
		return CheckResult{Status: "down", LatencyMs: latency, StatusCode: 0, Error: err.Error()}
	}
	defer resp.Body.Close()

	expected := m.ExpectedCode
	if expected == 0 {
		expected = 200
	}

	if resp.StatusCode == expected || (expected == 200 && resp.StatusCode >= 200 && resp.StatusCode < 400) {
		return CheckResult{Status: "up", LatencyMs: latency, StatusCode: resp.StatusCode}
	}
	return CheckResult{
		Status:     "down",
		LatencyMs:  latency,
		StatusCode: resp.StatusCode,
		Error:      fmt.Sprintf("unexpected status %d", resp.StatusCode),
	}
}

// doTCPCheck performs a TCP dial check (like ping - checks reachability)
func (s *Service) doTCPCheck(m *models.UptimeMonitor) CheckResult {
	timeout := time.Duration(m.TimeoutSec) * time.Second

	// Parse host:port from URL
	host := m.URL
	if u, err := url.Parse(m.URL); err == nil && u.Host != "" {
		host = u.Host
		if u.Port() == "" {
			if u.Scheme == "https" {
				host = net.JoinHostPort(u.Hostname(), "443")
			} else {
				host = net.JoinHostPort(u.Hostname(), "80")
			}
		}
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", host, timeout)
	latency := float64(time.Since(start).Milliseconds())

	if err != nil {
		return CheckResult{Status: "down", LatencyMs: latency, Error: err.Error()}
	}
	conn.Close()
	return CheckResult{Status: "up", LatencyMs: latency}
}
