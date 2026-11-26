// Package protocol defines the wire types exchanged between sentrix-agent and sentrix-server.
//
// All payloads are JSON over HTTPS. Agents authenticate with a client certificate issued at
// enrolment; the only unauthenticated agent endpoints are CA retrieval and enrolment itself.
package protocol

import "time"

// API paths served by the agent gateway.
const (
	PathCA        = "/agent/v1/ca"
	PathEnroll    = "/agent/v1/enroll"
	PathHeartbeat = "/agent/v1/heartbeat"
	PathMetrics   = "/agent/v1/metrics"
	PathState     = "/agent/v1/state"
	PathInventory = "/agent/v1/inventory"
	PathCommands  = "/agent/v1/commands"
	PathResults   = "/agent/v1/results"
	PathRenew     = "/agent/v1/renew"
)

// EnrollRequest exchanges a one-time token and a CSR for a client certificate.
type EnrollRequest struct {
	Token     string `json:"token"`
	Hostname  string `json:"hostname"`
	MachineID string `json:"machine_id"`
	CSRPEM    string `json:"csr_pem"`
}

// EnrollResponse carries the issued identity.
type EnrollResponse struct {
	AgentID   string `json:"agent_id"`
	CertPEM   string `json:"cert_pem"`
	CACertPEM string `json:"ca_cert_pem"`
}

// RenewRequest asks for a fresh certificate for the same identity.
type RenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// Heartbeat is sent periodically by every agent.
type Heartbeat struct {
	AgentVersion string    `json:"agent_version"`
	Hostname     string    `json:"hostname"`
	BootTime     time.Time `json:"boot_time"`
	SentAt       time.Time `json:"sent_at"`
}

// HeartbeatResponse lets the server tune the agent remotely.
type HeartbeatResponse struct {
	ServerTime      time.Time `json:"server_time"`
	IntervalSeconds int       `json:"interval_seconds"`
	WatchServices   []string  `json:"watch_services,omitempty"`
	TLSEndpoints    []string  `json:"tls_endpoints,omitempty"`
}

// Sample is one numeric measurement. Labels are encoded as a stable "k=v,k=v" string
// so a (Name, Labels) pair identifies a series.
type Sample struct {
	TS     int64   `json:"t"` // unix seconds
	Name   string  `json:"n"`
	Labels string  `json:"l,omitempty"`
	Value  float64 `json:"v"`
}

// MetricsBatch is a group of samples, possibly replayed from the agent's disk buffer.
type MetricsBatch struct {
	Samples []Sample `json:"samples"`
}
