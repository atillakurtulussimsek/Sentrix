package protocol

import "time"

// HostState is the latest non-numeric snapshot of a host (overwritten on each send).
type HostState struct {
	CollectedAt   time.Time       `json:"collected_at"`
	Uptime        int64           `json:"uptime_seconds"`
	ProcessCount  int             `json:"process_count"`
	TopCPU        []ProcessInfo   `json:"top_cpu"`
	TopMem        []ProcessInfo   `json:"top_mem"`
	FailedUnits   []string        `json:"failed_units"`
	Services      []ServiceStatus `json:"services"`
	Containers    []Container     `json:"containers"`
	DockerPresent bool            `json:"docker_present"`
	Reboot        RebootStatus    `json:"reboot"`
	Certificates  []CertStatus    `json:"certificates,omitempty"`
}

// ProcessInfo describes a single process in a top list.
type ProcessInfo struct {
	PID        int     `json:"pid"`
	Name       string  `json:"name"`
	User       string  `json:"user"`
	CPUPercent float64 `json:"cpu_percent"`
	RSSBytes   uint64  `json:"rss_bytes"`
}

// ServiceStatus is the state of a watched systemd unit.
type ServiceStatus struct {
	Name        string `json:"name"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
}

// Container is a Docker container seen on the host.
type Container struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Image        string  `json:"image"`
	State        string  `json:"state"`
	Status       string  `json:"status"`
	RestartCount int     `json:"restart_count"`
	CPUPercent   float64 `json:"cpu_percent"`
	MemBytes     uint64  `json:"mem_bytes"`
}

// RebootStatus reports whether the host needs a reboot and why.
type RebootStatus struct {
	Required      bool      `json:"required"`
	Reasons       []string  `json:"reasons,omitempty"`
	RunningKernel string    `json:"running_kernel"`
	NewestKernel  string    `json:"newest_kernel,omitempty"`
	Since         time.Time `json:"since,omitempty"`
}

// CertStatus is the TLS certificate expiry of a configured endpoint.
type CertStatus struct {
	Endpoint string    `json:"endpoint"`
	Subject  string    `json:"subject"`
	NotAfter time.Time `json:"not_after"`
	Error    string    `json:"error,omitempty"`
}
