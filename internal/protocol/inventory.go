package protocol

import "time"

// Inventory is a full description of what is installed on a host.
type Inventory struct {
	CollectedAt    time.Time       `json:"collected_at"`
	OS             OSInfo          `json:"os"`
	PackageManager string          `json:"package_manager"` // dpkg | rpm | apk
	Packages       []Package       `json:"packages"`
	Updates        []Update        `json:"updates"`
	Ports          []ListeningPort `json:"ports"`
	Images         []string        `json:"images"`
	Errors         []string        `json:"errors,omitempty"`
}

// OSInfo identifies the operating system.
type OSInfo struct {
	ID             string `json:"id"` // os-release ID: debian, ubuntu, rocky, almalinux, alpine, fedora
	VersionID      string `json:"version_id"`
	Codename       string `json:"codename,omitempty"`
	PrettyName     string `json:"pretty_name"`
	Kernel         string `json:"kernel"`
	Arch           string `json:"arch"`
	Virtualization string `json:"virtualization"`
}

// Package is one installed package. SourceName is the source package (dpkg) or SRPM name
// (rpm); vulnerability data is usually keyed by source package.
type Package struct {
	Name       string `json:"name"`
	Version    string `json:"version"` // full native version, e.g. 1:2.3-4 or 2.3-4.el9 (with epoch if any)
	Arch       string `json:"arch,omitempty"`
	SourceName string `json:"source,omitempty"`
	SourceVer  string `json:"source_version,omitempty"`
}

// Update is an available package upgrade.
type Update struct {
	Name       string `json:"name"`
	CurrentVer string `json:"current"`
	NewVer     string `json:"new"`
	Security   bool   `json:"security"`
	Origin     string `json:"origin,omitempty"`
}

// ListeningPort is a socket in LISTEN state.
type ListeningPort struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}
