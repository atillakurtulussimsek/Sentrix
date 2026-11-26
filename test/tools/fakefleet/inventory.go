package main

import (
	"context"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// Deliberately outdated package sets so the demo shows real CVEs from live feeds.
var demoPackages = map[string][]protocol.Package{
	"debian": {
		{Name: "libssl3", Version: "3.0.11-1~deb12u2", Arch: "amd64", SourceName: "openssl", SourceVer: "3.0.11-1~deb12u2"},
		{Name: "openssl", Version: "3.0.11-1~deb12u2", Arch: "amd64", SourceName: "openssl", SourceVer: "3.0.11-1~deb12u2"},
		{Name: "openssh-server", Version: "1:9.2p1-2+deb12u1", Arch: "amd64", SourceName: "openssh", SourceVer: "1:9.2p1-2+deb12u1"},
		{Name: "libc6", Version: "2.36-9+deb12u3", Arch: "amd64", SourceName: "glibc", SourceVer: "2.36-9+deb12u3"},
		{Name: "curl", Version: "7.88.1-10+deb12u4", Arch: "amd64", SourceName: "curl", SourceVer: "7.88.1-10+deb12u4"},
		{Name: "nginx", Version: "1.22.1-9", Arch: "amd64", SourceName: "nginx", SourceVer: "1.22.1-9"},
		{Name: "sudo", Version: "1.9.13p3-1+deb12u1", Arch: "amd64", SourceName: "sudo", SourceVer: "1.9.13p3-1+deb12u1"},
		{Name: "bash", Version: "5.2.15-2+b2", Arch: "amd64", SourceName: "bash", SourceVer: "5.2.15-2"},
	},
	"ubuntu": {
		{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13", Arch: "amd64", SourceName: "openssh", SourceVer: "1:9.6p1-3ubuntu13"},
		{Name: "libssl3t64", Version: "3.0.13-0ubuntu3", Arch: "amd64", SourceName: "openssl", SourceVer: "3.0.13-0ubuntu3"},
		{Name: "libc6", Version: "2.39-0ubuntu8", Arch: "amd64", SourceName: "glibc", SourceVer: "2.39-0ubuntu8"},
		{Name: "docker.io", Version: "24.0.7-0ubuntu4", Arch: "amd64", SourceName: "docker.io", SourceVer: "24.0.7-0ubuntu4"},
		{Name: "git", Version: "1:2.43.0-1ubuntu7", Arch: "amd64", SourceName: "git", SourceVer: "1:2.43.0-1ubuntu7"},
	},
	"rocky": {
		{Name: "openssh-server", Version: "8.7p1-38.el9", Arch: "x86_64", SourceName: "openssh", SourceVer: "8.7p1-38.el9"},
		{Name: "openssl-libs", Version: "1:3.0.7-24.el9", Arch: "x86_64", SourceName: "openssl", SourceVer: "1:3.0.7-24.el9"},
		{Name: "postgresql-server", Version: "13.11-1.el9", Arch: "x86_64", SourceName: "postgresql", SourceVer: "13.11-1.el9"},
		{Name: "glibc", Version: "2.34-83.el9_3.7", Arch: "x86_64", SourceName: "glibc", SourceVer: "2.34-83.el9_3.7"},
		{Name: "kernel-core", Version: "5.14.0-362.8.1.el9_3", Arch: "x86_64", SourceName: "kernel", SourceVer: "5.14.0-362.8.1.el9_3"},
	},
	"almalinux": {
		{Name: "postfix", Version: "2:3.5.8-7.el8", Arch: "x86_64", SourceName: "postfix", SourceVer: "2:3.5.8-7.el8"},
		{Name: "openssl-libs", Version: "1:1.1.1k-9.el8_7", Arch: "x86_64", SourceName: "openssl", SourceVer: "1:1.1.1k-9.el8_7"},
		{Name: "dovecot", Version: "1:2.3.16-3.el8", Arch: "x86_64", SourceName: "dovecot", SourceVer: "1:2.3.16-3.el8"},
		{Name: "sudo", Version: "1.8.29-10.el8", Arch: "x86_64", SourceName: "sudo", SourceVer: "1.8.29-10.el8"},
	},
	"alpine": {
		{Name: "libcrypto3", Version: "3.1.4-r5", Arch: "aarch64", SourceName: "openssl", SourceVer: "3.1.4-r5"},
		{Name: "libssl3", Version: "3.1.4-r5", Arch: "aarch64", SourceName: "openssl", SourceVer: "3.1.4-r5"},
		{Name: "haproxy", Version: "2.8.5-r0", Arch: "aarch64", SourceName: "haproxy", SourceVer: "2.8.5-r0"},
		{Name: "busybox", Version: "1.36.1-r15", Arch: "aarch64", SourceName: "busybox", SourceVer: "1.36.1-r15"},
		{Name: "musl", Version: "1.2.4_git20230717-r4", Arch: "aarch64", SourceName: "musl", SourceVer: "1.2.4_git20230717-r4"},
	},
}

var demoUpdates = map[string][]protocol.Update{
	"debian": {
		{Name: "libssl3", CurrentVer: "3.0.11-1~deb12u2", NewVer: "3.0.15-1~deb12u1", Security: true, Origin: "Debian-Security:12/stable-security"},
		{Name: "openssl", CurrentVer: "3.0.11-1~deb12u2", NewVer: "3.0.15-1~deb12u1", Security: true, Origin: "Debian-Security:12/stable-security"},
		{Name: "openssh-server", CurrentVer: "1:9.2p1-2+deb12u1", NewVer: "1:9.2p1-2+deb12u3", Security: true, Origin: "Debian-Security:12/stable-security"},
		{Name: "libc6", CurrentVer: "2.36-9+deb12u3", NewVer: "2.36-9+deb12u9", Security: true, Origin: "Debian-Security:12/stable-security"},
		{Name: "tzdata", CurrentVer: "2024a-0+deb12u1", NewVer: "2024b-0+deb12u1", Origin: "Debian:12.8/stable-updates"},
	},
	"ubuntu": {
		{Name: "openssh-server", CurrentVer: "1:9.6p1-3ubuntu13", NewVer: "1:9.6p1-3ubuntu13.5", Security: true, Origin: "Ubuntu:24.04/noble-security"},
		{Name: "libc6", CurrentVer: "2.39-0ubuntu8", NewVer: "2.39-0ubuntu8.3", Security: true, Origin: "Ubuntu:24.04/noble-security"},
	},
	"rocky": {
		{Name: "openssh-server", CurrentVer: "8.7p1-38.el9", NewVer: "8.7p1-43.el9", Security: true, Origin: "baseos"},
		{Name: "openssl-libs", CurrentVer: "1:3.0.7-24.el9", NewVer: "1:3.2.2-6.el9_5", Security: true, Origin: "baseos"},
	},
	"almalinux": {{Name: "sudo", CurrentVer: "1.8.29-10.el8", NewVer: "1.9.5p2-1.el8_9", Security: true, Origin: "baseos"}},
	"alpine":    {{Name: "libcrypto3", CurrentVer: "3.1.4-r5", NewVer: "3.1.7-r1", Origin: "main"}},
}

func init() {
	extraInit = func(ctx context.Context, hosts []fakeHost) func(context.Context, *fakeHost, int) {
		return func(ctx context.Context, h *fakeHost, i int) {
			if i%360 != 0 { // every hour
				return
			}
			inv := protocol.Inventory{CollectedAt: time.Now(), OS: h.os, Packages: demoPackages[h.os.ID], Updates: demoUpdates[h.os.ID],
				Ports: []protocol.ListeningPort{{Proto: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd"}}}
			switch h.os.ID {
			case "debian", "ubuntu":
				inv.PackageManager = "dpkg"
			case "alpine":
				inv.PackageManager = "apk"
				inv.Ports = append(inv.Ports, protocol.ListeningPort{Proto: "tcp", Address: "0.0.0.0", Port: 443, Process: "haproxy"})
			default:
				inv.PackageManager = "rpm"
			}
			if h.name == "web-01" || h.name == "web-02" {
				inv.Ports = append(inv.Ports, protocol.ListeningPort{Proto: "tcp", Address: "0.0.0.0", Port: 443, Process: "nginx"})
			}
			_ = h.a.Post(ctx, protocol.PathInventory, inv, nil)
		}
	}
}
