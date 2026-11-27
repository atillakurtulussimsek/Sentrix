package protocol

import "strings"

// protectedNames are packages remove_packages never removes, directly or as a
// dependency: the agent itself, package managers, the C library, init, remote
// access and core userland. Removing any of them can leave a host unbootable or
// unreachable, which a remote tool must not be able to do.
var protectedNames = map[string]bool{
	"sentrix-agent": true,
	// package management
	"apt": true, "dpkg": true, "debconf": true, "rpm": true, "dnf": true, "yum": true,
	"microdnf": true, "apk-tools": true, "alpine-baselayout": true, "alpine-keys": true,
	// C library / loader
	"libc6": true, "libc-bin": true, "glibc": true, "glibc-common": true, "musl": true, "musl-utils": true,
	// init and boot
	"systemd": true, "systemd-sysv": true, "init": true, "openrc": true, "udev": true,
	"grub-common": true, "grub2-common": true, "grub-efi-amd64-signed": true, "grub-pc": true,
	"shim-signed": true, "initramfs-tools": true, "dracut": true, "mkinitfs": true,
	"busybox-initramfs": true,
	// remote access and authentication
	"openssh-server": true, "openssh": true, "sudo": true, "login": true, "passwd": true,
	"libpam-modules": true, "pam": true, "shadow": true, "shadow-utils": true,
	// core userland
	"bash": true, "dash": true, "coreutils": true, "util-linux": true, "base-files": true,
	"base-passwd": true, "filesystem": true, "setup": true, "tar": true, "gzip": true,
	"sed": true, "grep": true, "findutils": true, "procps": true, "mount": true,
	"ca-certificates": true,
}

// protectedPrefixes cover kernels and boot loaders across distributions.
var protectedPrefixes = []string{
	"linux-image", "linux-modules", "linux-generic", "linux-virtual", "linux-lts", "linux-virt",
	"linux-signed", "linux-firmware", "kernel", "grub", "shim",
}

// ProtectedPackage reports whether remove_packages must refuse to remove name.
func ProtectedPackage(name string) bool {
	if protectedNames[name] {
		return true
	}
	for _, p := range protectedPrefixes {
		if name == p || strings.HasPrefix(name, p+"-") {
			return true
		}
	}
	return false
}
