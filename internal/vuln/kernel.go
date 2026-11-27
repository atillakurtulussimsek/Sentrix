package vuln

import (
	"regexp"
	"strings"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/vuln/version"
)

// dpkgKernelPkg matches Debian/Ubuntu binary packages built for one kernel release,
// e.g. linux-image-6.8.0-142-generic or linux-headers-6.8.0-142; group 1 is the release.
var dpkgKernelPkg = regexp.MustCompile(`^linux-(?:image(?:-unsigned)?|modules(?:-extra)?|headers|tools|cloud-tools|buildinfo|objects|signatures-nvidia)-(\d+\.\d+\S*)$`)

// splitKernels separates packages that belong to kernels which are installed but not
// running (inactive) from the rest. Only the running kernel can be exploited, so
// inactive kernels are not matched; they are still used to tell whether a fix is
// installed and only waits for a reboot.
//
// Filtering is applied only when the running release is known and at least one
// installed kernel package belongs to it (containers report the host's kernel and
// usually have no kernel packages); otherwise all packages are returned unchanged.
// Alpine installs a single kernel per flavour, so APK is never filtered.
func splitKernels(scheme version.Scheme, pkgs []protocol.Package, running string) (active, inactive []protocol.Package) {
	running = strings.TrimSpace(running)
	if running == "" || scheme == version.APK {
		return pkgs, nil
	}
	isKernel := func(p protocol.Package) (match, ok bool) {
		switch scheme {
		case version.Dpkg:
			m := dpkgKernelPkg.FindStringSubmatch(p.Name)
			if m == nil {
				return false, false
			}
			// Flavourless packages (linux-headers-6.8.0-142) serve every flavour of that release.
			return m[1] == running || strings.HasPrefix(running, m[1]+"-"), true
		case version.RPM:
			if p.Name != "kernel" && !strings.HasPrefix(p.Name, "kernel-") {
				return false, false
			}
			v := p.Version
			if _, rest, found := strings.Cut(v, ":"); found {
				v = rest
			}
			return running == v || running == v+"."+p.Arch || strings.HasPrefix(running, v+"."), true
		}
		return false, false
	}
	// For RPM only names that have an installed build of the running kernel are
	// filtered (kernel-headers, kernel-tools … follow the newest kernel, not the
	// running one, and are kept as they are).
	runningNames := map[string]bool{}
	anyRunning := false
	for _, p := range pkgs {
		if m, ok := isKernel(p); ok && m {
			runningNames[p.Name] = true
			anyRunning = true
		}
	}
	if !anyRunning {
		return pkgs, nil
	}
	for _, p := range pkgs {
		m, ok := isKernel(p)
		switch {
		case !ok || m:
			active = append(active, p)
		case scheme == version.RPM && !runningNames[p.Name]:
			active = append(active, p)
		default:
			inactive = append(inactive, p)
		}
	}
	return active, inactive
}

// newestByKey returns, per matching key, the highest version among pkgs.
func newestByKey(scheme version.Scheme, pkgs []protocol.Package) map[string]string {
	out := map[string]string{}
	for _, p := range pkgs {
		key, ver := p.Name, p.Version
		if scheme == version.Dpkg {
			if p.SourceName != "" {
				key = p.SourceName
			}
			if p.SourceVer != "" {
				ver = p.SourceVer
			}
		}
		if cur, ok := out[key]; !ok {
			out[key] = ver
		} else if c, err := version.Compare(scheme, ver, cur); err == nil && c > 0 {
			out[key] = ver
		}
	}
	return out
}
