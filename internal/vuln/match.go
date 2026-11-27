package vuln

import (
	"sort"
	"strings"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/vuln/version"
)

// Finding is a vulnerability affecting an installed package on a host.
type Finding struct {
	VulnID    string
	Package   string // matching key: source package (dpkg/apk) or RPM name
	Installed string
	Fixed     string // empty = no fix available yet
	Advisory  string
	Binaries  []string
	Exposed   string // evidence that the package's service listens on a network interface
	DistroSev string
	// RebootRequired is set when the finding is on the running kernel and a newer,
	// installed but not yet booted kernel already contains the fix.
	RebootRequired bool
}

// FixAvailable reports whether the distribution has released a fix.
func (f Finding) FixAvailable() bool { return f.Fixed != "" }

// installedPkg is a package grouped by its vulnerability matching key.
type installedPkg struct {
	key      string
	version  string
	binaries []string
}

// groupPackages groups installed packages by the name used in distro advisories:
// source package for dpkg and apk, binary RPM name for rpm. For dpkg the lowest source
// version among binaries is used (conservative); for rpm "installonly" packages
// (kernels) the highest installed version is used.
func groupPackages(scheme version.Scheme, pkgs []protocol.Package) map[string]*installedPkg {
	out := map[string]*installedPkg{}
	for _, p := range pkgs {
		key, ver := p.Name, p.Version
		switch scheme {
		case version.Dpkg, version.APK:
			if p.SourceName != "" {
				key = p.SourceName
			}
			if p.SourceVer != "" {
				ver = p.SourceVer
			}
		}
		g, ok := out[key]
		if !ok {
			out[key] = &installedPkg{key: key, version: ver, binaries: []string{p.Name}}
			continue
		}
		g.binaries = append(g.binaries, p.Name)
		c, _ := version.Compare(scheme, ver, g.version)
		if (scheme == version.RPM && c > 0) || (scheme != version.RPM && c < 0) {
			g.version = ver
		}
	}
	return out
}

// AffectedIndex holds advisories of one ecosystem keyed by package.
type AffectedIndex map[string][]Affected

// Match returns findings for the given installed packages. A package is affected when
// introduced <= installed (if introduced is set) and either no fix exists or
// installed < fixed, compared with the distro's own version scheme. A finding is never
// dropped unless the installed version is verified to be >= the distro fixed version.
//
// runningKernel is the host's kernel release (uname -r). Packages of other installed
// kernels are not matched, because only the running kernel is exposed; see splitKernels.
func Match(scheme version.Scheme, pkgs []protocol.Package, idx AffectedIndex, ports []protocol.ListeningPort, runningKernel string) []Finding {
	active, inactive := splitKernels(scheme, pkgs, runningKernel)
	pending := newestByKey(scheme, inactive)
	groups := groupPackages(scheme, active)
	type acc struct {
		f        Finding
		hasFix   bool
		unfixed  bool
		advisory []string
	}
	results := map[[2]string]*acc{}
	for key, g := range groups {
		for _, a := range idx[key] {
			if a.Introduced != "" {
				if c, err := version.Compare(scheme, g.version, a.Introduced); err != nil || c < 0 {
					continue
				}
			}
			affected := false
			if a.Fixed == "" {
				affected = true
			} else if c, err := version.Compare(scheme, g.version, a.Fixed); err == nil && c < 0 {
				affected = true
			}
			if !affected {
				continue
			}
			k := [2]string{a.VulnID, key}
			r, ok := results[k]
			if !ok {
				r = &acc{f: Finding{VulnID: a.VulnID, Package: key, Installed: g.version, Binaries: g.binaries, DistroSev: a.DistroSeverity}}
				results[k] = r
			}
			if a.Advisory != "" && !contains(r.advisory, a.Advisory) {
				r.advisory = append(r.advisory, a.Advisory)
			}
			if a.Fixed == "" {
				r.unfixed = true
				continue
			}
			if !r.hasFix {
				r.f.Fixed, r.hasFix = a.Fixed, true
			} else if c, _ := version.Compare(scheme, a.Fixed, r.f.Fixed); c > 0 {
				r.f.Fixed = a.Fixed // need the highest fixed version among affecting advisories
			}
		}
	}
	exposure := exposureIndex(ports)
	out := make([]Finding, 0, len(results))
	for _, r := range results {
		sort.Strings(r.advisory)
		r.f.Advisory = strings.Join(r.advisory, " ")
		r.f.Exposed = exposedEvidence(r.f, exposure)
		if v, ok := pending[r.f.Package]; ok && r.f.Fixed != "" && !r.unfixed {
			if c, err := version.Compare(scheme, v, r.f.Fixed); err == nil && c >= 0 {
				r.f.RebootRequired = true
			}
		}
		out = append(out, r.f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].VulnID != out[j].VulnID {
			return out[i].VulnID < out[j].VulnID
		}
		return out[i].Package < out[j].Package
	})
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// processPackages maps common daemon process names to package name prefixes.
var processPackages = map[string][]string{
	"sshd":         {"openssh"},
	"postgres":     {"postgresql"},
	"mysqld":       {"mysql", "mariadb"},
	"mariadbd":     {"mariadb"},
	"named":        {"bind"},
	"httpd":        {"httpd", "apache"},
	"apache2":      {"apache2"},
	"master":       {"postfix"},
	"smtpd":        {"postfix"},
	"dockerd":      {"docker", "moby"},
	"containerd":   {"containerd"},
	"smbd":         {"samba"},
	"redis-server": {"redis"},
	"node":         {"nodejs"},
	"java":         {"openjdk", "java"},
	"exim4":        {"exim4"},
	"dovecot":      {"dovecot"},
	"haproxy":      {"haproxy"},
	"nginx":        {"nginx"},
	"memcached":    {"memcached"},
	"vsftpd":       {"vsftpd"},
	"proftpd":      {"proftpd"},
	"squid":        {"squid"},
	"cupsd":        {"cups"},
	"rpcbind":      {"rpcbind"},
	"chronyd":      {"chrony"},
	"ntpd":         {"ntp"},
	"dnsmasq":      {"dnsmasq"},
	"unbound":      {"unbound"},
	"slapd":        {"openldap"},
	"pveproxy":     {"pve-manager"},
}

type exposedSock struct{ proc, addr string }

func exposureIndex(ports []protocol.ListeningPort) []exposedSock {
	var out []exposedSock
	for _, p := range ports {
		if p.Process == "" || strings.HasPrefix(p.Address, "127.") || p.Address == "::1" {
			continue
		}
		out = append(out, exposedSock{proc: p.Process, addr: p.Proto + " " + p.Address + ":" + itoa(p.Port)})
	}
	return out
}

func exposedEvidence(f Finding, socks []exposedSock) string {
	names := append([]string{f.Package}, f.Binaries...)
	for _, s := range socks {
		cands := append([]string{s.proc}, processPackages[s.proc]...)
		for _, c := range cands {
			for _, n := range names {
				if n == c || strings.HasPrefix(n, c+"-") || strings.HasPrefix(n, c) && len(c) >= 4 {
					return s.proc + " listening on " + s.addr
				}
			}
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
