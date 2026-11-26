// Command sentrix is the Sentrix command-line client (REST API with a scoped API token).
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/version"
)

const usage = `Usage: sentrix <command> [flags]

  login --server URL --token TOKEN        save server URL and API token
  hosts                                   list hosts
  cve list [--severity S] [--kev] [--fixable] [--q TEXT]
                                          fleet vulnerabilities (S = minimum: low|medium|high|critical)
  patch list                              list patch plans
  patch plan (--hosts a,b | --group G) [--scope security|packages|all] [--packages p1,p2]
             [--reboot never|if_required|always] [--canary N] [--parallel N] [--no-wait]
                                          create a plan and show its dry run
  patch apply PLAN_ID --approve [--no-wait]
                                          approve a plan and follow it until finished
  patch status PLAN_ID                    show a plan
  patch cancel PLAN_ID                    cancel a plan
  version

Environment: SENTRIX_URL and SENTRIX_TOKEN override the saved login.
`

type cliConfig struct {
	Server string `json:"server"`
	Token  string `json:"token"`
}

func configPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "sentrix", "cli.json")
}

func loadConfig() cliConfig {
	var c cliConfig
	if b, err := os.ReadFile(configPath()); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if v := os.Getenv("SENTRIX_URL"); v != "" {
		c.Server = v
	}
	if v := os.Getenv("SENTRIX_TOKEN"); v != "" {
		c.Token = v
	}
	return c
}

type client struct {
	cfg  cliConfig
	http *http.Client
}

func (c *client) do(method, path string, body, out any) error {
	if c.cfg.Server == "" || c.cfg.Token == "" {
		return errors.New("not logged in: run 'sentrix login --server URL --token TOKEN' or set SENTRIX_URL/SENTRIX_TOKEN")
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	// The server URL is the user's own configuration, not untrusted input.
	req, err := http.NewRequest(method, strings.TrimRight(c.cfg.Server, "/")+path, rd) //nolint:gosec // see above
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req) //nolint:gosec // user-configured server URL
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s (HTTP %d)", e.Error, resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	c := &client{cfg: loadConfig(), http: &http.Client{Timeout: 60 * time.Second}}
	switch args[0] {
	case "version":
		fmt.Println("sentrix", version.String())
		return nil
	case "login":
		fs := flag.NewFlagSet("login", flag.ExitOnError)
		srv := fs.String("server", "", "server URL, e.g. https://sentrix.example.com")
		tok := fs.String("token", "", "API token (Settings → API tokens)")
		_ = fs.Parse(args[1:])
		c.cfg = cliConfig{Server: *srv, Token: *tok}
		var me map[string]string
		if err := c.do("GET", "/api/v1/me", nil, &me); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(configPath()), 0o700); err != nil {
			return err
		}
		b, _ := json.MarshalIndent(c.cfg, "", "  ")
		if err := os.WriteFile(configPath(), b, 0o600); err != nil {
			return err
		}
		fmt.Printf("logged in as %s (%s); saved to %s\n", me["username"], me["role"], configPath())
		return nil
	case "hosts":
		var hosts []map[string]any
		if err := c.do("GET", "/api/v1/hosts", nil, &hosts); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "HOSTNAME\tSTATUS\tOS\tGROUP\tUPDATES\tSECURITY\tRISK\tID")
		for _, h := range hosts {
			fmt.Fprintf(tw, "%v\t%v\t%v\t%v\t%v\t%v\t%.0f\t%v\n", h["hostname"], h["status"], h["os"], h["group"], h["updates"], h["security_updates"], h["risk"], h["id"])
		}
		return tw.Flush()
	case "cve":
		if len(args) < 2 || args[1] != "list" {
			return errors.New("usage: sentrix cve list [--severity high]")
		}
		fs := flag.NewFlagSet("cve list", flag.ExitOnError)
		sev := fs.String("severity", "", "minimum severity")
		kev := fs.Bool("kev", false, "only known exploited")
		fixable := fs.Bool("fixable", false, "only with a fix available")
		q := fs.String("q", "", "filter by CVE or package")
		_ = fs.Parse(args[2:])
		v := url.Values{}
		if *sev != "" {
			v.Set("min_severity", *sev)
		}
		if *kev {
			v.Set("kev", "1")
		}
		if *fixable {
			v.Set("fixable", "1")
		}
		if *q != "" {
			v.Set("q", *q)
		}
		var rows []map[string]any
		if err := c.do("GET", "/api/v1/vulns?"+v.Encode(), nil, &rows); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "RISK\tCVE\tSEVERITY\tCVSS\tEPSS\tKEV\tHOSTS\tFIX\tPACKAGES")
		for _, r := range rows {
			kevs := ""
			if r["kev"] == true {
				kevs = "KEV"
			}
			fix := "no"
			if r["fixable"] == true {
				fix = "yes"
			}
			fmt.Fprintf(tw, "%.0f\t%v\t%v\t%.1f\t%.3f\t%s\t%v\t%s\t%v\n", r["risk"], r["id"], r["severity"], r["cvss"], r["epss"], kevs, r["hosts"], fix, r["packages"])
		}
		fmt.Fprintf(tw, "\n%d vulnerabilities\n", len(rows))
		return tw.Flush()
	case "patch":
		if len(args) < 2 {
			return errors.New("usage: sentrix patch plan|apply|status|list|cancel")
		}
		return patchCmd(c, args[1], args[2:])
	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type planHost struct {
	HostID         string   `json:"host_id"`
	Hostname       string   `json:"hostname"`
	Status         string   `json:"status"`
	DryRunChanges  []change `json:"dry_run_changes"`
	Changes        []change `json:"changes"`
	Error          string   `json:"error"`
	FindingsBefore int      `json:"findings_before"`
	FindingsAfter  int      `json:"findings_after"`
	RebootRequired bool     `json:"reboot_required"`
}

type change struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
}

type plan struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scope      string     `json:"scope"`
	Status     string     `json:"status"`
	Error      string     `json:"error"`
	CreatedBy  string     `json:"created_by"`
	ApprovedBy string     `json:"approved_by"`
	CreatedAt  time.Time  `json:"created_at"`
	Hosts      []planHost `json:"hosts"`
}

func printPlan(p plan) {
	fmt.Printf("Plan %s — %s\nstatus: %s  scope: %s  created by: %s", p.ID, p.Name, p.Status, p.Scope, p.CreatedBy)
	if p.ApprovedBy != "" {
		fmt.Printf("  approved by: %s", p.ApprovedBy)
	}
	fmt.Println()
	if p.Error != "" {
		fmt.Println("error:", p.Error)
	}
	for _, h := range p.Hosts {
		fmt.Printf("\n%s  [%s]", h.Hostname, h.Status)
		if h.FindingsBefore >= 0 && h.FindingsAfter >= 0 {
			fmt.Printf("  CVEs %d → %d", h.FindingsBefore, h.FindingsAfter)
		}
		if h.RebootRequired {
			fmt.Print("  (reboot required)")
		}
		fmt.Println()
		if h.Error != "" {
			fmt.Println("  error:", h.Error)
		}
		chs := h.Changes
		if len(chs) == 0 {
			chs = h.DryRunChanges
		}
		for _, ch := range chs {
			from := ch.From
			if from == "" {
				from = "(new)"
			}
			fmt.Printf("  %-40s %s → %s\n", ch.Name, from, ch.To)
		}
	}
}

func waitPlan(c *client, id string, until func(string) bool) (plan, error) {
	var p plan
	for i := 0; i < 1200; i++ {
		if err := c.do("GET", "/api/v1/plans/"+id, nil, &p); err != nil {
			return p, err
		}
		if until(p.Status) {
			return p, nil
		}
		time.Sleep(3 * time.Second)
	}
	return p, errors.New("timed out waiting for plan")
}

func patchCmd(c *client, sub string, args []string) error {
	switch sub {
	case "list":
		var ps []plan
		if err := c.do("GET", "/api/v1/plans", nil, &ps); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSTATUS\tSCOPE\tCREATED\tNAME")
		for _, p := range ps {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.ID, p.Status, p.Scope, p.CreatedAt.Local().Format("2006-01-02 15:04"), p.Name)
		}
		return tw.Flush()
	case "plan":
		fs := flag.NewFlagSet("patch plan", flag.ExitOnError)
		hosts := fs.String("hosts", "", "comma-separated host names or IDs")
		group := fs.String("group", "", "host group")
		scope := fs.String("scope", "security", "security|packages|all")
		pkgs := fs.String("packages", "", "comma-separated packages (scope=packages)")
		reboot := fs.String("reboot", "never", "never|if_required|always")
		canary := fs.Int("canary", 1, "canary hosts patched first")
		parallel := fs.Int("parallel", 1, "max hosts in parallel")
		name := fs.String("name", "", "plan name")
		noWait := fs.Bool("no-wait", false, "do not wait for the dry run")
		_ = fs.Parse(args)
		req := map[string]any{"name": *name, "group": *group, "scope": *scope, "reboot": *reboot, "canary": *canary, "max_parallel": *parallel,
			"hosts": splitCSV(*hosts), "packages": splitCSV(*pkgs)}
		var p plan
		if err := c.do("POST", "/api/v1/plans", req, &p); err != nil {
			return err
		}
		if *noWait {
			fmt.Println(p.ID)
			return nil
		}
		fmt.Fprintf(os.Stderr, "plan %s created; waiting for dry run…\n", p.ID)
		p, err := waitPlan(c, p.ID, func(s string) bool { return s != "dry_run" })
		if err != nil {
			return err
		}
		printPlan(p)
		if p.Status == "ready" {
			fmt.Printf("\nApply with: sentrix patch apply %s --approve\n", p.ID)
		}
		return nil
	case "apply":
		if len(args) == 0 {
			return errors.New("usage: sentrix patch apply PLAN_ID --approve")
		}
		id := args[0]
		fs := flag.NewFlagSet("patch apply", flag.ExitOnError)
		approve := fs.Bool("approve", false, "confirm that you reviewed the dry run")
		noWait := fs.Bool("no-wait", false, "return immediately")
		_ = fs.Parse(args[1:])
		if !*approve {
			return errors.New("refusing to apply without --approve (review the dry run with 'sentrix patch status " + id + "')")
		}
		var p plan
		if err := c.do("POST", "/api/v1/plans/"+id+"/approve", nil, &p); err != nil {
			return err
		}
		if *noWait {
			fmt.Println(p.Status)
			return nil
		}
		fmt.Fprintln(os.Stderr, "approved; following progress…")
		p, err := waitPlan(c, id, func(s string) bool { return s == "done" || s == "failed" || s == "cancelled" })
		if err != nil {
			return err
		}
		printPlan(p)
		if p.Status != "done" {
			return fmt.Errorf("plan %s", p.Status)
		}
		return nil
	case "status":
		if len(args) == 0 {
			return errors.New("usage: sentrix patch status PLAN_ID")
		}
		var p plan
		if err := c.do("GET", "/api/v1/plans/"+args[0], nil, &p); err != nil {
			return err
		}
		printPlan(p)
		return nil
	case "cancel":
		if len(args) == 0 {
			return errors.New("usage: sentrix patch cancel PLAN_ID")
		}
		var p plan
		if err := c.do("POST", "/api/v1/plans/"+args[0]+"/cancel", nil, &p); err != nil {
			return err
		}
		fmt.Println(p.Status)
		return nil
	}
	return fmt.Errorf("unknown patch command %q", sub)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
