// Package notify delivers Sentrix notifications (email, Telegram, Discord, Slack, ntfy,
// generic webhook) and evaluates alert rules.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Message is a rendered notification.
type Message struct {
	Event    string    `json:"event"` // firing | resolved | digest | test | patch | vulnerability
	Severity string    `json:"severity"`
	Title    string    `json:"title"`
	Body     string    `json:"body"`
	Host     string    `json:"host,omitempty"`
	HostID   string    `json:"host_id,omitempty"`
	AlertID  string    `json:"alert_id,omitempty"`
	Rule     string    `json:"rule,omitempty"`
	Value    float64   `json:"value,omitempty"`
	URL      string    `json:"url,omitempty"`
	Time     time.Time `json:"time"`
}

// Config is a channel configuration. Field use depends on Kind; secret fields are
// sealed at rest by the server and opened before sending.
type Config struct {
	URL      string `json:"url,omitempty"`      // webhook, slack, discord, ntfy server
	Secret   string `json:"secret,omitempty"`   // webhook HMAC secret (sealed)
	Token    string `json:"token,omitempty"`    // telegram bot token / ntfy access token (sealed)
	ChatID   string `json:"chat_id,omitempty"`  // telegram
	Topic    string `json:"topic,omitempty"`    // ntfy
	Host     string `json:"host,omitempty"`     // smtp
	Port     int    `json:"port,omitempty"`     // smtp
	Username string `json:"username,omitempty"` // smtp
	Password string `json:"password,omitempty"` // smtp (sealed)
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`       // comma separated
	TLSMode  string `json:"tls_mode,omitempty"` // smtp: starttls (default) | tls | none
}

// SecretFields lists Config fields that must be sealed at rest.
var SecretFields = []string{"secret", "token", "password"}

// Sender delivers messages for one channel kind.
type Sender struct {
	HTTP *http.Client
	// TelegramAPI overrides https://api.telegram.org (tests).
	TelegramAPI string
	// Dial overrides SMTP dialing (tests).
	SMTPDial func(addr string) (net.Conn, error)
}

// NewSender returns a sender with sane timeouts.
func NewSender() *Sender {
	return &Sender{HTTP: &http.Client{Timeout: 20 * time.Second}, TelegramAPI: "https://api.telegram.org"}
}

func plain(m Message) string {
	s := m.Title
	if m.Body != "" {
		s += "\n" + m.Body
	}
	if m.URL != "" {
		s += "\n" + m.URL
	}
	return s
}

func emoji(m Message) string {
	switch {
	case m.Event == "resolved":
		return "✅"
	case m.Severity == "critical":
		return "🔴"
	case m.Severity == "warning":
		return "🟠"
	}
	return "ℹ️"
}

// Send delivers m via a channel of the given kind.
func (s *Sender) Send(ctx context.Context, kind string, c Config, m Message) error {
	switch kind {
	case "webhook":
		body, _ := json.Marshal(m)
		hdr := map[string]string{"Content-Type": "application/json"}
		if c.Secret != "" {
			mac := hmac.New(sha256.New, []byte(c.Secret))
			mac.Write(body)
			hdr["X-Sentrix-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
		}
		return s.post(ctx, c.URL, body, hdr)
	case "slack":
		body, _ := json.Marshal(map[string]string{"text": emoji(m) + " *" + m.Title + "*\n" + m.Body + linkSuffix(m.URL)})
		return s.post(ctx, c.URL, body, map[string]string{"Content-Type": "application/json"})
	case "discord":
		text := emoji(m) + " **" + m.Title + "**\n" + m.Body + linkSuffix(m.URL)
		if len(text) > 1900 {
			text = text[:1900] + "…"
		}
		body, _ := json.Marshal(map[string]string{"content": text})
		return s.post(ctx, c.URL, body, map[string]string{"Content-Type": "application/json"})
	case "telegram":
		if c.Token == "" || c.ChatID == "" {
			return errors.New("telegram: token and chat_id required")
		}
		text := emoji(m) + " " + m.Title + "\n" + m.Body + linkSuffix(m.URL)
		if len(text) > 4000 {
			text = text[:4000] + "…"
		}
		body, _ := json.Marshal(map[string]any{"chat_id": c.ChatID, "text": text, "disable_web_page_preview": true})
		return s.post(ctx, strings.TrimRight(s.TelegramAPI, "/")+"/bot"+c.Token+"/sendMessage", body, map[string]string{"Content-Type": "application/json"})
	case "ntfy":
		base := c.URL
		if base == "" {
			base = "https://ntfy.sh"
		}
		if c.Topic == "" {
			return errors.New("ntfy: topic required")
		}
		hdr := map[string]string{"Title": asciiHeader(m.Title), "Tags": map[bool]string{true: "white_check_mark", false: "warning"}[m.Event == "resolved"]}
		switch m.Severity {
		case "critical":
			hdr["Priority"] = "5"
		case "warning":
			hdr["Priority"] = "4"
		}
		if m.URL != "" {
			hdr["Click"] = m.URL
		}
		if c.Token != "" {
			hdr["Authorization"] = "Bearer " + c.Token
		}
		return s.post(ctx, strings.TrimRight(base, "/")+"/"+url.PathEscape(c.Topic), []byte(m.Body), hdr)
	case "email":
		return s.sendMail(c, m)
	}
	return fmt.Errorf("unknown channel kind %q", kind)
}

func linkSuffix(u string) string {
	if u == "" {
		return ""
	}
	return "\n" + u
}

// asciiHeader keeps header values ASCII (ntfy titles).
func asciiHeader(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (s *Sender) post(ctx context.Context, target string, body []byte, hdr map[string]string) error {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("invalid URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "Sentrix-Notifier")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return redactURL(err, target)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// redactURL removes the URL (which can contain tokens, e.g. Telegram) from errors.
func redactURL(err error, target string) error {
	msg := strings.ReplaceAll(err.Error(), target, "<redacted url>")
	if u, perr := url.Parse(target); perr == nil {
		msg = strings.ReplaceAll(msg, u.Path, "/<redacted>")
	}
	return errors.New(msg)
}

func (s *Sender) sendMail(c Config, m Message) error {
	if c.Host == "" || c.From == "" || c.To == "" {
		return errors.New("email: host, from and to are required")
	}
	port := c.Port
	if port == 0 {
		port = 587
		if c.TLSMode == "tls" {
			port = 465
		}
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(port))
	var to []string
	for _, t := range strings.Split(c.To, ",") {
		if t = strings.TrimSpace(t); t != "" {
			to = append(to, t)
		}
	}
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: [Sentrix] %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		c.From, strings.Join(to, ", "), mimeHeader(m.Title), time.Now().Format(time.RFC1123Z), strings.ReplaceAll(plain(m), "\n", "\r\n"))
	dial := s.SMTPDial
	if dial == nil {
		dial = func(a string) (net.Conn, error) { return net.DialTimeout("tcp", a, 15*time.Second) }
	}
	conn, err := dial(addr)
	if err != nil {
		return err
	}
	if c.TLSMode == "tls" {
		conn = tls.Client(conn, &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12})
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if c.TLSMode == "" || c.TLSMode == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); ok {
			if err := cl.StartTLS(&tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		} else if c.Username != "" {
			return errors.New("server does not offer STARTTLS; refusing to send credentials in clear text (set tls_mode)")
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := cl.Mail(c.From); err != nil {
		return err
	}
	for _, t := range to {
		if err := cl.Rcpt(t); err != nil {
			return err
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg.Bytes()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

func mimeHeader(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?utf-8?B?" + b64(s) + "?="
		}
	}
	return s
}
