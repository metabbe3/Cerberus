// Command cerberus-ssh is a policy-gated SSH bastion proxy.
//
// Agents SSH into the bastion (default 0.0.0.0:2222). Every "exec" request is
// first checked against the Cerberus engine (POST /v1/decide with
// key_id "ssh-bastion", stage "ssh", action "ssh_exec"). Denied or
// engine-unreachable commands never leave the bastion (fail-closed).
//
// Modes:
//   - relay (-key-file set): allowed commands are executed on the real
//     upstream SSH host via ssh.Dial + session.Run with a production private
//     key loaded from a file path (ENV/MOUNT). Keys are NEVER embedded in
//     code; the path only comes from -key-file / CERBERUS_SSH_UPSTREAM_KEY.
//   - decide-only (-key-file empty): no upstream key configured; the bastion
//     still enforces policy and echoes the decision instead of relaying.
//     Used for testing and for auditing agent activity before upstream
//     access is wired.
//
// Interactive access is disabled: "pty-req" and "shell" requests are rejected
// and the session channel is closed. Only "exec" on "session" channels is
// supported. Identity verification is TODO: NoClientAuth is acceptable only
// because agents run on an isolated network segment.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// config carries every runtime setting for the bastion.
type config struct {
	Listen             string
	EngineURL          string
	EngineToken        string
	UpstreamHost       string // decide input "host" value AND relay dial target
	UpstreamUser       string // decide input "user" value AND relay SSH user
	KeyFile            string // upstream private key PEM; "" = decide-only mode
	HostKeyFile        string // bastion host key; auto-generated if missing
	UpstreamHostKeyB64 string // base64 wire-format pubkey of upstream host
}

// decideResp mirrors the engine /v1/decide response (subset we care about).
type decideResp struct {
	Decision string `json:"decision"`
	RuleID   string `json:"rule_id"`
	Reason   string `json:"reason"`
}

const (
	bastionKeyID   = "ssh-bastion"
	bastionStage   = "ssh"
	bastionAction  = "ssh_exec"
	engineTimeout  = 3 * time.Second
	dialTimeout    = 10 * time.Second
	blockedExit    = 126     // policy denial / engine unreachable
	relayErrExit   = 127     // upstream dial/run failure after an allow
	maxCommandSize = 1 << 20 // 1MB exec command cap
)

// bastion is the SSH policy proxy server.
type bastion struct {
	cfg             config
	hostSigner      ssh.Signer
	upstreamSigner  ssh.Signer    // nil => decide-only mode
	upstreamHostKey ssh.PublicKey // nil => InsecureIgnoreHostKey (TODO below)
	hc              *http.Client
}

// newBastion validates config and loads keys. Host key is generated and
// persisted (0600) if the file does not exist yet.
func newBastion(cfg config) (*bastion, error) {
	if cfg.KeyFile != "" && cfg.UpstreamHost == "" {
		return nil, errors.New("relay mode (-key-file set) requires -upstream-host")
	}
	hostSigner, err := loadOrGenerateHostKey(cfg.HostKeyFile)
	if err != nil {
		return nil, err
	}
	b := &bastion{
		cfg:        cfg,
		hostSigner: hostSigner,
		hc:         &http.Client{Timeout: engineTimeout},
	}
	if cfg.KeyFile != "" {
		keyData, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read upstream key %s: %w", cfg.KeyFile, err)
		}
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse upstream key %s: %w", cfg.KeyFile, err)
		}
		b.upstreamSigner = signer
	}
	if s := strings.TrimSpace(cfg.UpstreamHostKeyB64); s != "" {
		pk, err := parseHostKeyB64(s)
		if err != nil {
			return nil, fmt.Errorf("parse CERBERUS_SSH_UPSTREAM_HOSTKEY: %w", err)
		}
		b.upstreamHostKey = pk
	}
	return b, nil
}

// serverConfig builds the SSH server config. NoClientAuth is deliberate:
// agents live on an isolated network segment. TODO(identity): require
// per-agent public keys once agent key distribution is in place.
func (b *bastion) serverConfig() *ssh.ServerConfig {
	sc := &ssh.ServerConfig{
		NoClientAuth: true, // TODO(identity): per-agent pubkey auth
	}
	sc.AddHostKey(b.hostSigner)
	return sc
}

// serve accepts TCP connections until the listener is closed.
func (b *bastion) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go b.handleConn(c)
	}
}

func (b *bastion) handleConn(c net.Conn) {
	defer func() { _ = c.Close() }()
	sconn, newChs, reqs, err := ssh.NewServerConn(c, b.serverConfig())
	if err != nil {
		log.Printf("[cerberus-ssh] handshake from %s: %v", c.RemoteAddr(), err)
		return
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newCh := range newChs {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.Prohibited, "cerberus_ssh_error: only session channels are allowed")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			log.Printf("[cerberus-ssh] channel accept: %v", err)
			continue
		}
		go b.handleSession(ch, reqs)
	}
}

// handleSession enforces the exec-only policy on one session channel.
func (b *bastion) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "pty-req", "shell":
			_ = req.Reply(false, nil)
			_, _ = fmt.Fprintf(ch.Stderr(), "cerberus_ssh_error: interactive shell disabled\n")
			_ = ch.Close()
			return
		case "exec":
			cmd := parseExecPayload(req.Payload)
			b.handleExec(ch, req, cmd)
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// handleExec is the policy gate for a single command.
func (b *bastion) handleExec(ch ssh.Channel, req *ssh.Request, cmd string) {
	verdict, allowed := b.decide(cmd)
	if !allowed {
		_ = req.Reply(false, nil)
		_, _ = fmt.Fprintf(ch.Stderr(), "cerberus_ssh_blocked: %s\n", verdict.Reason)
		_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(blockedExit))
		_ = ch.Close()
		return
	}

	if b.upstreamSigner == nil { // decide-only mode
		_ = req.Reply(true, nil)
		_, _ = fmt.Fprintf(ch, "cerberus-ssh decide-only: ALLOW %s\n", cmd)
		_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(0))
		_ = ch.Close()
		return
	}

	_ = req.Reply(true, nil)
	status, err := b.relay(ch, cmd)
	if err != nil {
		log.Printf("[cerberus-ssh] relay %q: %v", cmd, err)
		_, _ = fmt.Fprintf(ch.Stderr(), "cerberus_ssh_error: upstream relay failed: %v\n", err)
		status = relayErrExit
	}
	_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(status))
	_ = ch.Close()
}

// decide asks the engine POST /v1/decide. Fail-closed: deny, unreachable,
// non-200, or malformed engine response all block the command.
func (b *bastion) decide(cmd string) (decideResp, bool) {
	if b.cfg.EngineURL == "" {
		return decideResp{Decision: "deny", Reason: "engine-url not configured"}, false
	}
	body, err := json.Marshal(map[string]any{
		"key_id": bastionKeyID,
		"stage":  bastionStage,
		"action": bastionAction,
		"input": map[string]string{
			"host": b.cfg.UpstreamHost,
			"user": b.cfg.UpstreamUser,
			"cmd":  cmd,
		},
	})
	if err != nil {
		return decideResp{Decision: "deny", Reason: "marshal decide request"}, false
	}
	url := strings.TrimSuffix(b.cfg.EngineURL, "/") + "/v1/decide"
	hreq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return decideResp{Decision: "deny", Reason: "bad engine url: " + err.Error()}, false
	}
	hreq.Header.Set("Content-Type", "application/json")
	if b.cfg.EngineToken != "" {
		hreq.Header.Set("Authorization", "Bearer "+b.cfg.EngineToken)
	}
	resp, err := b.hc.Do(hreq)
	if err != nil {
		log.Printf("[cerberus-ssh] engine unreachable (denying): %v", err)
		return decideResp{Decision: "deny", Reason: "engine unreachable"}, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return decideResp{Decision: "deny", Reason: fmt.Sprintf("engine http %d", resp.StatusCode)}, false
	}
	var dr decideResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&dr); err != nil || dr.Decision == "" {
		return decideResp{Decision: "deny", Reason: "bad engine response"}, false
	}
	return dr, dr.Decision == "allow"
}

// relay runs cmd on the upstream host and streams stdout/stderr back.
func (b *bastion) relay(ch ssh.Channel, cmd string) (int, error) {
	cfg := &ssh.ClientConfig{
		User:            b.cfg.UpstreamUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(b.upstreamSigner)},
		HostKeyCallback: b.upstreamHostKeyCallback(),
		Timeout:         dialTimeout,
	}
	client, err := ssh.Dial("tcp", upstreamDialAddr(b.cfg.UpstreamHost), cfg)
	if err != nil {
		return relayErrExit, fmt.Errorf("dial %s: %w", b.cfg.UpstreamHost, err)
	}
	defer func() { _ = client.Close() }()
	sess, err := client.NewSession()
	if err != nil {
		return relayErrExit, fmt.Errorf("new session: %w", err)
	}
	defer func() { _ = sess.Close() }()
	sess.Stdout = ch
	sess.Stderr = ch.Stderr()
	if err := sess.Run(cmd); err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			return ee.ExitStatus(), nil // upstream ran; propagate its status
		}
		return relayErrExit, fmt.Errorf("run: %w", err)
	}
	return 0, nil
}

// upstreamHostKeyCallback pins the upstream key when one is configured.
func (b *bastion) upstreamHostKeyCallback() ssh.HostKeyCallback {
	if b.upstreamHostKey != nil {
		return ssh.FixedHostKey(b.upstreamHostKey)
	}
	// TODO(prod): distribute and pin the upstream host key via
	// CERBERUS_SSH_UPSTREAM_HOSTKEY. Until then any upstream key is accepted,
	// which means a MITM between bastion and upstream is undetected.
	return ssh.InsecureIgnoreHostKey() //nolint:gosec // G106: temporary until CERBERUS_SSH_UPSTREAM_HOSTKEY pinning is set in prod
}

// parseExecPayload decodes an RFC 4254 §6.5 exec request: 4-byte big-endian
// command length followed by the command bytes.
func parseExecPayload(p []byte) string {
	if len(p) < 4 {
		return ""
	}
	n := int(binary.BigEndian.Uint32(p[:4]))
	if n > maxCommandSize || n > len(p)-4 {
		return string(p[4:]) // malformed: best effort, engine still sees it
	}
	return string(p[4 : 4+n])
}

func exitStatusPayload(code int) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(code)) //nolint:gosec // G115: code is 0/126/127 or an SSH exit status
}

// upstreamDialAddr appends the default SSH port when none is given.
func upstreamDialAddr(host string) string {
	if strings.Contains(host, ":") {
		return host
	}
	return host + ":22"
}

// parseHostKeyB64 accepts a base64 wire-format public key blob, optionally
// in authorized_keys form ("ssh-ed25519 AAAA... comment").
func parseHostKeyB64(s string) (ssh.PublicKey, error) {
	if fields := strings.Fields(s); len(fields) >= 2 && strings.HasPrefix(fields[0], "ssh-") {
		s = fields[1]
	}
	blob, err := base64Decode(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return ssh.ParsePublicKey(blob)
}

func base64Decode(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// loadOrGenerateHostKey returns the bastion host key signer, generating and
// persisting a fresh ed25519 key (OpenSSH PEM, 0600) if the file is missing.
func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: path is a server flag/env, not user input
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse host key %s: %w", path, err)
		}
		return signer, nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "cerberus-ssh bastion host key")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, fmt.Errorf("encode host key pem: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("write host key %s: %w", path, err)
	}
	return ssh.ParsePrivateKey(buf.Bytes())
}

func main() {
	var cfg config
	flag.StringVar(&cfg.Listen, "listen", "0.0.0.0:2222", "listen address")
	flag.StringVar(&cfg.EngineURL, "engine-url", "http://host.docker.internal:8089", "cerberus engine base URL")
	flag.StringVar(&cfg.EngineToken, "engine-token", os.Getenv("CERBERUS_ADMIN_TOKEN"), "cerberus engine token (or env CERBERUS_ADMIN_TOKEN)")
	flag.StringVar(&cfg.UpstreamHost, "upstream-host", os.Getenv("CERBERUS_SSH_UPSTREAM_HOST"), "upstream SSH host (also the decide input host value)")
	flag.StringVar(&cfg.UpstreamUser, "upstream-user", os.Getenv("CERBERUS_SSH_UPSTREAM_USER"), "upstream SSH user (also the decide input user value)")
	flag.StringVar(&cfg.KeyFile, "key-file", os.Getenv("CERBERUS_SSH_UPSTREAM_KEY"), "path to upstream private key PEM; empty = decide-only mode (no relay)")
	flag.StringVar(&cfg.HostKeyFile, "hostkey-file", "/data/cerberus_ssh_hostkey", "bastion host key path (auto-generated if missing)")
	flag.StringVar(&cfg.UpstreamHostKeyB64, "upstream-hostkey", os.Getenv("CERBERUS_SSH_UPSTREAM_HOSTKEY"), "base64 upstream host public key; set to pin, unset = accepted (TODO)")
	flag.Parse()

	b, err := newBastion(cfg)
	if err != nil {
		log.Fatalf("[cerberus-ssh] config: %v", err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("[cerberus-ssh] listen %s: %v", cfg.Listen, err)
	}
	mode := "relay"
	if b.upstreamSigner == nil {
		mode = "decide-only"
	}
	log.Printf("[cerberus-ssh] listening on %s (mode=%s engine=%s upstream=%s@%s)",
		cfg.Listen, mode, orDefault(cfg.EngineURL, "off"), cfg.UpstreamUser, cfg.UpstreamHost)

	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		_ = ln.Close()
	}()
	b.serve(ln)
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
