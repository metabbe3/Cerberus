package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDetectMode(t *testing.T) {
	tests := []struct {
		argv0       string
		args        []string
		wantMode    string
		wantTarget  string
		wantRemArgs []string
	}{
		{
			argv0:       "/usr/local/bin/cerberus-kubectl",
			args:        []string{"get", "pods", "-n", "kube-system"},
			wantMode:    "k8s",
			wantTarget:  "kubectl",
			wantRemArgs: []string{"get", "pods", "-n", "kube-system"},
		},
		{
			argv0:       "kubectl",
			args:        []string{"apply", "-f", "deploy.yaml"},
			wantMode:    "k8s",
			wantTarget:  "kubectl",
			wantRemArgs: []string{"apply", "-f", "deploy.yaml"},
		},
		{
			argv0:       "cerberus-psql",
			args:        []string{"-d", "mydb", "-c", "SELECT 1;"},
			wantMode:    "db",
			wantTarget:  "psql",
			wantRemArgs: []string{"-d", "mydb", "-c", "SELECT 1;"},
		},
		{
			argv0:       "psql",
			args:        []string{"mydb"},
			wantMode:    "db",
			wantTarget:  "psql",
			wantRemArgs: []string{"mydb"},
		},
		{
			argv0:       "cerberus-mysql",
			args:        []string{"-D", "proddb", "-e", "SHOW TABLES;"},
			wantMode:    "db",
			wantTarget:  "mysql",
			wantRemArgs: []string{"-D", "proddb", "-e", "SHOW TABLES;"},
		},
		{
			argv0:       "cerberus-ssh",
			args:        []string{"ubuntu@10.0.0.1", "uptime"},
			wantMode:    "ssh",
			wantTarget:  "ssh",
			wantRemArgs: []string{"ubuntu@10.0.0.1", "uptime"},
		},
		{
			argv0:       "cerberus-exec",
			args:        []string{"kubectl", "get", "nodes"},
			wantMode:    "k8s",
			wantTarget:  "kubectl",
			wantRemArgs: []string{"get", "nodes"},
		},
		{
			argv0:       "cerberus-exec",
			args:        []string{"psql", "-c", "SELECT 1;"},
			wantMode:    "db",
			wantTarget:  "psql",
			wantRemArgs: []string{"-c", "SELECT 1;"},
		},
		{
			argv0:       "cerberus-exec",
			args:        []string{"ssh", "admin@host", "ls"},
			wantMode:    "ssh",
			wantTarget:  "ssh",
			wantRemArgs: []string{"admin@host", "ls"},
		},
		{
			argv0:       "cerberus-exec",
			args:        []string{"curl", "-v", "http://example.com"},
			wantMode:    "generic",
			wantTarget:  "curl",
			wantRemArgs: []string{"-v", "http://example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.argv0, func(t *testing.T) {
			mode, target, rem := detectMode(tt.argv0, tt.args)
			if mode != tt.wantMode {
				t.Errorf("mode = %q, want %q", mode, tt.wantMode)
			}
			if target != tt.wantTarget {
				t.Errorf("target = %q, want %q", target, tt.wantTarget)
			}
			if !reflect.DeepEqual(rem, tt.wantRemArgs) {
				t.Errorf("rem = %v, want %v", rem, tt.wantRemArgs)
			}
		})
	}
}

func TestBuildPayloads(t *testing.T) {
	// 1. K8s
	k8sPayload := buildPayload("k8s", "kubectl", "k-k8s", []string{"delete", "pod", "web-1", "-n", "production", "-A"})
	if k8sPayload["stage"] != "k8s" {
		t.Errorf("k8s stage = %v", k8sPayload["stage"])
	}
	if k8sPayload["key_id"] != "k-k8s" {
		t.Errorf("k8s key_id = %v", k8sPayload["key_id"])
	}
	args, _ := k8sPayload["args"].(map[string]any)
	if args["verb"] != "delete" {
		t.Errorf("verb = %v, want delete", args["verb"])
	}
	if args["resource"] != "pod" {
		t.Errorf("resource = %v, want pod", args["resource"])
	}
	if args["target"] != "web-1" {
		t.Errorf("target = %v, want web-1", args["target"])
	}
	if args["namespace"] != "production" {
		t.Errorf("namespace = %v, want production", args["namespace"])
	}
	if args["all_namespaces"] != true {
		t.Errorf("all_namespaces = %v, want true", args["all_namespaces"])
	}

	// 2. DB Postgres with DSN
	dsn := "postgres://admin:secretPass@10.0.0.5:5432/orders_db?sslmode=disable" //nolint:gosec // G101: test fixture DSN
	dbPayload := buildPayload("db", "psql", "k-db", []string{"-d", dsn, "-c", "DROP TABLE users;"})
	if dbPayload["stage"] != "db" {
		t.Errorf("db stage = %v", dbPayload["stage"])
	}
	if dbPayload["dialect"] != "postgres" {
		t.Errorf("db dialect = %v", dbPayload["dialect"])
	}
	dbArgs, _ := dbPayload["args"].(map[string]any)
	if dbArgs["database"] != "orders_db" {
		t.Errorf("database = %v, want orders_db", dbArgs["database"])
	}
	if dbArgs["sql"] != "DROP TABLE users;" {
		t.Errorf("sql = %v, want DROP TABLE users;", dbArgs["sql"])
	}

	// 3. DB MySQL
	mysqlPayload := buildPayload("db", "mysql", "k-db", []string{"-D", "inventory", "-e", "SELECT * FROM items;"})
	if mysqlPayload["dialect"] != "mysql" {
		t.Errorf("mysql dialect = %v", mysqlPayload["dialect"])
	}
	mysqlArgs, _ := mysqlPayload["args"].(map[string]any)
	if mysqlArgs["database"] != "inventory" {
		t.Errorf("mysql database = %v, want inventory", mysqlArgs["database"])
	}
	if mysqlArgs["sql"] != "SELECT * FROM items;" {
		t.Errorf("mysql sql = %v", mysqlArgs["sql"])
	}

	// 4. SSH
	sshPayload := buildPayload("ssh", "ssh", "k-ssh", []string{"-p", "2222", "ubuntu@192.168.1.10", "cat", "/etc/hosts"})
	if sshPayload["stage"] != "ssh" {
		t.Errorf("ssh stage = %v", sshPayload["stage"])
	}
	if sshPayload["action"] != "exec" {
		t.Errorf("ssh action = %v, want exec", sshPayload["action"])
	}
	if sshPayload["host"] != "192.168.1.10" {
		t.Errorf("ssh host = %v", sshPayload["host"])
	}
	if sshPayload["user"] != "ubuntu" {
		t.Errorf("ssh user = %v", sshPayload["user"])
	}
	if sshPayload["port"] != 2222 {
		t.Errorf("ssh port = %v", sshPayload["port"])
	}
	if sshPayload["command"] != "cat /etc/hosts" {
		t.Errorf("ssh command = %v", sshPayload["command"])
	}
}

func TestRun_Allow(t *testing.T) {
	var capturedDecide map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/decide" {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &capturedDecide)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"decision": "allow",
				"rule_id":  "k8s.allow",
				"reason":   "read-only verb allowed",
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	var executedCmd string
	var executedArgs []string
	oldExec := execCommand
	execCommand = func(name string, args []string) error {
		executedCmd = name
		executedArgs = args
		return nil
	}
	defer func() { execCommand = oldExec }()

	tmpDir := t.TempDir()
	fakeKubectl := filepath.Join(tmpDir, "kubectl")
	_ = os.WriteFile(fakeKubectl, []byte("#!/bin/sh\nexit 0\n"), 0o755) //nolint:gosec // G306: executable script in test tempdir

	env := []string{
		"PATH=" + tmpDir + ":" + os.Getenv("PATH"),
		"CERBERUS_ENGINE_URL=" + srv.URL,
		"CERBERUS_KEY_ID=k-test-allow",
		"CERBERUS_EXEC_VERBOSE=true",
	}

	exitCode := run([]string{"cerberus-kubectl", "get", "pods", "-n", "default"}, env)
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if executedCmd != fakeKubectl {
		t.Errorf("executedCmd = %q, want %q", executedCmd, fakeKubectl)
	}
	if !reflect.DeepEqual(executedArgs, []string{"get", "pods", "-n", "default"}) {
		t.Errorf("executedArgs = %v, want [get pods -n default]", executedArgs)
	}
	if capturedDecide["key_id"] != "k-test-allow" {
		t.Errorf("engine key_id = %v", capturedDecide["key_id"])
	}
}

func TestRun_Deny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"decision": "deny",
			"rule_id":  "db.destructive_statement",
			"reason":   "DROP TABLE is prohibited on production",
		})
	}))
	defer srv.Close()

	wasExecuted := false
	oldExec := execCommand
	execCommand = func(_ string, _ []string) error {
		wasExecuted = true
		return nil
	}
	defer func() { execCommand = oldExec }()

	env := []string{
		"CERBERUS_ENGINE_URL=" + srv.URL,
		"CERBERUS_KEY_ID=k-test-deny",
	}

	exitCode := run([]string{"cerberus-psql", "-d", "prod", "-c", "DROP TABLE users;"}, env)
	if exitCode != exitDenied {
		t.Fatalf("exitCode = %d, want %d (exitDenied)", exitCode, exitDenied)
	}
	if wasExecuted {
		t.Fatal("target binary must not be executed when engine denies")
	}
}

func TestRun_EngineUnreachable_FailClosed(t *testing.T) {
	wasExecuted := false
	oldExec := execCommand
	execCommand = func(_ string, _ []string) error {
		wasExecuted = true
		return nil
	}
	defer func() { execCommand = oldExec }()

	env := []string{
		"CERBERUS_ENGINE_URL=http://127.0.0.1:1", // dead port
		"CERBERUS_KEY_ID=k-test",
		"CERBERUS_EXEC_ADVISORY=false",
	}

	exitCode := run([]string{"cerberus-kubectl", "get", "nodes"}, env)
	if exitCode != exitUnreachable {
		t.Fatalf("exitCode = %d, want %d (exitUnreachable)", exitCode, exitUnreachable)
	}
	if wasExecuted {
		t.Fatal("target binary must not be executed when engine is unreachable in fail-closed mode")
	}
}

func TestRun_EngineUnreachable_Advisory(t *testing.T) {
	wasExecuted := false
	oldExec := execCommand
	execCommand = func(_ string, _ []string) error {
		wasExecuted = true
		return nil
	}
	defer func() { execCommand = oldExec }()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "kubectl")
	_ = os.WriteFile(fakeBin, []byte("#!/bin/sh\nexit 0\n"), 0o755) //nolint:gosec // G306: executable script in test tempdir

	env := []string{
		"PATH=" + tmpDir + ":" + os.Getenv("PATH"),
		"CERBERUS_ENGINE_URL=http://127.0.0.1:1", // dead port
		"CERBERUS_KEY_ID=k-test",
		"CERBERUS_EXEC_ADVISORY=true",
	}

	exitCode := run([]string{"cerberus-kubectl", "get", "nodes"}, env)
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0 in advisory mode", exitCode)
	}
	if !wasExecuted {
		t.Fatal("target binary should be executed in advisory mode even when engine is unreachable")
	}
}

func TestFindRealBinary(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "dummy-tool")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil { //nolint:gosec // G306: executable script in test tempdir
		t.Fatal(err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", fmt.Sprintf("%s:%s", tmpDir, oldPath))

	found, err := findRealBinary("dummy-tool", fmt.Sprintf("%s:%s", tmpDir, oldPath))
	if err != nil {
		t.Fatalf("findRealBinary: %v", err)
	}
	if found != fakeBin {
		t.Errorf("found = %q, want %q", found, fakeBin)
	}
}
