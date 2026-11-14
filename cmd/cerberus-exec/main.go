// Package main implements cerberus-exec, a single-binary wrapper executor
// for forced in-path policy enforcement on CLI tools (kubectl, psql, mysql, ssh).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultEngineURL = "http://127.0.0.1:8089"
	exitUnreachable  = 124
	exitDenied       = 125
)

// runner abstracts binary execution so unit tests can mock process spawning.
var execCommand = defaultExecCommand

func defaultExecCommand(name string, args []string) error {
	cmd := exec.Command(name, args...) //nolint:gosec // G204: wrapper executor targets dynamic command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	exitCode := run(os.Args, os.Environ())
	os.Exit(exitCode)
}

func run(args []string, environ []string) int {
	getEnv := func(key string) string {
		for _, env := range environ {
			if strings.HasPrefix(env, key+"=") {
				return strings.TrimPrefix(env, key+"=")
			}
		}
		return os.Getenv(key)
	}

	argv0 := args[0]
	cliArgs := args[1:]

	mode, target, targetArgs := detectMode(argv0, cliArgs)
	if target == "" {
		fmt.Fprintln(os.Stderr, "cerberus-exec: no target command specified")
		return 1
	}

	engineURL := getEnv("CERBERUS_ENGINE_URL")
	if engineURL == "" {
		engineURL = defaultEngineURL
	}
	keyID := getEnv("CERBERUS_KEY_ID")
	if keyID == "" {
		keyID = "default"
	}
	adminToken := getEnv("CERBERUS_ADMIN_TOKEN")
	isAdvisory := getEnv("CERBERUS_EXEC_ADVISORY") == "true" || getEnv("CERBERUS_EXEC_ADVISORY") == "1"
	isVerbose := getEnv("CERBERUS_EXEC_VERBOSE") == "true" || getEnv("CERBERUS_EXEC_VERBOSE") == "1"

	payload := buildPayload(mode, target, keyID, targetArgs)

	start := time.Now()
	res, err := callEngine(engineURL, adminToken, payload)
	elapsed := time.Since(start)

	switch {
	case err != nil && isAdvisory:
		fmt.Fprintf(os.Stderr, "cerberus: warning: engine unreachable at %s (%v), proceeding in advisory mode\n", engineURL, err)
	case err != nil:
		fmt.Fprintf(os.Stderr, "cerberus: engine unreachable at %s: %v\n", engineURL, err)
		return exitUnreachable
	case res.Decision != "allow":
		ruleID := res.RuleID
		if ruleID == "" {
			ruleID = "denied"
		}
		reason := res.Reason
		if reason == "" {
			reason = "command rejected by policy"
		}
		fmt.Fprintf(os.Stderr, "cerberus: denied %s %s\n", ruleID, reason)
		return exitDenied
	case isVerbose:
		fmt.Fprintf(os.Stderr, "cerberus: allowed %s (%v)\n", res.RuleID, elapsed)
	}

	realBin, err := findRealBinary(target, getEnv("PATH"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cerberus: target executable %q not found in PATH: %v\n", target, err)
		return 127
	}

	if err := execCommand(realBin, targetArgs); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "cerberus: execution failed: %v\n", err)
		return 1
	}

	return 0
}

func detectMode(argv0 string, args []string) (mode, target string, remaining []string) {
	base := filepath.Base(argv0)
	switch base {
	case "cerberus-kubectl", "kubectl":
		return "k8s", "kubectl", args
	case "cerberus-psql", "psql":
		return "db", "psql", args
	case "cerberus-mysql", "mysql":
		return "db", "mysql", args
	case "cerberus-ssh", "ssh":
		return "ssh", "ssh", args
	default:
		// generic wrapper: cerberus-exec <cmd> [args...]
		if len(args) == 0 {
			return "", "", nil
		}
		sub := args[0]
		remaining = args[1:]
		switch sub {
		case "kubectl", "cerberus-kubectl":
			return "k8s", "kubectl", remaining
		case "psql", "cerberus-psql":
			return "db", "psql", remaining
		case "mysql", "cerberus-mysql":
			return "db", "mysql", remaining
		case "ssh", "cerberus-ssh":
			return "ssh", "ssh", remaining
		default:
			return "generic", sub, remaining
		}
	}
}

func buildPayload(mode, target, keyID string, args []string) map[string]any {
	switch mode {
	case "k8s":
		return buildK8sPayload(keyID, args)
	case "db":
		return buildDBPayload(keyID, target, args)
	case "ssh":
		return buildSSHPayload(keyID, args)
	default:
		return map[string]any{
			"stage":     "tool",
			"key_id":    keyID,
			"action":    target,
			"tool_call": target,
			"args": map[string]any{
				"args": args,
			},
		}
	}
}

func buildK8sPayload(keyID string, args []string) map[string]any {
	verb := ""
	resource := ""
	target := ""
	namespace := "default"
	allNamespaces := false
	var flags []string
	manifest := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-A" || arg == "--all-namespaces":
			allNamespaces = true
			flags = append(flags, arg)
		case strings.HasPrefix(arg, "-n="):
			namespace = strings.TrimPrefix(arg, "-n=")
			flags = append(flags, arg)
		case strings.HasPrefix(arg, "--namespace="):
			namespace = strings.TrimPrefix(arg, "--namespace=")
			flags = append(flags, arg)
		case arg == "-n" || arg == "--namespace":
			if i+1 < len(args) {
				i++
				namespace = args[i]
				flags = append(flags, arg, namespace)
			}
		case strings.HasPrefix(arg, "-f="):
			manifest = strings.TrimPrefix(arg, "-f=")
			flags = append(flags, arg)
		case strings.HasPrefix(arg, "--filename="):
			manifest = strings.TrimPrefix(arg, "--filename=")
			flags = append(flags, arg)
		case arg == "-f" || arg == "--filename":
			if i+1 < len(args) {
				i++
				manifest = args[i]
				flags = append(flags, arg, manifest)
			}
		case strings.HasPrefix(arg, "-"):
			flags = append(flags, arg)
		default:
			switch {
			case verb == "":
				verb = arg
			case resource == "":
				resource = arg
			case target == "":
				target = arg
			}
		}
	}

	if manifest != "" {
		if data, err := os.ReadFile(manifest); err == nil && len(data) <= 64*1024 {
			manifest = string(data)
		}
	}

	payloadArgs := map[string]any{
		"verb":           verb,
		"resource":       resource,
		"namespace":      namespace,
		"all_namespaces": allNamespaces,
		"flags":          flags,
		"manifest":       manifest,
	}
	if target != "" {
		payloadArgs["target"] = target
	}

	return map[string]any{
		"stage":     "k8s",
		"key_id":    keyID,
		"action":    verb,
		"resource":  resource,
		"tool_call": "kubectl",
		"args":      payloadArgs,
	}
}

func buildDBPayload(keyID, target string, args []string) map[string]any {
	dialect := "postgres"
	if target == "mysql" || strings.Contains(target, "mysql") {
		dialect = "mysql"
	}

	database := ""
	sql := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if dialect == "postgres" {
			switch {
			case strings.HasPrefix(arg, "-d="):
				database = maskDSN(strings.TrimPrefix(arg, "-d="))
			case strings.HasPrefix(arg, "--dbname="):
				database = maskDSN(strings.TrimPrefix(arg, "--dbname="))
			case arg == "-d" || arg == "--dbname":
				if i+1 < len(args) {
					i++
					database = maskDSN(args[i])
				}
			case strings.HasPrefix(arg, "-c="):
				sql = strings.TrimPrefix(arg, "-c=")
			case strings.HasPrefix(arg, "--command="):
				sql = strings.TrimPrefix(arg, "--command=")
			case arg == "-c" || arg == "--command":
				if i+1 < len(args) {
					i++
					sql = args[i]
				}
			case strings.HasPrefix(arg, "-f="):
				if data, err := os.ReadFile(strings.TrimPrefix(arg, "-f=")); err == nil {
					sql = string(data)
				}
			case strings.HasPrefix(arg, "--file="):
				if data, err := os.ReadFile(strings.TrimPrefix(arg, "--file=")); err == nil {
					sql = string(data)
				}
			case arg == "-f" || arg == "--file":
				if i+1 < len(args) {
					i++
					if data, err := os.ReadFile(args[i]); err == nil {
						sql = string(data)
					}
				}
			case !strings.HasPrefix(arg, "-") && database == "":
				database = maskDSN(arg)
			}
		} else { // mysql
			switch {
			case strings.HasPrefix(arg, "-D="):
				database = maskDSN(strings.TrimPrefix(arg, "-D="))
			case strings.HasPrefix(arg, "--database="):
				database = maskDSN(strings.TrimPrefix(arg, "--database="))
			case arg == "-D" || arg == "--database":
				if i+1 < len(args) {
					i++
					database = maskDSN(args[i])
				}
			case strings.HasPrefix(arg, "-e="):
				sql = strings.TrimPrefix(arg, "-e=")
			case strings.HasPrefix(arg, "--execute="):
				sql = strings.TrimPrefix(arg, "--execute=")
			case arg == "-e" || arg == "--execute":
				if i+1 < len(args) {
					i++
					sql = args[i]
				}
			case !strings.HasPrefix(arg, "-") && database == "":
				database = maskDSN(arg)
			}
		}
	}

	return map[string]any{
		"stage":    "db",
		"key_id":   keyID,
		"dialect":  dialect,
		"resource": database,
		"args": map[string]any{
			"dialect":  dialect,
			"database": database,
			"sql":      sql,
		},
	}
}

func maskDSN(raw string) string {
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err == nil {
			dbName := strings.TrimPrefix(u.Path, "/")
			if dbName != "" {
				return dbName
			}
			return u.Host
		}
	}
	return raw
}

func buildSSHPayload(keyID string, args []string) map[string]any {
	host := ""
	user := ""
	port := 22
	var cmdParts []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-p":
			if i+1 < len(args) {
				i++
				if p, err := strconv.Atoi(args[i]); err == nil {
					port = p
				}
			}
		case arg == "-l":
			if i+1 < len(args) {
				i++
				user = args[i]
			}
		case strings.HasPrefix(arg, "-"):
			if arg == "-i" || arg == "-o" || arg == "-F" {
				i++
			}
		default:
			if host == "" {
				if strings.Contains(arg, "@") {
					parts := strings.SplitN(arg, "@", 2)
					if user == "" {
						user = parts[0]
					}
					host = parts[1]
				} else {
					host = arg
				}
			} else {
				cmdParts = append(cmdParts, arg)
			}
		}
	}

	command := strings.Join(cmdParts, " ")
	action := "connect"
	if command != "" {
		action = "exec"
	}

	return map[string]any{
		"stage":    "ssh",
		"key_id":   keyID,
		"action":   action,
		"host":     host,
		"user":     user,
		"port":     port,
		"command":  command,
		"resource": host,
		"args": map[string]any{
			"host":    host,
			"user":    user,
			"port":    port,
			"command": command,
		},
	}
}

type decideResp struct {
	Decision string `json:"decision"`
	RuleID   string `json:"rule_id"`
	Reason   string `json:"reason"`
}

func callEngine(engineURL, token string, payload map[string]any) (*decideResp, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	u := strings.TrimSuffix(engineURL, "/") + "/v1/decide"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var d decideResp
	if err := json.Unmarshal(respBody, &d); err != nil {
		return nil, fmt.Errorf("invalid json response from engine: %w", err)
	}

	return &d, nil
}

// findRealBinary looks for the target executable in PATH, skipping the current wrapper executable.
func findRealBinary(target, pathEnv string) (string, error) {
	if pathEnv == "" {
		pathEnv = os.Getenv("PATH")
	}
	selfPath, _ := os.Executable()
	selfReal, _ := filepath.EvalSymlinks(selfPath)

	dirs := filepath.SplitList(pathEnv)

	for _, dir := range dirs {
		candidate := filepath.Join(dir, target)
		info, err := os.Stat(candidate) //nolint:gosec // G703 searching target binary in trusted PATH
		if err != nil || info.IsDir() {
			continue
		}
		// Check if executable
		if info.Mode()&0o111 == 0 {
			continue
		}
		realCandidate, err := filepath.EvalSymlinks(candidate)
		if err == nil && realCandidate == selfReal && selfReal != "" {
			// Found ourselves via symlink in PATH, keep searching
			continue
		}
		return candidate, nil
	}

	// Fallback to standard exec.LookPath if no self-reference found
	return exec.LookPath(target)
}
