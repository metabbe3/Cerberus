// Package shellguard parses raw shell scripts into a real shell AST and
// extracts only simple commands that are provably literal. It feeds a
// downstream allowlist (e.g. prod shield command patterns) with trustworthy
// binaries instead of regex-matching raw text, which obfuscation defeats.
//
// The guard is fail-closed by design: dynamic command names, glob or escape
// characters in the binary name, interpreter builtins like eval/source, and
// any construct that can hide or synthesize a command (command substitution,
// subshells, functions, blocks, conditionals, loops, arithmetic) are rejected
// at any nesting depth.
package shellguard

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/syntax"
)

// ExtractedCommand is one simple command that passed validation.
type ExtractedCommand struct {
	// Binary is the literal command-name word (word 0) as the shell
	// spells it, e.g. "grep" or "/bin/grep".
	Binary string

	// Args are the remaining words of the command, each rendered by
	// syntax.NewPrinter so metacharacters stay visible to callers.
	Args []string
}

// nameMetaChars are characters that make a binary name ambiguous: glob
// wildcards, a character-class bracket, and backslash escapes. If any of
// them survives into the printed command name we cannot know what the shell
// would expand and execute, so the script is rejected.
const nameMetaChars = `*?[]\`

// evalBuiltins are shell constructs that re-interpret arbitrary strings as
// commands. Allowing any of them would make every other check bypassable by
// simply wrapping the payload, so they are unconditionally forbidden.
var evalBuiltins = map[string]bool{
	"eval":   true,
	"source": true,
	".":      true,
}

// Printers are safe for reuse but not for concurrent use, so guard calls
// borrow them from a pool instead of allocating one per word.
var printerPool = sync.Pool{
	New: func() any { return syntax.NewPrinter() },
}

// ExtractAndValidate parses rawScript with a full shell parser, walks the
// AST, and returns every literal simple command in source order.
//
// It returns a non-nil error (and no commands) when the script does not
// parse, or when it contains any fail-closed trigger: a dynamic command
// name, glob/escape characters in the binary, an eval-family builtin, or
// any obfuscation vector node at any depth. An empty or comment-only script
// yields an empty slice and a nil error.
func ExtractAndValidate(rawScript string) ([]ExtractedCommand, error) {
	file, err := syntax.NewParser().Parse(strings.NewReader(rawScript), "")
	if err != nil {
		// Unparseable input cannot be analyzed, so it is blocked
		// rather than guessed at.
		return nil, fmt.Errorf("shell syntax error (blocked fail-closed): %w", err)
	}

	cmds := make([]ExtractedCommand, 0, 4)
	var blocked error

	syntax.Walk(file, func(n syntax.Node) bool {
		if blocked != nil {
			return false // already rejected; stop descending
		}
		switch node := n.(type) {
		case *syntax.CmdSubst,
			*syntax.Subshell,
			*syntax.FuncDecl,
			*syntax.Block,
			*syntax.IfClause,
			*syntax.WhileClause,
			*syntax.ForClause,
			*syntax.CaseClause,
			*syntax.ArithmExp,
			*syntax.ArithmCmd,
			*syntax.ProcSubst:
			// Each of these can hide or synthesize a command, so its
			// mere presence anywhere in the tree is grounds to reject
			// the whole script.
			blocked = fmt.Errorf("construct %s rejected as obfuscation vector (fail-closed)", nodeName(n))
			return false
		case *syntax.CallExpr:
			cmd, err := validateCall(node)
			if err != nil {
				blocked = err
				return false
			}
			if cmd != nil {
				cmds = append(cmds, *cmd)
			}
		}
		return true
	})

	if blocked != nil {
		return nil, blocked
	}
	return cmds, nil
}

// validateCall checks one simple command. It rejects any command with variable
// assignment prefixes (fail-closed, reason assignment_prefix) and returns nil
// for commands with no arguments (e.g. bare redirections).
func validateCall(call *syntax.CallExpr) (*ExtractedCommand, error) {
	if len(call.Assigns) > 0 {
		return nil, fmt.Errorf("command has assignment prefix (assignment_prefix, fail-closed)")
	}
	if len(call.Args) == 0 {
		return nil, nil
	}

	name := call.Args[0]
	if dynamicWordPart(name.Parts) {
		return nil, fmt.Errorf("dynamic command name %q rejected (fail-closed)", literalString(name))
	}

	printed := literalString(name)
	if printed == "" {
		return nil, fmt.Errorf("command name could not be rendered (fail-closed)")
	}
	if strings.ContainsAny(printed, nameMetaChars) {
		return nil, fmt.Errorf("command name %q contains glob or escape metacharacter (fail-closed)", printed)
	}
	if evalBuiltins[pureLiteral(name)] {
		return nil, fmt.Errorf("command %q is an interpreter builtin (eval/source, fail-closed)", printed)
	}

	args := make([]string, 0, len(call.Args)-1)
	for _, w := range call.Args[1:] {
		s := literalString(w)
		if s == "" {
			// Fail closed: a word we cannot render is a word we
			// cannot reason about. (An empty-string argument is
			// likewise rendered as '' by the printer, never "".)
			return nil, fmt.Errorf("argument could not be rendered (fail-closed)")
		}
		args = append(args, s)
	}
	return &ExtractedCommand{Binary: printed, Args: args}, nil
}

// literalString renders w exactly as the shell sees it, keeping glob
// characters, escapes, and quotes visible for inspection. It returns "" if
// the word cannot be rendered; callers treat that as a fail-closed trigger.
func literalString(w *syntax.Word) string {
	p := printerPool.Get().(*syntax.Printer)
	defer printerPool.Put(p)
	var buf bytes.Buffer
	if err := p.Print(&buf, w); err != nil {
		return ""
	}
	return buf.String()
}

// dynamicWordPart reports whether any part of the command-name word (at any
// quote-nesting depth) is an expansion the guard cannot resolve: parameter,
// command substitution, arithmetic, process substitution, or extglob.
func dynamicWordPart(parts []syntax.WordPart) bool {
	for _, p := range parts {
		switch part := p.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst, *syntax.ExtGlob:
			return true
		case *syntax.DblQuoted:
			// "$x" still expands, so look through double quotes.
			if dynamicWordPart(part.Parts) {
				return true
			}
		}
	}
	return false
}

// pureLiteral returns the value the shell would resolve a fully static word
// to, with quotes stripped. Only call it after dynamicWordPart returned
// false; on dynamic input the result is a meaningless prefix.
func pureLiteral(w *syntax.Word) string {
	var b strings.Builder
	for _, p := range w.Parts {
		switch part := p.(type) {
		case *syntax.Lit:
			b.WriteString(part.Value)
		case *syntax.SglQuoted:
			b.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					b.WriteString(lit.Value)
				}
			}
		}
	}
	return b.String()
}

// nodeName shortens e.g. "*syntax.Subshell" to "Subshell" for error text.
func nodeName(n syntax.Node) string {
	return strings.TrimPrefix(fmt.Sprintf("%T", n), "*syntax.")
}
