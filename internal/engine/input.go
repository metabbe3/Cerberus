package engine

// Input is the neutral decision request, identical to the JSON body of
// POST /v1/decide (ADR-0002 input contract). Args and Context are free-form;
// the Rego stages read stage, key_id, model, prompt, tool_call, args, context.
type Input struct {
	Stage    string         `json:"stage"`
	KeyID    string         `json:"key_id"`
	Action   string         `json:"action,omitempty"`
	Resource string         `json:"resource,omitempty"`
	Host     string         `json:"host,omitempty"`
	User     string         `json:"user,omitempty"`
	Port     any            `json:"port,omitempty"`
	Command  string         `json:"command,omitempty"`
	Model    string         `json:"model,omitempty"`
	Prompt   string         `json:"prompt,omitempty"`
	ToolCall string         `json:"tool_call,omitempty"`
	Args     map[string]any `json:"args,omitempty"`
	Context  map[string]any `json:"context,omitempty"`
}

// regoInput converts Input to the generic map OPA evaluates. Empty strings and
// nil maps are omitted, mirroring the JSON omitempty tags, so policy sees
// exactly the wire shape of POST /v1/decide.
func regoInput(in Input) map[string]any {
	m := make(map[string]any, 13)
	m["stage"] = in.Stage
	m["key_id"] = in.KeyID
	if in.Action != "" {
		m["action"] = in.Action
	}
	if in.Resource != "" {
		m["resource"] = in.Resource
	}
	if in.Host != "" {
		m["host"] = in.Host
	}
	if in.User != "" {
		m["user"] = in.User
	}
	if in.Port != nil && in.Port != "" && in.Port != 0 {
		m["port"] = in.Port
	}
	if in.Command != "" {
		m["command"] = in.Command
	}
	if in.Model != "" {
		m["model"] = in.Model
	}
	if in.Prompt != "" {
		m["prompt"] = in.Prompt
	}
	if in.ToolCall != "" {
		m["tool_call"] = in.ToolCall
	}
	if in.Args != nil {
		m["args"] = in.Args
	}
	if in.Context != nil {
		m["context"] = in.Context
	}
	return m
}
