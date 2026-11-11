# GoAgent Guarded Tool Runner Example

This example demonstrates how to integrate Cerberus policy authorization into any Go agent or tool runner using the Go SDK (`sdk/go`).

## 1-Line Integration

```go
client := cerberus.NewClient(cerberus.ClientOptions{
    BaseURL: "http://127.0.0.1:8089",
    KeyID:   "my-goagent-key",
})
guard := cerberus.NewGuardedExecutor(client)

// Intercept before tool execution in 1 line:
guardedRunner := guard.Wrap(myExistingRunner)
```

## Features

- **Pre-execution Interception**: Checks Cerberus `/v1/decide` (`stage: tool`) before executing dangerous commands.
- **Client-Side Cache**: In-memory caching with 60-second TTL per `(tool, args-hash)` to reduce network roundtrips.
- **Exponential Backoff & Retries**: Automatically retries transient network errors (default 3 attempts).
- **Telemetry**: Built-in atomic counters for total calls, allowed, denied, cache hits, retries, and errors.
- **Fail-Closed**: If Cerberus returns a deny verdict or encounters an unrecoverable failure, `GuardedExecutor` halts execution and returns `*cerberus.ErrDenied`.
