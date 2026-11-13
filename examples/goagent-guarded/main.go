// Example goagent-guarded demonstrates integrating Cerberus policy evaluation
// into a GoAgent tool execution loop using GuardedExecutor in just 1 line.
package main

import (
	"context"
	"fmt"
	"log"

	cerberus "github.com/metabbe3/cerberus/sdk/go"
)

// Simulated existing tool executor in GoAgent
func myToolRunner(_ context.Context, tool string, args any) (any, error) {
	fmt.Printf("[Agent Engine] Executing tool %s with args: %+v\n", tool, args)
	return fmt.Sprintf("output from %s", tool), nil
}

func main() {
	// 1. Initialize Cerberus client
	client := cerberus.NewClient(cerberus.ClientOptions{
		BaseURL: "http://127.0.0.1:8089",
		KeyID:   "my-goagent-key",
	})

	// 2. Wrap tool runner in GuardedExecutor (1 line!)
	guard := cerberus.NewGuardedExecutor(client)
	guardedRunner := guard.Wrap(myToolRunner)

	ctx := context.Background()

	// Safe tool execution: passes policy gate
	fmt.Println("--- Case 1: Benign tool call ---")
	res, err := guardedRunner(ctx, "read_file", map[string]any{"path": "report.txt"})
	if err != nil {
		log.Printf("Tool failed: %v\n", err)
	} else {
		fmt.Printf("Success: %v\n", res)
	}

	// Dangerous tool execution: intercepted and denied before execution
	fmt.Println("\n--- Case 2: Dangerous tool call ---")
	_, err = guardedRunner(ctx, "bash", map[string]any{"cmd": "rm -rf /"})
	if err != nil {
		fmt.Printf("Intercepted by Cerberus: %v\n", err)
	}

	// Print client telemetry metrics
	m := client.Metrics()
	fmt.Printf("\n[Cerberus Telemetry] Total: %d, Allowed: %d, Denied: %d, Hits: %d\n",
		m.TotalCalls, m.AllowedCalls, m.DeniedCalls, m.CacheHits)
}
