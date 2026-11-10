// Command cerberus is the Cerberus policy-engine binary (HTTP :8089).
package main

import (
	"fmt"
	"os"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Printf("cerberus %s\n", version)
		os.Exit(0)
	}
	// Engine wiring (config, store, audit, server) lands in Phase 1 Task 8.
	fmt.Fprintln(os.Stderr, "cerberus: nothing to do yet; engine wiring comes with the v1 server")
	os.Exit(2)
}
