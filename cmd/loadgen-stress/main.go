// Random-pattern load generator: measures max TPS of a Cerberus engine
// decide endpoint. Purely defensive capacity testing against our own loopback instance.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type samp struct{ lat float64 }

var (
	url      = flag.String("url", "http://127.0.0.1:18089/v1/decide", "decide endpoint")
	token    = flag.String("token", "", "admin bearer token")
	dur      = flag.Duration("dur", 15*time.Second, "duration per concurrency level")
	levels   = flag.Int("levels", 8, "concurrency levels: 1,2,4,...2^(levels-1)")
	start    = flag.Int("start", 1, "starting concurrency (must be power of 2)")
	verbose  = flag.Bool("v", false, "print per-1s TPS")
)

func main() {
	flag.Parse()
	if *token == "" {
		fmt.Fprintln(os.Stderr, "token required")
		os.Exit(2)
	}
	tr := &http.Transport{MaxIdleConns: 512, MaxIdleConnsPerHost: 512, IdleConnTimeout: 90 * time.Second}
	cli := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	stages := []string{"tool", "http", "docker", "ssh", "llm"}
	hosts := []string{"api.github.com", "evil.example.com", "bastion.corp", "git.teknikal.id", "10.0.0.9"}
	actions := []string{"read", "connect", "exec", "write", "list"}
	resources := []string{"fs/tmp", "teknikalidnew-db-1", "shell", "kube/pod-x", "model/gpt-x"}
	commands := []string{"ls -la", "rm -rf /", "kubectl get pods", "grep wildcard /etc/passwd", "cat /etc/hosts"}

	mkBody := func(r *rand.Rand, i uint64) []byte {
		in := map[string]any{
			"stage":  stages[r.Intn(len(stages))],
			"key_id": "k-open",
			"action": actions[r.Intn(len(actions))],
			"resource": fmt.Sprintf("%s-%d", resources[r.Intn(len(resources))], i%7),
		}
		switch in["stage"] {
		case "http":
			in["host"] = hosts[r.Intn(len(hosts))]
		case "ssh":
			in["host"] = hosts[r.Intn(len(hosts))]
			in["user"] = []string{"deploy", "root", "ubuntu"}[r.Intn(3)]
		case "docker":
			in["resource"] = "teknikalidnew-db-1"
		case "llm":
			in["model"] = "m1"
			in["prompt"] = fmt.Sprintf("prompt pattern %d jangan jailbreak", i)
		case "tool":
			in["tool_call"] = []string{"shell_run", "read_file"}[r.Intn(2)]
			in["args"] = map[string]any{"cmd": commands[r.Intn(len(commands))]}
		}
		b, _ := json.Marshal(in)
		return b
	}

	fmt.Printf("%-6s %10s %9s %10s %10s %10s %8s\n", "conc", "TPS", "p50(ms)", "p90(ms)", "p99(ms)", "max(ms)", "err%")
	var best float64
	lvl0 := 0
	sc := *start
	for sc > 1 {
		sc >>= 1
		lvl0++
	}
	for lvl := lvl0; lvl < lvl0+*levels; lvl++ {
		conc := 1 << lvl
		var ok, errs int64
		var mu sync.Mutex
		lats := make([]float64, 0, 1<<20)
		stop := time.Now().Add(*dur)
		var wg sync.WaitGroup
		for w := 0; w < conc; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(w)))
				var i uint64
				for time.Now().Before(stop) {
					i++
					req, _ := http.NewRequest("POST", *url, bytes.NewReader(mkBody(r, i)))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Authorization", "Bearer "+*token)
					t0 := time.Now()
					resp, err := cli.Do(req)
					el := time.Since(t0).Seconds() * 1000
					if err != nil {
						atomic.AddInt64(&errs, 1)
						continue
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode >= 400 {
						// 429 = rate limit (policy working) — count separately as error bucket
						atomic.AddInt64(&errs, 1)
						continue
					}
					atomic.AddInt64(&ok, 1)
					mu.Lock()
					lats = append(lats, el)
					mu.Unlock()
				}
			}(w)
		}
		wg.Wait()
		elapsed := *dur
		tps := float64(ok) / elapsed.Seconds()
		if len(lats) > 0 {
			sort.Float64s(lats)
			p := func(q float64) float64 { return lats[int(q*float64(len(lats)-1))] }
			errpct := 100 * float64(errs) / float64(ok+errs)
			fmt.Printf("%-6d %10.0f %9.1f %10.1f %10.1f %10.1f %7.1f%%\n",
				conc, tps, p(0.50), p(0.90), p(0.99), lats[len(lats)-1], errpct)
			if errpct < 1 && tps > best {
				best = tps
			}
		}
	}
	fmt.Printf("\n>>> MAX SUSTAINED TPS (err<1%%): %.0f req/s\n", best)
}
