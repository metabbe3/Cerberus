package server

import (
	"encoding/json"
	"net/http"
	"time"
)

// ComponentHealth is one row of the /v1/health/components report: a named
// dependency of the gateway with its live status, so the Owl overview can
// surface the whole estate (engine, postgres, audit sink, policy snapshot,
// per-agent kill state) from ONE endpoint.
type ComponentHealth struct {
	Component string         `json:"component"`
	Status    string         `json:"status"` // ok | degraded | down
	Detail    string         `json:"detail,omitempty"`
	Meta      map[string]any `json:"meta,omitempty"`
}

// componentsHandler reports the health of every gateway component the engine
// itself can observe. Failures degrade the report, never the response code:
// a monitoring endpoint that dies with the failure it reports is useless.
func (s *Server) componentsHandler(w http.ResponseWriter, r *http.Request) {
	if s.deps.Engine == nil || s.deps.Store == nil || s.deps.Store.Current() == nil {
		writeErr(w, http.StatusServiceUnavailable, "engine not ready")
		return
	}
	snap := s.deps.Store.Current()
	comps := []ComponentHealth{
		{
			Component: "engine",
			Status:    "ok",
			Detail:    "policy snapshot serving",
			Meta: map[string]any{
				"epoch":    snap.Epoch,
				"loaded":   snap.Loaded.UTC().Format(time.RFC3339),
				"age_s":    time.Since(snap.Loaded).Seconds(),
				"coverage": snap.Coverage,
			},
		},
	}

	// Agents + active kill switches come straight off the snapshot data.
	if data := snap.Data; data != nil {
		if agents, ok := data["agents"].(map[string]any); ok {
			comps = append(comps, ComponentHealth{
				Component: "agents",
				Status:    "ok",
				Detail:    "registered agents",
				Meta:      map[string]any{"count": len(agents)},
			})
		}
		killed := []string{}
		if cfg, ok := data["config"].(map[string]any); ok {
			if ks, ok := cfg["kill_switch"].(map[string]any); ok {
				if keys, ok := ks["keys"].(map[string]any); ok {
					for k, v := range keys {
						if on, _ := v.(bool); on {
							killed = append(killed, k)
						}
					}
				}
				if g, _ := ks["global"].(bool); g {
					killed = append(killed, "__global__")
				}
			}
		}
		status := "ok"
		detail := "no kill switches active"
		if len(killed) > 0 {
			status = "degraded"
			detail = "kill switch active — all actions denied for listed keys"
		}
		comps = append(comps, ComponentHealth{
			Component: "kill_switch",
			Status:    status,
			Detail:    detail,
			Meta:      map[string]any{"active": killed},
		})
	}

	// PostgreSQL: ping through the mirror when configured.
	if s.deps.PGMirror != nil {
		if err := s.deps.PGMirror.Ping(r.Context()); err != nil {
			comps = append(comps, ComponentHealth{
				Component: "postgres",
				Status:    "degraded",
				Detail:    "system-of-record unreachable (serving from last snapshot)",
				Meta:      map[string]any{"err": err.Error()},
			})
		} else {
			comps = append(comps, ComponentHealth{
				Component: "postgres",
				Status:    "ok",
				Detail:    "system of record reachable",
			})
		}
	} else {
		comps = append(comps, ComponentHealth{
			Component: "postgres",
			Status:    "down",
			Detail:    "CERBERUS_PG_DSN not set — flat-file mode",
		})
	}

	// Audit sink health.
	if s.deps.Audit != nil {
		comps = append(comps, ComponentHealth{
			Component: "audit",
			Status:    "ok",
			Detail:    "decision audit streaming",
			Meta:      map[string]any{"queue_depth": s.deps.Audit.QueueDepth()},
		})
	} else {
		comps = append(comps, ComponentHealth{Component: "audit", Status: "down", Detail: "no audit sink"})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"checked_at": time.Now().UTC().Format(time.RFC3339),
		"components": comps,
	})
}

// ensure json import used when Meta carries json.RawMessage values.
var _ = json.Marshal
