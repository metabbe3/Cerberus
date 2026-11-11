"use client";

import { useEffect, useRef, useState } from "react";
import { AuditEventSchema, type AuditEvent } from "@/lib/schema";

// Live decision stream over EventSource('/api/events'). The engine frames
// are `event: decision`, so the default onmessage handler never fires — we
// listen by name. Keeps the last 200; EventSource reconnects on its own and
// the engine replays its last 50 ring events, so drops self-heal.
export function useDecisionStream(live: boolean) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const bufferRef = useRef<AuditEvent[]>([]);

  useEffect(() => {
    if (!live) return;
    const es = new EventSource("/api/events");
    es.addEventListener("decision", (msg) => {
      const parsed = AuditEventSchema.safeParse(JSON.parse((msg as MessageEvent).data));
      if (!parsed.success) return;
      bufferRef.current = [...bufferRef.current, parsed.data].slice(-200);
    });
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    // Batch React updates instead of re-rendering per frame.
    const flush = setInterval(() => {
      if (bufferRef.current.length) {
        const batch = bufferRef.current;
        bufferRef.current = [];
        setEvents((prev) => [...prev, ...batch].slice(-200));
      }
    }, 500);
    return () => {
      clearInterval(flush);
      es.close();
    };
  }, [live]);

  return { events, connected };
}
