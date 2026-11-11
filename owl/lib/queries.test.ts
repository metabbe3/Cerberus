import { describe, expect, test } from "vitest";
import { mergeEvents } from "./queries";
import type { AuditEvent } from "./schema";

const ev = (id: number, subject: string): AuditEvent => ({
  id,
  time: `2026-11-11T10:00:${String(id).padStart(2, "0")}Z`,
  stage: "tool",
  key_id: "k",
  subject,
  decision: "allow",
  rule_id: "",
  reason: "",
  epoch: 1,
  cached: false,
  latency_us: 1,
});

// The engine replays its last-50 ring on every (re)connect, and history
// already contains those same events — merging without dedupe shows the
// top of the table twice.
describe("mergeEvents", () => {
  test("drops history rows the live replay already covers", () => {
    const live = [ev(3, "c"), ev(4, "d")]; // arrival order: oldest → newest
    const history = [ev(1, "a"), ev(2, "b"), ev(3, "c")]; // newest-first
    expect(mergeEvents(live, history).map((e) => e.id)).toEqual([4, 3, 1, 2]);
  });

  test("caps the merged list, keeping the newest", () => {
    const live = [ev(4, "d"), ev(5, "e")];
    const history = [ev(1, "a"), ev(2, "b")];
    expect(mergeEvents(live, history, 3).map((e) => e.id)).toEqual([5, 4, 1]);
  });

  test("returns history alone when nothing is live", () => {
    expect(mergeEvents([], [ev(1, "a")]).map((e) => e.id)).toEqual([1]);
  });
});
