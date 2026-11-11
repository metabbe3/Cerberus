import test from "node:test";
import assert from "node:assert/strict";
import { CerberusClient, GuardedExecutor, Decision, ErrDenied } from "../dist/index.js";

test("Decision properties and methods", () => {
  const allowDec = new Decision({
    decision: "allow",
    rule_id: "rule.allow",
    reason: "allowed",
    masked_args: { arg1: "masked" },
    epoch: 10,
    cached: true,
  });

  assert.equal(allowDec.allowed(), true);
  assert.equal(allowDec.isAllowed, true);
  assert.equal(allowDec.rule_id, "rule.allow");
  assert.equal(allowDec.reason, "allowed");
  assert.deepEqual(allowDec.masked_args, { arg1: "masked" });
  assert.equal(allowDec.epoch, 10);
  assert.equal(allowDec.cached, true);

  const denyDec = new Decision({
    decision: "deny",
    rule_id: "rule.deny",
    reason: "forbidden",
  });
  assert.equal(denyDec.allowed(), false);
  assert.equal(denyDec.isAllowed, false);
});

test("GuardedExecutor executes on allow", async () => {
  const fakeClient = {
    decideTool: async (tool, args) => {
      return new Decision({
        decision: "allow",
        rule_id: "test.allow",
        reason: "ok",
      });
    },
  };

  const guard = new GuardedExecutor(fakeClient);
  let executed = false;
  const result = await guard.execute("grep", { pattern: "test" }, async (args) => {
    executed = true;
    return `matched ${args.pattern}`;
  });

  assert.equal(executed, true);
  assert.equal(result, "matched test");
});

test("GuardedExecutor throws ErrDenied on deny and halts execution", async () => {
  const fakeClient = {
    decideTool: async (tool, args) => {
      return new Decision({
        decision: "deny",
        rule_id: "shield.cmd.dangerous",
        reason: "rm -rf is blocked",
      });
    },
  };

  const guard = new GuardedExecutor(fakeClient);
  let executed = false;

  await assert.rejects(
    async () => {
      await guard.execute("shell", { cmd: "rm -rf /" }, async () => {
        executed = true;
        return "should not run";
      });
    },
    (err) => {
      assert.ok(err instanceof ErrDenied);
      assert.equal(err.rule_id, "shield.cmd.dangerous");
      assert.equal(err.reason, "rm -rf is blocked");
      assert.match(err.message, /denied by rule "shield\.cmd\.dangerous"/);
      return true;
    }
  );

  assert.equal(executed, false);
});

test("GuardedExecutor wraps tool runner middleware", async () => {
  const fakeClient = {
    decideTool: async (tool, args) => {
      return new Decision({ decision: "allow" });
    },
  };

  const guard = new GuardedExecutor(fakeClient);
  const runner = guard.wrap(async (tool, args) => `ran ${tool} on ${args.file}`);

  const out = await runner("cat", { file: "/etc/hosts" });
  assert.equal(out, "ran cat on /etc/hosts");
});

test("GuardedExecutor applies masked_args when provided", async () => {
  const fakeClient = {
    decideTool: async (tool, args) => {
      return new Decision({
        decision: "allow",
        masked_args: { secret: "[REDACTED]" },
      });
    },
  };

  const guard = new GuardedExecutor(fakeClient);
  const out = await guard.execute("login", { secret: "12345" }, async (args) => args.secret);
  assert.equal(out, "[REDACTED]");
});

test("CerberusClient caching with TTL", async () => {
  let fetchCount = 0;
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (url, opts) => {
    fetchCount++;
    return new Response(
      JSON.stringify({
        decision: "allow",
        rule_id: "rule.cache",
        reason: "ok",
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  };

  try {
    const client = new CerberusClient({
      baseUrl: "http://mock-cerberus",
      keyId: "test-key",
      cacheTtlMs: 50,
    });

    // 1. First call -> misses cache, hits fetch
    const dec1 = await client.decideTool("grep", { path: "a.txt" });
    assert.equal(dec1.allowed(), true);
    assert.equal(dec1.cached, false);
    assert.equal(fetchCount, 1);

    // 2. Second call with same args -> hits cache
    const dec2 = await client.decideTool("grep", { path: "a.txt" });
    assert.equal(dec2.allowed(), true);
    assert.equal(dec2.cached, true);
    assert.equal(fetchCount, 1);

    // 3. Different args -> cache miss
    const dec3 = await client.decideTool("grep", { path: "b.txt" });
    assert.equal(dec3.allowed(), true);
    assert.equal(dec3.cached, false);
    assert.equal(fetchCount, 2);

    // 4. Wait for TTL to expire
    await new Promise((res) => setTimeout(res, 70));

    // 5. Expired call -> hits fetch again
    const dec4 = await client.decideTool("grep", { path: "a.txt" });
    assert.equal(dec4.allowed(), true);
    assert.equal(dec4.cached, false);
    assert.equal(fetchCount, 3);

    const metrics = client.metrics();
    assert.equal(metrics.totalCalls, 4);
    assert.equal(metrics.cacheHits, 1);
    assert.equal(metrics.cacheMisses, 3);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("CerberusClient retries on 503 and recovers", async () => {
  let attempts = 0;
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (url, opts) => {
    attempts++;
    if (attempts === 1) {
      return new Response("Service Unavailable", { status: 503 });
    }
    return new Response(
      JSON.stringify({
        decision: "allow",
        rule_id: "rule.recovered",
        reason: "ok",
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  };

  try {
    const client = new CerberusClient({
      baseUrl: "http://mock-cerberus",
      maxRetries: 1,
      retryDelayMs: 5,
    });

    const dec = await client.decideTool("read", {});
    assert.equal(dec.allowed(), true);
    assert.equal(attempts, 2);

    const metrics = client.metrics();
    assert.equal(metrics.retries, 1);
    assert.equal(metrics.allowedCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
