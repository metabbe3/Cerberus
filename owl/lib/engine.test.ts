import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EngineError, engineMessage, getData, putData } from "./engine";

beforeEach(() => {
  process.env.CERBERUS_ADMIN_TOKEN = "test-token";
});
afterEach(() => vi.unstubAllGlobals());

describe("engineMessage", () => {
  it("passes a 422 engine message through verbatim", () => {
    expect(engineMessage(422, '{"error":"policy: invalid data: bad mask"}')).toBe(
      "policy: invalid data: bad mask",
    );
  });

  it("keeps 401 a token problem, not the body", () => {
    expect(engineMessage(401, "unauthorized")).toBe(
      "Unauthorized: check CERBERUS_ADMIN_TOKEN",
    );
  });

  it("hides 5xx bodies behind a generic message", () => {
    expect(engineMessage(500, "/var/lib/cerberus/secret/path")).toBe(
      "Engine request failed (HTTP 500)",
    );
  });
});

describe("getData", () => {
  it("returns the data document with the epoch from the header", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ config: {}, agents: {} }), {
          headers: { "X-Cerberus-Epoch": "3" },
        }),
      ),
    );
    const { data, epoch } = await getData();
    expect(epoch).toBe(3);
    expect(data).toEqual({ config: {}, agents: {} });
  });

  it("maps a network failure to Engine unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("boom"); }));
    await expect(getData()).rejects.toMatchObject({
      status: 502,
      message: "Engine unreachable",
    });
  });
});

describe("putData", () => {
  it("throws a 422 EngineError carrying the engine's message", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response('{"error":"policy: invalid data: unknown top-level key"}', {
          status: 422,
        }),
      ),
    );
    const err = (await putData({}).catch((e: unknown) => e)) as EngineError;
    expect(err).toBeInstanceOf(EngineError);
    expect(err.status).toBe(422);
    expect(err.message).toBe("policy: invalid data: unknown top-level key");
  });
});
