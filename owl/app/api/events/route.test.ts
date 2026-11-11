import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, expect, test } from "vitest";
import { GET } from "./route";

// The SSE proxy must tear the upstream engine connection down when its
// client disconnects — every orphaned /v1/events subscriber is a goroutine
// plus a channel on the engine. This is the one proxy behaviour Playwright
// can't observe (it only sees the browser side).

let upstream: Server | null = null;
let upstreamPort = 0;

beforeEach(async () => {
  process.env.CERBERUS_ADMIN_TOKEN = "test-token";
  upstream = createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    res.write("event: decision\ndata: {}\n\n");
    res.on("close", () => {
      (upstream as Server & { _clientClosed?: () => void })._clientClosed?.();
    });
  });
  upstream.on("connection", (socket) => {
    // First data frame has flushed once "data" fires after the write.
    (upstream as Server & { _clientClosed?: () => void })._clientClosed = () =>
      socket.destroy();
  });
  await new Promise<void>((resolve) => upstream!.listen(0, "127.0.0.1", resolve));
  upstreamPort = (upstream.address() as { port: number }).port;
  process.env.CERBERUS_URL = `http://127.0.0.1:${upstreamPort}`;
});

afterEach(async () => {
  await new Promise<void>((resolve, reject) =>
    upstream!.close((err) => (err && err.message !== "Server is not running" ? reject(err) : resolve())),
  );
  upstream = null;
});

test("client abort closes the upstream engine connection", async () => {
  const upstreamClosed = new Promise<void>((resolve) => {
    upstream!.on("connection", (socket) => socket.on("close", () => resolve()));
  });

  const controller = new AbortController();
  const res = await GET(new Request("http://owl.test/api/events", { signal: controller.signal }));
  expect(res.status).toBe(200);

  // Consume one frame so headers are flushed, then simulate the browser
  // dropping the connection (EventSource navigated away / toggled off).
  const reader = res.body!.getReader();
  await reader.read();
  controller.abort();

  await expect(upstreamClosed).resolves.toBeUndefined();
});
