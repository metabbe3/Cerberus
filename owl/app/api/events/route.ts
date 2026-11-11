import { openEventStream, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Byte-for-byte pass-through of the engine's GET /v1/events: frames
// `event: decision` + one JSON data line, `: ping` keepalives. On an upstream
// error the stream closes and the browser's EventSource reconnects — the
// engine replays its last 50 ring events, so gaps self-heal.
export async function GET() {
  try {
    const upstream = await openEventStream();
    return new Response(upstream.body, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      },
    });
  } catch (e) {
    return toErrorResponse(e);
  }
}
