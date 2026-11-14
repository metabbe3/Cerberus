import { getActiveBundle, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const res = await getActiveBundle();
    if (!res.ok) {
      return new Response("Bundle not available", { status: res.status });
    }
    const blob = await res.arrayBuffer();
    const revision = res.headers.get("X-Cerberus-Revision") || "active";
    return new Response(blob, {
      status: 200,
      headers: {
        "Content-Type": "application/gzip",
        "Content-Disposition": `attachment; filename="bundle-${revision}.tar.gz"`,
        "X-Cerberus-Revision": revision,
      },
    });
  } catch (e) {
    return toErrorResponse(e);
  }
}
