import type { NextRequest } from "next/server";
import { getBreakGlass, postBreakGlass, deleteBreakGlass, toErrorResponse } from "@/lib/engine";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    const keyId = req.nextUrl.searchParams.get("key_id") ?? undefined;
    const result = await getBreakGlass(keyId);
    return Response.json(result);
  } catch (e) {
    return toErrorResponse(e);
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const result = await postBreakGlass(body);
    return Response.json(result);
  } catch (e) {
    return toErrorResponse(e);
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const keyId = req.nextUrl.searchParams.get("key_id") ?? undefined;
    const result = await deleteBreakGlass(keyId);
    return Response.json(result);
  } catch (e) {
    return toErrorResponse(e);
  }
}
