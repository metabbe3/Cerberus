import { NextResponse } from "next/server";
import { setUserDisabled, toErrorResponse } from "@/lib/engine";

export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    const numId = parseInt(id, 10);
    const body = (await req.json()) as { disabled: boolean };
    await setUserDisabled(numId, body.disabled);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return toErrorResponse(e);
  }
}
