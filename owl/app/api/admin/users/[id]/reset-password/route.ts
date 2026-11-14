import { NextResponse } from "next/server";
import { resetUserPassword, toErrorResponse } from "@/lib/engine";

export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    const numId = parseInt(id, 10);
    const body = (await req.json()) as { password: string };
    await resetUserPassword(numId, body.password);
    return NextResponse.json({ ok: true });
  } catch (e) {
    return toErrorResponse(e);
  }
}
