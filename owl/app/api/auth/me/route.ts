import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/engine";

export async function GET() {
  const user = await getCurrentUser();
  if (!user) {
    return NextResponse.json({ error: "Tidak terautentikasi" }, { status: 401 });
  }
  return NextResponse.json({ user });
}
