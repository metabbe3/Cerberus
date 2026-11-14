import { NextResponse } from "next/server";
import { createUser, getUsers, toErrorResponse } from "@/lib/engine";

export async function GET() {
  try {
    const users = await getUsers();
    return NextResponse.json(users);
  } catch (e) {
    return toErrorResponse(e);
  }
}

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as {
      username: string;
      role: string;
      password: string;
    };
    const user = await createUser(body);
    return NextResponse.json({ user }, { status: 201 });
  } catch (e) {
    return toErrorResponse(e);
  }
}
