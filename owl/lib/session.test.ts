import { describe, expect, test } from "vitest";
import { checkPassword, safeNext, signSession, verifySession } from "./session";

const SECRET = "x".repeat(64);

describe("session tokens", () => {
  test("a fresh token verifies", async () => {
    const t = await signSession(SECRET, 60);
    expect(await verifySession(t, SECRET)).toBe(true);
  });

  test("a token signed with another secret fails", async () => {
    const t = await signSession(SECRET, 60);
    expect(await verifySession(t, "y".repeat(64))).toBe(false);
  });

  test("a tampered expiry fails (signature covers it)", async () => {
    const t = await signSession(SECRET, 60);
    const [, sig] = t.split(".");
    const later = Math.floor(Date.now() / 1000) + 10 ** 6;
    expect(await verifySession(`${later}.${sig}`, SECRET)).toBe(false);
  });

  test("an expired token fails", async () => {
    const t = await signSession(SECRET, -1);
    expect(await verifySession(t, SECRET)).toBe(false);
  });

  test.each([undefined, "", "garbage", "123.", ".abc", "1.2.3"])(
    "malformed token %s fails",
    async (t) => {
      expect(await verifySession(t, SECRET)).toBe(false);
    },
  );
});

describe("safeNext (post-login redirect)", () => {
  test.each([
    ["/agents", "/agents"],
    ["/agents/abc?prefill=x", "/agents/abc?prefill=x"],
    [null, "/"],
    ["", "/"],
    ["https://evil.example", "/"],
    ["//evil.example/x", "/"],
    ["/\\evil.example", "/"],
    ["agents", "/"],
  ])("%s → %s", (input, out) => {
    expect(safeNext(input)).toBe(out);
  });
});

describe("checkPassword", () => {
  test("accepts the exact password", async () => {
    expect(await checkPassword("hunter2", "hunter2")).toBe(true);
  });
  test("rejects anything else", async () => {
    expect(await checkPassword("hunter3", "hunter2")).toBe(false);
    expect(await checkPassword("", "hunter2")).toBe(false);
    expect(await checkPassword("hunter2 ", "hunter2")).toBe(false);
  });
});
