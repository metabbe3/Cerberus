import { describe, expect, test } from "vitest";
import { escapeCSVCell } from "./csv";

describe("escapeCSVCell", () => {
  test("plain values pass unchanged", () => {
    expect(escapeCSVCell("hello")).toBe("hello");
    expect(escapeCSVCell(123)).toBe("123");
    expect(escapeCSVCell(null)).toBe("");
    expect(escapeCSVCell(undefined)).toBe("");
  });

  test("quotes, commas, newlines are escaped and wrapped", () => {
    expect(escapeCSVCell('say "hello"')).toBe('"say ""hello"""');
    expect(escapeCSVCell("a,b,c")).toBe('"a,b,c"');
    expect(escapeCSVCell("line1\nline2")).toBe('"line1\nline2"');
  });
});
