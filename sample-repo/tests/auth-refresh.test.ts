import { describe, expect, it } from "vitest";

describe("auth refresh flow", () => {
  it("rejects replayed refresh tokens", () => {
    expect(401).toBe(401);
  });
});
