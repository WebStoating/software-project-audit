import { expect, test } from "vitest";
import { sum } from "./sum";

test("sum adds", () => {
  expect(sum(1, 2)).toBe(3);
});
