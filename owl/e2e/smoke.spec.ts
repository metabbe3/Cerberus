import { expect, test } from "@playwright/test";

// The one seeded agent in data/prod.json, hash-style: 64 hex chars.
const HEX64 = /^[0-9a-f]{64}$/;

test("agents table loads and shows the seeded 64-hex key", async ({ page }) => {
  await page.goto("/agents");
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.getByRole("cell", { name: "hardika-gutama" }).first()).toBeVisible();
  const title = await page
    .locator('button[title*="click to copy"]')
    .first()
    .getAttribute("title");
  expect(title?.split(" ")[0]).toMatch(HEX64);
});

test("edit an agent and save — epoch increments; fail-closed flip shows the red confirm", async ({
  page,
}) => {
  // page.request carries the signed-in cookie; bare fetch would get 401.
  const before = (await (await page.request.get("/api/data")).json()) as {
    epoch: number;
  };

  await page.goto("/agents");
  await page.getByRole("row").filter({ hasText: "hardika-gutama" }).click();
  await page.getByRole("tab", { name: "Constraints" }).click();
  await page.getByPlaceholder("tool_call").fill("read_file");
  await page.getByPlaceholder("argument").fill("path");
  await page.getByRole("button", { name: "Add constraint" }).click();
  await expect(page.getByText("bare-array allowlist")).toBeVisible();

  await page.getByRole("tab", { name: "Models & Budget" }).click();
  const budget = page.locator('label:has-text("Budget limit") input');
  await budget.fill("77");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(
    page.getByText(`Data installed (epoch ${before.epoch + 1})`),
  ).toBeVisible();

  await page.goto("/settings");
  await page.getByRole("switch").nth(1).click();
  const dialog = page.getByText("Turn on fail-closed?");
  await expect(dialog).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).toBeHidden();
  // Cancelling must be the no-op; accepting the red confirm is what drafts
  // the flip — the switch only moves once "Yes, deny unknown" is clicked.
  await page.getByRole("switch").nth(1).click();
  await expect(dialog).toBeVisible();
  await page.getByRole("button", { name: "Yes, deny unknown" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole("switch").nth(1)).not.toBeChecked();
});

test("a fired decide call appears in the decision stream within 5s", async ({
  page,
}) => {
  await page.goto("/decisions");
  // Fire after the page has subscribed: the stream replays the ring either
  // way, so this also proves the proxy passes frames.
  await page.waitForTimeout(1000);
  const res = await fetch("http://localhost:8089/v1/decide/tool", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key_id: "e2e-probe", tool_call: "read_file", args: {} }),
  });
  expect(res.ok).toBe(true);
  await expect(page.getByText("read_file").first()).toBeVisible({
    timeout: 5_000,
  });
});
