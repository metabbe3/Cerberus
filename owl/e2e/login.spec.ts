import { expect, test } from "@playwright/test";
import { E2E_PASSWORD } from "../playwright.config";

test("signed-out visits land on /login; wrong password is refused; right one returns you", async ({
  page,
  request,
}) => {
  // APIs refuse without a session — the admin proxy is never open.
  const api = await request.get("/api/data");
  expect(api.status()).toBe(401);

  await page.goto("/agents");
  await expect(page).toHaveURL(/\/login\?next=%2Fagents$/);

  await page.getByLabel("Admin password").fill("not-it");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Wrong password")).toBeVisible();

  await page.getByLabel("Admin password").fill(E2E_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/agents$/);
  await expect(page.getByRole("table")).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
});
