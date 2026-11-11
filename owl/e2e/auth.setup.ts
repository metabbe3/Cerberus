import { test as setup } from "@playwright/test";
import { E2E_PASSWORD } from "../playwright.config";

setup("sign in once for the smoke flows", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Admin password").fill(E2E_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL("/");
  await page.context().storageState({ path: "test-results/.auth.json" });
});
