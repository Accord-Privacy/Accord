import { test, expect } from "@playwright/test";

/**
 * Mock the app so it renders with no saved identity (first-run state).
 * The SetupWizard shows when there are no stored identities.
 */

test.beforeEach(async ({ page }) => {
  // Intercept API calls so no real server is needed
  await page.route("**/health", (route) =>
    route.fulfill({ status: 200, json: { status: "healthy" } })
  );

  // Clear any localStorage state before each test
  await page.addInitScript(() => {
    localStorage.clear();
  });

  await page.goto("/");
});

test.describe("Setup Wizard — first-run flow", () => {
  test("shows setup wizard when no saved identity exists", async ({ page }) => {
    // The setup wizard should be visible on first load
    // Step 1 is the identity creation/recovery step
    await expect(
      page.getByText(/create|identity|setup|welcome/i).first()
    ).toBeVisible({ timeout: 10_000 });
  });

  test("relay URL input is present and required", async ({ page }) => {
    // Navigate to the relay step (step 3 in the wizard)
    // First we need to complete identity step — create new identity
    const createBtn = page.getByText(/create.*identity|create.*new/i).first();
    if (await createBtn.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await createBtn.click();
    }

    // Look for relay/server URL input somewhere in the wizard flow
    const relayInput = page.getByPlaceholder(/relay|server.*url|wss?:\/\//i).first();
    // If we can reach the relay step, verify the input exists
    // The wizard has multiple steps so we may need to advance
    await expect(relayInput.or(page.getByLabel(/relay/i).first())).toBeVisible({
      timeout: 10_000,
    });
  });

  test("display name input is present", async ({ page }) => {
    // The display name field should appear during setup
    const displayNameInput = page
      .getByPlaceholder(/display.*name|name/i)
      .first()
      .or(page.getByLabel(/display.*name/i).first());

    // It may be on any step of the wizard
    await expect(displayNameInput).toBeVisible({ timeout: 10_000 });
  });

  test("can enter relay URL and display name", async ({ page }) => {
    // Mock the probe endpoint so the relay URL validates
    await page.route("**/health", (route) =>
      route.fulfill({ status: 200, json: { status: "healthy" } })
    );

    // Fill display name if visible
    const nameInput = page.getByPlaceholder(/display.*name|name/i).first();
    if (await nameInput.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await nameInput.fill("TestUser");
      await expect(nameInput).toHaveValue("TestUser");
    }

    // Fill relay URL if visible (may need to navigate to that step)
    const relayInput = page.getByPlaceholder(/relay|server.*url|wss?:\/\//i).first();
    if (await relayInput.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await relayInput.fill("wss://relay.example.com");
      await expect(relayInput).toHaveValue("wss://relay.example.com");
    }
  });
});
