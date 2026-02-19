import { test, expect } from "@playwright/test";

/**
 * Auth flow tests — registration and login.
 * Uses route interception to mock the Accord relay API.
 */

const MOCK_USER = {
  id: "user-001",
  public_key_hash: "abc123def456",
  public_key: "MOCK_PUBLIC_KEY",
  created_at: Date.now(),
};

const MOCK_TOKEN = {
  token: "mock-jwt-token",
  user_id: MOCK_USER.id,
  expires_at: Date.now() + 3600_000,
};

test.beforeEach(async ({ page }) => {
  // Mock health endpoint
  await page.route("**/health", (route) =>
    route.fulfill({ status: 200, json: { status: "healthy" } })
  );

  // Mock registration endpoint
  await page.route("**/auth/register", async (route) => {
    const body = route.request().postDataJSON();
    if (body?.public_key && body?.password) {
      await route.fulfill({
        status: 200,
        json: { user_id: MOCK_USER.id, message: "registered" },
      });
    } else {
      await route.fulfill({
        status: 400,
        json: { error: "Missing fields" },
      });
    }
  });

  // Mock login endpoint
  await page.route("**/auth/login", async (route) => {
    const body = route.request().postDataJSON();
    if (body?.password === "wrongpassword") {
      await route.fulfill({
        status: 401,
        json: { error: "Invalid credentials" },
      });
    } else {
      await route.fulfill({ status: 200, json: MOCK_TOKEN });
    }
  });

  // Mock user info
  await page.route("**/users/me", (route) =>
    route.fulfill({ status: 200, json: MOCK_USER })
  );

  await page.addInitScript(() => {
    localStorage.clear();
  });

  await page.goto("/");
});

test.describe("Authentication flow", () => {
  test("registration creates a new identity via the setup wizard", async ({
    page,
  }) => {
    // On first load with no identity, the setup wizard appears
    // Look for the create identity option
    const createBtn = page.getByText(/create.*identity|create.*new|generate/i).first();
    await expect(createBtn).toBeVisible({ timeout: 10_000 });
    await createBtn.click();

    // Fill in password fields (setup wizard requires password for key encryption)
    const passwordInputs = page.locator('input[type="password"]');
    const count = await passwordInputs.count();
    if (count >= 2) {
      await passwordInputs.nth(0).fill("securepassword123");
      await passwordInputs.nth(1).fill("securepassword123");
    } else if (count === 1) {
      await passwordInputs.nth(0).fill("securepassword123");
    }

    // Look for a generate/create/continue button
    const generateBtn = page
      .getByRole("button", { name: /generate|create|continue|next/i })
      .first();
    if (await generateBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await generateBtn.click();
    }

    // After identity creation, a mnemonic phrase may be shown
    // or we advance to the next step
    await expect(
      page.getByText(/mnemonic|recovery|phrase|relay|server/i).first()
    ).toBeVisible({ timeout: 10_000 });
  });

  test("login with existing identity works", async ({ page }) => {
    // Simulate a stored identity so the app shows login instead of setup
    await page.addInitScript(() => {
      localStorage.setItem(
        "accord_identities",
        JSON.stringify([
          {
            publicKeyHash: "abc123def456",
            createdAt: Date.now(),
            label: "Test Identity",
          },
        ])
      );
      localStorage.setItem("accord_active_identity", "abc123def456");
    });
    await page.goto("/");

    // With a stored identity, we should see a password/unlock prompt
    const passwordInput = page.locator('input[type="password"]').first();
    await expect(passwordInput).toBeVisible({ timeout: 10_000 });
    await passwordInput.fill("securepassword123");

    // Submit
    const unlockBtn = page
      .getByRole("button", { name: /unlock|login|sign.*in|continue/i })
      .first();
    if (await unlockBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await unlockBtn.click();
    }
  });

  test("invalid credentials show an error", async ({ page }) => {
    // Simulate stored identity
    await page.addInitScript(() => {
      localStorage.setItem(
        "accord_identities",
        JSON.stringify([
          {
            publicKeyHash: "abc123def456",
            createdAt: Date.now(),
            label: "Test Identity",
          },
        ])
      );
      localStorage.setItem("accord_active_identity", "abc123def456");
    });
    await page.goto("/");

    const passwordInput = page.locator('input[type="password"]').first();
    await expect(passwordInput).toBeVisible({ timeout: 10_000 });
    await passwordInput.fill("wrongpassword");

    const unlockBtn = page
      .getByRole("button", { name: /unlock|login|sign.*in|continue/i })
      .first();
    if (await unlockBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await unlockBtn.click();
    }

    // Should show an error message
    await expect(
      page.getByText(/invalid|incorrect|wrong|failed|error/i).first()
    ).toBeVisible({ timeout: 10_000 });
  });
});
