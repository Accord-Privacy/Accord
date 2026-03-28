import { test, expect } from "@playwright/test";

/**
 * Settings panel & theme-switching E2E tests.
 * Mocks a fully authenticated state (same pattern as navigation.spec.ts).
 */

const MOCK_NODES = [
  {
    id: "node-001",
    name: "Test Server",
    owner_id: "user-001",
    created_at: Date.now(),
  },
];

const MOCK_CHANNELS = [
  {
    id: "chan-001",
    node_id: "node-001",
    name: "general",
    channel_type: "text",
    position: 0,
    created_at: Date.now(),
  },
];

const MOCK_MESSAGES = {
  messages: [],
  has_more: false,
};

test.beforeEach(async ({ page }) => {
  // Mock all API endpoints for an authenticated session
  await page.route("**/health", (route) =>
    route.fulfill({ status: 200, json: { status: "healthy" } })
  );

  await page.route("**/users/me", (route) =>
    route.fulfill({
      status: 200,
      json: {
        id: "user-001",
        public_key_hash: "abc123",
        public_key: "PK",
        created_at: Date.now(),
        display_name: "TestUser",
      },
    })
  );

  await page.route("**/nodes", (route) =>
    route.fulfill({ status: 200, json: MOCK_NODES })
  );

  await page.route("**/nodes/node-001/channels", (route) =>
    route.fulfill({ status: 200, json: MOCK_CHANNELS })
  );

  await page.route("**/channels/*/messages*", (route) =>
    route.fulfill({ status: 200, json: MOCK_MESSAGES })
  );

  await page.route("**/nodes/node-001/members", (route) =>
    route.fulfill({
      status: 200,
      json: [
        {
          user_id: "user-001",
          node_id: "node-001",
          display_name: "TestUser",
          roles: [],
          joined_at: Date.now(),
        },
      ],
    })
  );

  // Mock WebSocket to prevent connection errors
  await page.addInitScript(() => {
    (window as any).WebSocket = class MockWebSocket {
      readyState = 1;
      onopen: (() => void) | null = null;
      onmessage: ((e: any) => void) | null = null;
      onclose: (() => void) | null = null;
      onerror: (() => void) | null = null;
      send() {}
      close() {}
      addEventListener() {}
      removeEventListener() {}
    };
  });

  // Simulate an authenticated state
  await page.addInitScript(() => {
    localStorage.setItem("accord_relay_token", "mock-jwt-token");
    localStorage.setItem("accord_relay_user_id", "user-001");
    localStorage.setItem("accord_server_url", "http://localhost:8443");
    localStorage.setItem(
      "accord_identities",
      JSON.stringify([
        {
          publicKeyHash: "abc123",
          createdAt: Date.now(),
          label: "Test",
        },
      ])
    );
    localStorage.setItem("accord_active_identity", "abc123");
  });

  await page.goto("/");

  // Wait for the app to finish loading
  await page.getByText("general").first().waitFor({ timeout: 10_000 });
});

test.describe("Settings panel", () => {
  test("opens via Ctrl+, shortcut", async ({ page }) => {
    await page.keyboard.press("Control+,");

    const settingsOverlay = page.locator(".settings-overlay");
    await expect(settingsOverlay).toBeVisible({ timeout: 5_000 });
  });

  test("opens via gear button", async ({ page }) => {
    const settingsBtn = page.locator(
      'button[title="Settings (Ctrl+,)"], button[title="Settings"]'
    ).first();
    await expect(settingsBtn).toBeVisible({ timeout: 5_000 });
    await settingsBtn.click();

    const settingsOverlay = page.locator(".settings-overlay");
    await expect(settingsOverlay).toBeVisible({ timeout: 5_000 });
  });

  test("closes via Escape key", async ({ page }) => {
    await page.keyboard.press("Control+,");

    const settingsOverlay = page.locator(".settings-overlay");
    await expect(settingsOverlay).toBeVisible({ timeout: 5_000 });

    await page.keyboard.press("Escape");
    await expect(settingsOverlay).not.toBeVisible({ timeout: 5_000 });
  });

  test("closes via close button", async ({ page }) => {
    await page.keyboard.press("Control+,");

    const settingsOverlay = page.locator(".settings-overlay");
    await expect(settingsOverlay).toBeVisible({ timeout: 5_000 });

    await page.locator(".settings-close").click();
    await expect(settingsOverlay).not.toBeVisible({ timeout: 5_000 });
  });

  test("renders Account section", async ({ page }) => {
    await page.keyboard.press("Control+,");
    await expect(page.locator(".settings-overlay")).toBeVisible({
      timeout: 5_000,
    });

    // Account / Profile is the default tab
    await expect(
      page.locator('.settings-nav-item:has-text("Profile")')
    ).toBeVisible({ timeout: 5_000 });
  });

  test("renders Appearance section", async ({ page }) => {
    await page.keyboard.press("Control+,");
    await expect(page.locator(".settings-overlay")).toBeVisible({
      timeout: 5_000,
    });

    const tab = page.locator('.settings-nav-item:has-text("Appearance")');
    await expect(tab).toBeVisible({ timeout: 5_000 });
    await tab.click();

    // Should show theme swatches
    await expect(page.locator(".theme-swatch-btn").first()).toBeVisible({
      timeout: 5_000,
    });
  });

  test("renders Voice & Audio section", async ({ page }) => {
    await page.keyboard.press("Control+,");
    await expect(page.locator(".settings-overlay")).toBeVisible({
      timeout: 5_000,
    });

    const tab = page.locator('.settings-nav-item:has-text("Voice & Audio")');
    await expect(tab).toBeVisible({ timeout: 5_000 });
    await tab.click();

    // Should show input/output device selectors
    await expect(
      page.locator('.settings-subsection-title:has-text("Input Device")')
    ).toBeVisible({ timeout: 5_000 });
    await expect(
      page.locator('.settings-subsection-title:has-text("Output Device")')
    ).toBeVisible({ timeout: 5_000 });
    await expect(page.locator(".settings-select").first()).toBeVisible({
      timeout: 5_000,
    });
  });

  test("renders Privacy section", async ({ page }) => {
    await page.keyboard.press("Control+,");
    await expect(page.locator(".settings-overlay")).toBeVisible({
      timeout: 5_000,
    });

    const tab = page.locator('.settings-nav-item:has-text("Privacy")');
    await expect(tab).toBeVisible({ timeout: 5_000 });
    await tab.click();

    // Should render privacy checkboxes
    await expect(page.locator(".settings-checkbox").first()).toBeVisible({
      timeout: 5_000,
    });
  });

  test("renders Notifications section with toggles", async ({ page }) => {
    await page.keyboard.press("Control+,");
    await expect(page.locator(".settings-overlay")).toBeVisible({
      timeout: 5_000,
    });

    const tab = page.locator('.settings-nav-item:has-text("Notifications")');
    await expect(tab).toBeVisible({ timeout: 5_000 });
    await tab.click();

    // Should show notification toggles
    await expect(
      page.locator(".settings-toggle-row").first()
    ).toBeVisible({ timeout: 5_000 });

    // Verify specific toggle labels exist
    await expect(
      page.getByText("Enable Desktop Notifications")
    ).toBeVisible({ timeout: 5_000 });
    await expect(
      page.getByText("Enable Notification Sounds")
    ).toBeVisible({ timeout: 5_000 });
  });
});

test.describe("Theme switching", () => {
  test("switches to Light theme and persists in localStorage", async ({
    page,
  }) => {
    await page.keyboard.press("Control+,");
    await expect(page.locator(".settings-overlay")).toBeVisible({
      timeout: 5_000,
    });

    // Navigate to Appearance tab
    await page
      .locator('.settings-nav-item:has-text("Appearance")')
      .click();

    // Click the Light theme swatch
    await page.locator('.theme-swatch-btn:has-text("Light")').click();

    // Verify theme is persisted in localStorage
    const theme = await page.evaluate(() =>
      localStorage.getItem("accord_theme")
    );
    expect(theme).toBe("light");

    // Verify body has the correct theme class
    await expect(page.locator("body")).toHaveClass(/theme-light/, {
      timeout: 5_000,
    });
  });

  test("switches to Midnight theme and persists in localStorage", async ({
    page,
  }) => {
    await page.keyboard.press("Control+,");
    await expect(page.locator(".settings-overlay")).toBeVisible({
      timeout: 5_000,
    });

    await page
      .locator('.settings-nav-item:has-text("Appearance")')
      .click();

    await page.locator('.theme-swatch-btn:has-text("Midnight")').click();

    const theme = await page.evaluate(() =>
      localStorage.getItem("accord_theme")
    );
    expect(theme).toBe("midnight");

    await expect(page.locator("body")).toHaveClass(/theme-midnight/, {
      timeout: 5_000,
    });
  });

  test("switches to Dark theme and persists in localStorage", async ({
    page,
  }) => {
    // First switch to Light so we can toggle back to Dark
    await page.keyboard.press("Control+,");
    await expect(page.locator(".settings-overlay")).toBeVisible({
      timeout: 5_000,
    });

    await page
      .locator('.settings-nav-item:has-text("Appearance")')
      .click();

    await page.locator('.theme-swatch-btn:has-text("Light")').click();
    await expect(page.locator("body")).toHaveClass(/theme-light/, {
      timeout: 5_000,
    });

    // Now switch back to Dark
    await page.locator('.theme-swatch-btn:has-text("Dark")').first().click();

    const theme = await page.evaluate(() =>
      localStorage.getItem("accord_theme")
    );
    expect(theme).toBe("dark");

    await expect(page.locator("body")).toHaveClass(/theme-dark/, {
      timeout: 5_000,
    });
  });
});

test.describe("Keyboard shortcuts modal", () => {
  test("opens via Ctrl+/ shortcut", async ({ page }) => {
    await page.keyboard.press("Control+/");

    const shortcutsModal = page.locator(".shortcuts-modal");
    await expect(shortcutsModal).toBeVisible({ timeout: 5_000 });
    await expect(
      shortcutsModal.getByText("Keyboard Shortcuts")
    ).toBeVisible({ timeout: 5_000 });
  });

  test("lists expected key bindings", async ({ page }) => {
    await page.keyboard.press("Control+/");

    const shortcutsModal = page.locator(".shortcuts-modal");
    await expect(shortcutsModal).toBeVisible({ timeout: 5_000 });

    // Verify some key bindings are listed
    await expect(
      shortcutsModal.locator('.shortcut-row:has-text("Open search")')
    ).toBeVisible({ timeout: 5_000 });
    await expect(
      shortcutsModal.locator('.shortcut-row:has-text("Open settings")')
    ).toBeVisible({ timeout: 5_000 });
    await expect(
      shortcutsModal.locator('.shortcut-row:has-text("Send message")')
    ).toBeVisible({ timeout: 5_000 });
  });

  test("closes via Escape key", async ({ page }) => {
    await page.keyboard.press("Control+/");

    const shortcutsModal = page.locator(".shortcuts-modal");
    await expect(shortcutsModal).toBeVisible({ timeout: 5_000 });

    await page.keyboard.press("Escape");
    await expect(shortcutsModal).not.toBeVisible({ timeout: 5_000 });
  });
});
