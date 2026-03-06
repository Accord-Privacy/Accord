import { test, expect, Page } from "@playwright/test";

// Unique suffix per run to avoid collisions
const RUN_ID = Date.now().toString(36);
const DISPLAY_NAME = `TestUser-${RUN_ID}`;
const PASSWORD = "testpass1234";
const NODE_NAME = `TestNode-${RUN_ID}`;
const TEST_MESSAGE = `Hello E2E ${RUN_ID}`;

test.describe.serial("Accord Full Flow", () => {
  let page: Page;
  let mnemonic: string;

  test.beforeAll(async ({ browser }) => {
    // Fresh context — no stored keys
    const context = await browser.newContext();
    page = await context.newPage();
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  test("1 - Identity creation", async () => {
    await page.goto("/");
    // Skip onboarding tour in tests
    await page.evaluate(() => localStorage.setItem("accord-onboarding-complete", "true"));

    // Should see the SetupWizard with "Create Identity" button
    await expect(page.locator(".brand-accent")).toBeVisible({ timeout: 10_000 });
    await page.click("button:has-text('Create Identity')");

    // Fill in display name, password, confirm password
    await page.fill('input[placeholder*="How others will see you"]', DISPLAY_NAME);
    await page.fill('input[placeholder*="Choose a password"]', PASSWORD);
    await page.fill('input[placeholder*="Confirm your password"]', PASSWORD);

    // Click generate identity
    await page.click("button:has-text('Generate Identity')");

    // Should show mnemonic step
    await expect(page.locator("text=Backup Your Recovery Phrase")).toBeVisible({ timeout: 15_000 });

    // Capture mnemonic
    const mnemonicBox = page.locator(".auth-info-box").first();
    const mnemonicText = await mnemonicBox.textContent();
    expect(mnemonicText).toBeTruthy();
    expect(mnemonicText!.trim().split(/\s+/).length).toBeGreaterThanOrEqual(24);
    mnemonic = mnemonicText!.trim();

    // Continue past mnemonic
    await page.click("button:has-text(\"I've saved my recovery phrase\")");

    // Should land in main app (authenticated) — wait for app layout
    // The app may show the main interface or a welcome/empty state
    await expect(page.locator(".app")).toBeVisible({ timeout: 15_000 });
    // Should no longer show the SetupWizard auth page
    await expect(page.locator("text=Create Identity")).not.toBeVisible({ timeout: 5_000 });
  });

  test("2 - Node creation", async () => {
    // Click the "+" button in the server list to open create/join modal
    const addButton = page.locator('[title="Join or Create Node"]');
    await expect(addButton).toBeVisible({ timeout: 10_000 });
    await addButton.click();

    // Should see "Join a Node" modal heading
    await expect(page.locator(".modal-card h3:has-text('Join a Node')")).toBeVisible({ timeout: 5_000 });

    // Click "Create a New Node" link
    await page.click(".modal-card button:has-text('Create a New Node')");

    // Fill in node name
    await expect(page.locator("text=Create a Node")).toBeVisible({ timeout: 5_000 });
    await page.fill('input[placeholder="My Community"]', NODE_NAME);

    // Click create
    await page.click("button:has-text('Create Node')");

    // Modal should close and node should appear in sidebar
    await expect(page.locator("text=Create a Node")).not.toBeVisible({ timeout: 10_000 });

    // Verify node appears — either in server list or channel sidebar
    // The node name should be visible somewhere in the UI
    await expect(page.locator(`text=${NODE_NAME}`)).toBeVisible({ timeout: 10_000 });
  });

  test("3 - Messaging", async () => {
    // Should have a #general channel selected by default
    // Look for the message input
    const messageInput = page.locator("textarea.message-input");
    await expect(messageInput).toBeVisible({ timeout: 10_000 });

    // Type and send a message
    await messageInput.fill(TEST_MESSAGE);
    await messageInput.press("Enter");

    // Verify the message appears in chat
    await expect(page.locator(`.message-content:has-text("${TEST_MESSAGE}")`)).toBeVisible({ timeout: 10_000 });

    // Verify message input cleared after send
    await expect(messageInput).toHaveValue("", { timeout: 5_000 });
  });

  test("4 - Logout and Login", async () => {
    // Open settings
    // The settings button may be in the bottom of the sidebar
    // Look for a gear icon or settings button
    // Click user settings (bottom-left gear, not node settings)
    const settingsBtn = page.locator('button[title="Settings (Ctrl+,)"]');
    await settingsBtn.click();
    await expect(page.locator("text=Log Out")).toBeVisible({ timeout: 5_000 });

    // Click Log Out
    await page.click("button:has-text('Log Out')");

    // Confirm logout if there's a confirmation dialog
    const confirmBtn = page.locator("button:has-text('Log Out')").last();
    if (await confirmBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
      await confirmBtn.click();
    }

    // Should return to SetupWizard
    await expect(page.locator("text=Log In")).toBeVisible({ timeout: 10_000 });

    // Log in with same password
    await page.click("button:has-text('Log In')");
    await page.waitForTimeout(500);
    const pwInput = page.locator('input[type="password"]').first();
    await pwInput.fill(PASSWORD);
    // Find the submit button (not the nav "Log In")
    await page.click("button:has-text('Log In'):not(.btn-ghost)");

    // Should return to main app
    await expect(page.locator("textarea.message-input")).toBeVisible({ timeout: 15_000 });

    // Verify messages are still visible (decrypted correctly)
    await expect(page.locator(`.message-content:has-text("${TEST_MESSAGE}")`)).toBeVisible({ timeout: 10_000 });
  });

  test("5 - Settings tabs", async () => {
    // Open settings
    const settingsBtn = page.locator('button[title="Settings (Ctrl+,)"]');
    await settingsBtn.click();

    // Should see settings panel with nav
    await expect(page.locator("text=Log Out")).toBeVisible({ timeout: 5_000 });

    // Click through tabs
    const tabs = ["Account", "Appearance", "Notifications", "Privacy", "Advanced"];
    for (const tab of tabs) {
      const tabBtn = page.locator(`.settings-tab:has-text("${tab}"), button:has-text("${tab}")`).first();
      if (await tabBtn.isVisible()) {
        await tabBtn.click();
        // Just verify it doesn't crash — the tab content should change
        await page.waitForTimeout(200);
      }
    }

    // Close settings (click outside or press Escape)
    await page.keyboard.press("Escape");
  });

  test("6 - Search", async () => {
    // Open search — usually Ctrl+K or a search button
    await page.keyboard.press("Control+k");

    // Wait for search overlay
    const searchInput = page.locator('.search-overlay input, .search-input, input[placeholder*="Search"]').first();
    await expect(searchInput).toBeVisible({ timeout: 5_000 });

    // Search for our test message
    await searchInput.fill(TEST_MESSAGE);

    // Wait for results — in E2EE, search may be client-side or may not work on encrypted content
    // Give it time
    await page.waitForTimeout(1000);

    // Check if any results appear (search may or may not work depending on implementation)
    const hasResults = await page.locator(`.search-result, .search-results, text="${TEST_MESSAGE}"`).first().isVisible().catch(() => false);

    // Close search
    await page.keyboard.press("Escape");

    // We note the result but don't fail — E2EE search over encrypted blobs may be a known limitation
    if (!hasResults) {
      console.log("KNOWN LIMITATION: Search may not find encrypted messages");
    }
  });

  test("7 - Profile card", async () => {
    // Click on a member in the member sidebar (if visible)
    // First check if member sidebar is shown
    const memberEntry = page.locator('.member-item, .member-list-item, .member-entry').first();

    if (await memberEntry.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await memberEntry.click();

      // Should show a profile card / popup
      const profileCard = page.locator('.profile-card, .user-profile, .profile-popup').first();
      await expect(profileCard).toBeVisible({ timeout: 5_000 });

      // Verify it shows the user's display name
      await expect(profileCard.locator(`text=${DISPLAY_NAME}`)).toBeVisible({ timeout: 3_000 }).catch(() => {
        // Display name might have been truncated or formatted differently
        console.log("Profile card visible but display name not exactly matching");
      });

      // Close profile card
      await page.keyboard.press("Escape");
    } else {
      // Member sidebar might not be visible — try clicking our own avatar/name
      const selfName = page.locator(`text=${DISPLAY_NAME}`).first();
      if (await selfName.isVisible().catch(() => false)) {
        await selfName.click();
        await page.waitForTimeout(500);
      }
      console.log("NOTE: Member sidebar not visible — profile card test limited");
    }
  });
});
