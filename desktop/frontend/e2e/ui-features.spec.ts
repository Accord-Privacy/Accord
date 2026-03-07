import { test, expect, Page } from "@playwright/test";

const RUN_ID = Date.now().toString(36);
const DISPLAY_NAME = `TestUser-${RUN_ID}`;
const PASSWORD = "testpass1234";
const NODE_NAME = `TestNode-${RUN_ID}`;

test.describe.serial("UI Features", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext();
    page = await context.newPage();
    await page.goto("/");
    await page.evaluate(() => localStorage.setItem("accord-onboarding-complete", "true"));
  });

  test.afterAll(async () => {
    await page.context().close();
  });

  // --- Setup: Register user and create node (reuse full-flow pattern) ---

  test("setup - create identity", async () => {
    await expect(page.locator(".brand-accent")).toBeVisible({ timeout: 10_000 });
    await page.click("button:has-text('Create Identity')");

    await page.fill('input[placeholder*="How others will see you"]', DISPLAY_NAME);
    await page.fill('input[placeholder*="Choose a password"]', PASSWORD);
    await page.fill('input[placeholder*="Confirm your password"]', PASSWORD);
    await page.click("button:has-text('Generate Identity')");

    await expect(page.locator("text=Backup Your Recovery Phrase")).toBeVisible({ timeout: 15_000 });
    await page.click("button:has-text(\"I've saved my recovery phrase\")");
    await expect(page.locator(".app")).toBeVisible({ timeout: 15_000 });
  });

  test("setup - create node", async () => {
    const addButton = page.locator('[title="Join or Create Node"]');
    await expect(addButton).toBeVisible({ timeout: 10_000 });
    await addButton.click();

    await expect(page.locator(".modal-card h3:has-text('Join a Node')")).toBeVisible({ timeout: 5_000 });
    await page.click(".modal-card button:has-text('Create a New Node')");

    await expect(page.locator("text=Create a Node")).toBeVisible({ timeout: 5_000 });
    await page.fill('input[placeholder="My Community"]', NODE_NAME);
    await page.click("button:has-text('Create Node')");

    await expect(page.locator("text=Create a Node")).not.toBeVisible({ timeout: 10_000 });
    await expect(page.locator(`text=${NODE_NAME}`)).toBeVisible({ timeout: 10_000 });
  });

  // --- Test 1: Slash commands — /shrug ---

  test("slash command /shrug sends ¯\\_(ツ)_/¯", async () => {
    const messageInput = page.locator("textarea.message-input");
    await expect(messageInput).toBeVisible({ timeout: 10_000 });

    await messageInput.fill("/shrug");
    // Wait for slash command autocomplete to appear, then select it
    const shrugOption = page.locator("text=¯\\_(ツ)_/¯").first();
    if (await shrugOption.isVisible({ timeout: 2_000 }).catch(() => false)) {
      await shrugOption.click();
    }
    await messageInput.press("Enter");

    // Verify the shrug appears in chat
    await expect(page.locator('.message-content:has-text("¯\\_(ツ)_/¯")')).toBeVisible({ timeout: 10_000 });
  });

  // --- Test 2: Message context menu ---

  test("message context menu shows expected options", async () => {
    // Right-click the message we just sent
    const message = page.locator('.message-content:has-text("¯\\_(ツ)_/¯")').first();
    await message.click({ button: "right" });

    // Verify context menu items appear
    const contextMenu = page.locator(".context-menu");
    await expect(contextMenu).toBeVisible({ timeout: 5_000 });

    await expect(contextMenu.locator("text=Reply")).toBeVisible();
    await expect(contextMenu.locator("text=Edit Message")).toBeVisible();
    await expect(contextMenu.locator("text=Delete Message")).toBeVisible();
    await expect(contextMenu.locator("text=Pin Message")).toBeVisible();
    await expect(contextMenu.locator("text=Copy Text")).toBeVisible();
    await expect(contextMenu.locator("text=Save Message")).toBeVisible();

    // Close the context menu
    await page.keyboard.press("Escape");
    await expect(contextMenu).not.toBeVisible({ timeout: 3_000 });
  });

  // --- Test 3: Channel categories — collapsible ---

  test("channel category header is collapsible", async () => {
    const categoryHeader = page.locator(".category-header").first();
    await expect(categoryHeader).toBeVisible({ timeout: 5_000 });

    // There should be at least one channel visible
    const channelsBefore = await page.locator(".channel").count();
    expect(channelsBefore).toBeGreaterThan(0);

    // Click category header to collapse
    await categoryHeader.click();

    // Arrow should change to collapsed indicator ▶
    await expect(categoryHeader.locator(".category-arrow:has-text('▶')")).toBeVisible({ timeout: 3_000 });

    // Click again to expand
    await categoryHeader.click();
    await expect(categoryHeader.locator(".category-arrow:has-text('▼')")).toBeVisible({ timeout: 3_000 });
  });

  // --- Test 4: Search with filters ---

  test("search with from: filter shows filter chip", async () => {
    // Open search with Ctrl+F (also Ctrl+K works)
    await page.keyboard.press("Control+f");

    const searchInput = page.locator('.search-overlay input, .search-input, input[placeholder*="Search"]').first();
    await expect(searchInput).toBeVisible({ timeout: 5_000 });

    await searchInput.fill("from:TestUser");
    // Wait for filter chip to appear
    await expect(page.locator('.search-chip:has-text("from:TestUser")')).toBeVisible({ timeout: 5_000 });

    // Close search
    await page.keyboard.press("Escape");
  });

  // --- Test 5: Keyboard shortcuts — Ctrl+K opens search, Escape closes ---

  test("Ctrl+K opens search overlay and Escape closes it", async () => {
    await page.keyboard.press("Control+k");

    const searchInput = page.locator('.search-overlay input, .search-input, input[placeholder*="Search"]').first();
    await expect(searchInput).toBeVisible({ timeout: 5_000 });

    await page.keyboard.press("Escape");
    await expect(searchInput).not.toBeVisible({ timeout: 3_000 });
  });

  // --- Test 6: Message editing ---

  test("editing a message shows textarea with hint", async () => {
    const message = page.locator('.message-content:has-text("¯\\_(ツ)_/¯")').first();
    await message.click({ button: "right" });

    const contextMenu = page.locator(".context-menu");
    await expect(contextMenu).toBeVisible({ timeout: 5_000 });

    await contextMenu.locator("text=Edit Message").click();

    // Verify edit textarea appears
    const editTextarea = page.locator("textarea.message-edit-input, textarea.edit-input, .message-editing textarea").first();
    await expect(editTextarea).toBeVisible({ timeout: 5_000 });

    // Verify the hint text
    await expect(page.locator("text=escape to cancel")).toBeVisible({ timeout: 3_000 });
    await expect(page.locator("text=enter to save")).toBeVisible({ timeout: 3_000 });

    // Cancel editing
    await page.keyboard.press("Escape");
  });
});
