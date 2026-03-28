import { test, expect } from "@playwright/test";

/**
 * Search overlay & messaging feature E2E tests.
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
  {
    id: "chan-002",
    node_id: "node-001",
    name: "random",
    channel_type: "text",
    position: 1,
    created_at: Date.now(),
  },
];

const MOCK_MESSAGES = {
  messages: [
    {
      id: "msg-001",
      channel_id: "chan-001",
      sender_id: "user-001",
      display_name: "TestUser",
      encrypted_payload: "Hello, world!",
      content: "Hello, world!",
      created_at: Math.floor(Date.now() / 1000),
      reactions: [],
    },
    {
      id: "msg-002",
      channel_id: "chan-001",
      sender_id: "user-001",
      display_name: "TestUser",
      encrypted_payload: "**bold text** and `inline code` and https://example.com",
      content: "**bold text** and `inline code` and https://example.com",
      created_at: Math.floor(Date.now() / 1000) - 60,
      reactions: [
        { emoji: "👍", count: 2, user_reacted: false },
      ],
    },
  ],
  has_more: false,
};

const MOCK_MESSAGES_EMPTY = {
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

  // Default: return messages for chan-001, empty for chan-002
  await page.route("**/channels/*/messages*", (route) => {
    const url = route.request().url();
    if (url.includes("chan-002")) {
      return route.fulfill({ status: 200, json: MOCK_MESSAGES_EMPTY });
    }
    return route.fulfill({ status: 200, json: MOCK_MESSAGES });
  });

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

  // Mock search endpoint
  await page.route("**/search*", (route) =>
    route.fulfill({
      status: 200,
      json: {
        results: [
          {
            id: "msg-001",
            channel_id: "chan-001",
            sender_id: "user-001",
            display_name: "TestUser",
            content: "Hello, world!",
            created_at: Math.floor(Date.now() / 1000),
          },
        ],
      },
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

test.describe("Search overlay", () => {
  test("opens via Ctrl+K", async ({ page }) => {
    await page.keyboard.press("Control+k");

    // Search overlay or command palette should appear
    const searchOverlay = page.locator(
      ".search-overlay, .command-palette"
    ).first();
    await expect(searchOverlay).toBeVisible({ timeout: 5_000 });
  });

  test("closes via Escape key", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const searchOverlay = page.locator(
      ".search-overlay, .command-palette"
    ).first();
    await expect(searchOverlay).toBeVisible({ timeout: 5_000 });

    await page.keyboard.press("Escape");
    await expect(searchOverlay).not.toBeVisible({ timeout: 5_000 });
  });

  test("search input accepts text", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const searchInput = page.locator(
      ".search-input, .command-palette-input"
    ).first();
    await expect(searchInput).toBeVisible({ timeout: 5_000 });

    await searchInput.fill("Hello");
    await expect(searchInput).toHaveValue("Hello", { timeout: 3_000 });
  });

  test("search shows results for matching query", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const searchInput = page.locator(
      ".search-input, .command-palette-input"
    ).first();
    await expect(searchInput).toBeVisible({ timeout: 5_000 });

    await searchInput.fill("Hello");

    // Results should appear
    const results = page.locator(
      ".search-result, .search-results, .cp-result-item"
    ).first();
    await expect(results).toBeVisible({ timeout: 5_000 });
  });

  test("search from: filter shows filter chip", async ({ page }) => {
    // Open search via Ctrl+F (search overlay, not command palette)
    await page.keyboard.press("Control+f");

    const searchInput = page.locator(
      '.search-input, input[placeholder*="Search"]'
    ).first();
    // Fall back to Ctrl+K if Ctrl+F didn't open search
    if (!(await searchInput.isVisible({ timeout: 2_000 }).catch(() => false))) {
      await page.keyboard.press("Control+k");
    }
    await expect(searchInput).toBeVisible({ timeout: 5_000 });

    await searchInput.fill("from:TestUser");

    // Filter chip should appear
    const chip = page.locator('.search-chip:has-text("from:")');
    await expect(chip).toBeVisible({ timeout: 5_000 });
  });

  test("search footer shows keyboard hints", async ({ page }) => {
    await page.keyboard.press("Control+k");

    const overlay = page.locator(
      ".search-overlay, .command-palette"
    ).first();
    await expect(overlay).toBeVisible({ timeout: 5_000 });

    // Should show navigation hints in footer
    const footer = page.locator(
      ".search-footer-hint, .command-palette-footer"
    ).first();
    await expect(footer).toBeVisible({ timeout: 5_000 });
    await expect(footer).toContainText(/esc/i, { timeout: 3_000 });
  });
});

test.describe("Messaging features", () => {
  test("messages render in the chat area", async ({ page }) => {
    // Click general channel
    await page.getByText("general").first().click();

    // Messages should be visible
    await expect(
      page.locator(".message, [role=article]").first()
    ).toBeVisible({ timeout: 10_000 });
  });

  test("message timestamps render", async ({ page }) => {
    await page.getByText("general").first().click();

    // Wait for messages to load
    await expect(
      page.locator(".message, [role=article]").first()
    ).toBeVisible({ timeout: 10_000 });

    // Timestamps should be present
    const timestamp = page.locator(".message-time, .message-hover-time").first();
    await expect(timestamp).toBeAttached({ timeout: 5_000 });
  });

  test("hover on message shows action buttons", async ({ page }) => {
    await page.getByText("general").first().click();

    const message = page.locator(".message, [role=article]").first();
    await expect(message).toBeVisible({ timeout: 10_000 });

    // Hover over the message
    await message.hover();

    // Action bar should appear with reaction/reply buttons
    const actions = page.locator(".message-actions").first();
    await expect(actions).toBeVisible({ timeout: 5_000 });
  });

  test("message context menu shows Reply option", async ({ page }) => {
    await page.getByText("general").first().click();

    const message = page.locator(".message, [role=article]").first();
    await expect(message).toBeVisible({ timeout: 10_000 });

    // Right-click to open context menu
    await message.click({ button: "right" });

    const contextMenu = page.locator(".context-menu");
    await expect(contextMenu).toBeVisible({ timeout: 5_000 });
    await expect(contextMenu.locator("text=Reply")).toBeVisible({
      timeout: 3_000,
    });

    // Close context menu
    await page.keyboard.press("Escape");
  });

  test("message reactions display", async ({ page }) => {
    await page.getByText("general").first().click();

    // Wait for messages with reactions
    await expect(
      page.locator(".message, [role=article]").first()
    ).toBeVisible({ timeout: 10_000 });

    // If a reaction container is present, it should show the reaction
    const reactions = page.locator(".message-reactions, .reaction").first();
    // Reactions depend on mock data; verify the container is at least attached
    await expect(reactions).toBeAttached({ timeout: 5_000 });
  });

  test("typing indicator area exists in chat", async ({ page }) => {
    await page.getByText("general").first().click();

    // The typing indicator container should be present in the DOM
    // (it may be hidden when no one is typing)
    const typingArea = page.locator(
      ".typing-indicator, .typing-indicator-animated"
    ).first();
    await expect(typingArea).toBeAttached({ timeout: 10_000 });
  });

  test("empty state shows for channels with no messages", async ({ page }) => {
    // Click the random channel (which returns empty messages)
    await page.getByText("random").first().click();

    // Should show an empty state
    const emptyState = page.locator(
      ".empty-state, .empty-state-title"
    ).first();
    await expect(emptyState).toBeVisible({ timeout: 10_000 });
  });

  test("markdown bold renders in messages", async ({ page }) => {
    await page.getByText("general").first().click();

    // Wait for messages to load
    await expect(
      page.locator(".message, [role=article]").first()
    ).toBeVisible({ timeout: 10_000 });

    // Bold text should be rendered as <strong> or <b>
    const boldEl = page.locator(
      ".message-content strong, .message-content b"
    ).first();
    await expect(boldEl).toBeVisible({ timeout: 5_000 });
    await expect(boldEl).toHaveText("bold text");
  });

  test("markdown inline code renders in messages", async ({ page }) => {
    await page.getByText("general").first().click();

    await expect(
      page.locator(".message, [role=article]").first()
    ).toBeVisible({ timeout: 10_000 });

    // Inline code should be rendered as <code>
    const codeEl = page.locator(".message-content code").first();
    await expect(codeEl).toBeVisible({ timeout: 5_000 });
    await expect(codeEl).toHaveText("inline code");
  });

  test("markdown links render in messages", async ({ page }) => {
    await page.getByText("general").first().click();

    await expect(
      page.locator(".message, [role=article]").first()
    ).toBeVisible({ timeout: 10_000 });

    // Links should be rendered as <a> tags
    const linkEl = page.locator('.message-content a[href*="example.com"]').first();
    await expect(linkEl).toBeVisible({ timeout: 5_000 });
  });
});
