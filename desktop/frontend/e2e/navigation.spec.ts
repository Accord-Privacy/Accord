import { test, expect } from "@playwright/test";

/**
 * Navigation tests — sidebar, channels, settings, search.
 * Mocks a fully authenticated state so the main app UI renders.
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
      user_id: "user-001",
      content: "Hello, world!",
      created_at: Date.now(),
    },
  ],
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
    // Stub WebSocket so the app doesn't try to connect
    const OrigWS = window.WebSocket;
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
});

test.describe("App navigation", () => {
  test("sidebar is visible after login", async ({ page }) => {
    // The sidebar should contain node/server names or channel list
    const sidebar = page
      .locator(".sidebar, [class*=sidebar], nav, [role=navigation]")
      .first();
    await expect(sidebar).toBeVisible({ timeout: 10_000 });
  });

  test("channel list renders", async ({ page }) => {
    // Should see our mock channels in the sidebar
    await expect(page.getByText("general")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("random")).toBeVisible({ timeout: 10_000 });
  });

  test("clicking a channel loads the messages area", async ({ page }) => {
    // Click on the general channel
    await page.getByText("general").first().click();

    // Should see the message content or a messages container
    await expect(
      page
        .getByText("Hello, world!")
        .or(page.locator(".messages, [class*=message], .chat-area").first())
    ).toBeVisible({ timeout: 10_000 });
  });

  test("settings opens on Ctrl+,", async ({ page }) => {
    // Wait for app to load
    await page.getByText("general").first().waitFor({ timeout: 10_000 });

    // Trigger settings shortcut
    await page.keyboard.press("Control+,");

    // Settings panel/modal should appear
    await expect(
      page.getByText(/settings/i).first().or(
        page.locator(".settings, [class*=settings], [role=dialog]").first()
      )
    ).toBeVisible({ timeout: 5_000 });
  });

  test("search opens on Ctrl+K", async ({ page }) => {
    // Wait for app to load
    await page.getByText("general").first().waitFor({ timeout: 10_000 });

    // Trigger search shortcut
    await page.keyboard.press("Control+k");

    // Search overlay should appear
    await expect(
      page
        .getByPlaceholder(/search/i)
        .first()
        .or(page.locator(".search-overlay, [class*=search]").first())
    ).toBeVisible({ timeout: 5_000 });
  });
});
