import { test, expect } from "@playwright/test";

/**
 * Admin & moderation E2E tests — node settings, roles, members, invites,
 * moderation, audit log. Mocks all API endpoints for a fully authenticated
 * admin session.
 */

const MOCK_NODES = [
  {
    id: "node-001",
    name: "Test Server",
    owner_id: "user-001",
    description: "A test server for E2E",
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

const MOCK_ROLES = [
  {
    id: "role-001",
    name: "Admin",
    color: "#ff0000",
    permissions: 0xffff,
    position: 0,
    hoist: true,
    mentionable: true,
  },
  {
    id: "role-002",
    name: "Member",
    color: "#00ff00",
    permissions: 0x01,
    position: 1,
    hoist: false,
    mentionable: false,
  },
];

const MOCK_MEMBERS = [
  {
    user_id: "user-001",
    node_id: "node-001",
    display_name: "TestUser",
    node_role: "admin",
    online: true,
    roles: [{ id: "role-001", name: "Admin", color: "#ff0000" }],
    joined_at: Date.now(),
  },
  {
    user_id: "user-002",
    node_id: "node-001",
    display_name: "OtherUser",
    node_role: "member",
    online: true,
    roles: [{ id: "role-002", name: "Member", color: "#00ff00" }],
    joined_at: Date.now(),
  },
  {
    user_id: "user-003",
    node_id: "node-001",
    display_name: "AnotherUser",
    node_role: "member",
    online: false,
    roles: [],
    joined_at: Date.now(),
  },
];

const MOCK_INVITES = [
  {
    code: "abc123",
    created_at: Math.floor(Date.now() / 1000),
    max_uses: 10,
    uses: 3,
    expires_at: Math.floor(Date.now() / 1000) + 86400,
  },
  {
    code: "xyz789",
    created_at: Math.floor(Date.now() / 1000) - 3600,
    uses: 0,
  },
];

const MOCK_AUDIT_LOG = {
  entries: [
    {
      id: "audit-001",
      action: "channel_create",
      executor_id: "user-001",
      timestamp: Math.floor(Date.now() / 1000),
      details: JSON.stringify({ channel_name: "general" }),
    },
    {
      id: "audit-002",
      action: "member_kick",
      executor_id: "user-001",
      timestamp: Math.floor(Date.now() / 1000) - 3600,
      details: JSON.stringify({}),
    },
    {
      id: "audit-003",
      action: "invite_create",
      executor_id: "user-001",
      timestamp: Math.floor(Date.now() / 1000) - 7200,
      details: JSON.stringify({}),
    },
  ],
  has_more: false,
  next_cursor: undefined,
};

const MOCK_AUTO_MOD_WORDS = {
  words: [
    { word: "badword", action: "block", created_at: Date.now() },
    { word: "spam", action: "warn", created_at: Date.now() },
  ],
};

test.beforeEach(async ({ page }) => {
  // Mock health
  await page.route("**/health", (route) =>
    route.fulfill({ status: 200, json: { status: "healthy" } })
  );

  // Mock users/me
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

  // Mock nodes
  await page.route("**/nodes", (route) => {
    if (route.request().method() === "GET") {
      return route.fulfill({ status: 200, json: MOCK_NODES });
    }
    return route.fulfill({ status: 200, json: MOCK_NODES[0] });
  });

  // Mock channels
  await page.route("**/nodes/node-001/channels", (route) =>
    route.fulfill({ status: 200, json: MOCK_CHANNELS })
  );

  // Mock messages
  await page.route("**/channels/*/messages*", (route) =>
    route.fulfill({ status: 200, json: MOCK_MESSAGES })
  );

  // Mock members — standard endpoint
  await page.route("**/nodes/node-001/members", (route) =>
    route.fulfill({ status: 200, json: MOCK_MEMBERS })
  );

  // Mock batch members endpoint
  await page.route("**/nodes/node-001/members/batch*", (route) =>
    route.fulfill({
      status: 200,
      json: { members: MOCK_MEMBERS },
    })
  );

  // Mock roles
  await page.route("**/nodes/node-001/roles", (route) => {
    if (route.request().method() === "GET") {
      return route.fulfill({ status: 200, json: MOCK_ROLES });
    }
    // POST = create role
    return route.fulfill({
      status: 200,
      json: {
        id: "role-new",
        name: "New Role",
        color: "#99aab5",
        permissions: 0,
        position: 2,
        hoist: false,
        mentionable: false,
      },
    });
  });

  // Mock role updates/deletes
  await page.route("**/nodes/node-001/roles/*", (route) => {
    if (route.request().method() === "DELETE") {
      return route.fulfill({ status: 200, json: { success: true } });
    }
    // PATCH = update role
    return route.fulfill({ status: 200, json: MOCK_ROLES[0] });
  });

  // Mock invites
  await page.route("**/nodes/node-001/invites", (route) => {
    if (route.request().method() === "GET") {
      return route.fulfill({ status: 200, json: MOCK_INVITES });
    }
    // POST = create invite
    return route.fulfill({
      status: 200,
      json: {
        code: "newinvite",
        created_at: Math.floor(Date.now() / 1000),
        uses: 0,
      },
    });
  });

  // Mock invite revoke
  await page.route("**/nodes/node-001/invites/*", (route) =>
    route.fulfill({ status: 200, json: { success: true } })
  );

  // Mock audit log
  await page.route("**/nodes/node-001/audit-log*", (route) =>
    route.fulfill({ status: 200, json: MOCK_AUDIT_LOG })
  );

  // Mock auto-mod words
  await page.route("**/nodes/node-001/words", (route) => {
    if (route.request().method() === "GET") {
      return route.fulfill({ status: 200, json: MOCK_AUTO_MOD_WORDS });
    }
    // POST = add word
    return route.fulfill({ status: 200, json: { success: true } });
  });

  await page.route("**/nodes/node-001/words/*", (route) =>
    route.fulfill({ status: 200, json: { success: true } })
  );

  // Mock slow mode
  await page.route("**/channels/*/slowmode", (route) => {
    if (route.request().method() === "GET") {
      return route.fulfill({
        status: 200,
        json: { slow_mode_seconds: 0 },
      });
    }
    return route.fulfill({ status: 200, json: { success: true } });
  });

  // Mock node update
  await page.route("**/nodes/node-001", (route) => {
    if (route.request().method() === "PATCH") {
      return route.fulfill({ status: 200, json: MOCK_NODES[0] });
    }
    return route.fulfill({ status: 200, json: MOCK_NODES[0] });
  });

  // Mock member kick
  await page.route("**/nodes/node-001/members/*", (route) => {
    if (route.request().method() === "DELETE") {
      return route.fulfill({ status: 200, json: { success: true } });
    }
    return route.fulfill({ status: 200, json: {} });
  });

  // Mock member role assignment
  await page.route("**/nodes/node-001/members/*/roles/*", (route) =>
    route.fulfill({ status: 200, json: { success: true } })
  );

  // Mock user avatars
  await page.route("**/users/*/avatar", (route) =>
    route.fulfill({ status: 404 })
  );

  // Mock node icon
  await page.route("**/nodes/node-001/icon*", (route) =>
    route.fulfill({ status: 404 })
  );

  // Mock custom emojis
  await page.route("**/nodes/node-001/emojis*", (route) =>
    route.fulfill({ status: 200, json: [] })
  );

  // Stub WebSocket
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

  // Simulate authenticated admin state
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

/**
 * Helper: open the Node Settings modal via the server header dropdown.
 */
async function openNodeSettings(page: import("@playwright/test").Page) {
  // Wait for the server header to be visible
  const serverHeader = page.locator(".server-header");
  await expect(serverHeader).toBeVisible({ timeout: 10_000 });

  // Open the dropdown
  await serverHeader.locator(".server-header-button").click();

  // Wait for dropdown
  const dropdown = page.locator(".server-header-dropdown");
  await expect(dropdown).toBeVisible({ timeout: 5_000 });

  // Click "Node Settings"
  await dropdown.locator(".server-dropdown-item").filter({ hasText: "Node Settings" }).click();

  // Wait for the settings modal
  await expect(page.locator(".node-settings-overlay")).toBeVisible({
    timeout: 5_000,
  });
}

test.describe("Admin panel access", () => {
  test("Node Settings accessible via server header dropdown", async ({
    page,
  }) => {
    await openNodeSettings(page);

    // Should see the Node Settings header
    await expect(page.locator(".node-settings-header h2")).toHaveText(
      "Node Settings"
    );

    // Should see the tabs
    await expect(
      page.locator(".node-settings-tab").filter({ hasText: "General" })
    ).toBeVisible({ timeout: 5_000 });
  });

  test("Node Settings shows all admin tabs", async ({ page }) => {
    await openNodeSettings(page);

    // All tabs should be visible for admin user
    const expectedTabs = [
      "General",
      "Members",
      "Roles",
      "Invites",
      "Moderation",
      "Audit Log",
    ];

    for (const tabName of expectedTabs) {
      await expect(
        page.locator(".node-settings-tab").filter({ hasText: tabName })
      ).toBeVisible({ timeout: 5_000 });
    }
  });
});

test.describe("Members management", () => {
  test("Members tab shows member list with roles", async ({ page }) => {
    await openNodeSettings(page);

    // Click the Members tab
    await page
      .locator(".node-settings-tab")
      .filter({ hasText: "Members" })
      .click();

    // Should show member count header
    await expect(page.getByText(/Members/)).toBeVisible({ timeout: 5_000 });

    // Should show member cards
    const memberCards = page.locator(".ns-member-card");
    await expect(memberCards.first()).toBeVisible({ timeout: 5_000 });
  });

  test("Kick button appears for non-owner members", async ({ page }) => {
    await openNodeSettings(page);

    // Click the Members tab
    await page
      .locator(".node-settings-tab")
      .filter({ hasText: "Members" })
      .click();

    // Wait for members to load
    await expect(page.locator(".ns-member-card").first()).toBeVisible({
      timeout: 5_000,
    });

    // Should have Kick buttons for non-owner members
    const kickButtons = page.locator(".ns-btn-danger").filter({ hasText: "Kick" });
    // At least one non-owner member should have a kick button
    await expect(kickButtons.first()).toBeVisible({ timeout: 5_000 });
  });
});

test.describe("Role management", () => {
  test("Roles tab shows existing roles", async ({ page }) => {
    await openNodeSettings(page);

    // Click the Roles tab
    await page
      .locator(".node-settings-tab")
      .filter({ hasText: "Roles" })
      .click();

    // Should show role items
    const roleItems = page.locator(".ns-role-item");
    await expect(roleItems.first()).toBeVisible({ timeout: 5_000 });

    // Should show the Create Role button
    await expect(
      page.locator(".ns-btn-primary").filter({ hasText: "Create Role" })
    ).toBeVisible({ timeout: 5_000 });
  });

  test("Create Role form opens and shows color palette", async ({ page }) => {
    await openNodeSettings(page);

    // Click Roles tab
    await page
      .locator(".node-settings-tab")
      .filter({ hasText: "Roles" })
      .click();

    // Click Create Role button
    await page
      .locator(".ns-btn-primary")
      .filter({ hasText: "Create Role" })
      .click();

    // Should show the create role form
    const formCard = page.locator(".ns-form-card");
    await expect(formCard).toBeVisible({ timeout: 5_000 });

    // Should show role name input
    await expect(
      formCard.locator('.ns-input[type="text"]').first()
    ).toBeVisible({ timeout: 3_000 });

    // Should show the color palette
    const colorPalette = formCard.locator(".ns-color-palette");
    await expect(colorPalette).toBeVisible({ timeout: 3_000 });

    // Should have color swatches
    const swatches = colorPalette.locator(".ns-color-swatch");
    const swatchCount = await swatches.count();
    expect(swatchCount).toBeGreaterThanOrEqual(12);

    // Should also have a custom color input
    await expect(
      colorPalette.locator('.ns-color-custom')
    ).toBeVisible({ timeout: 3_000 });
  });

  test("Permission checkboxes render in role form", async ({ page }) => {
    await openNodeSettings(page);

    // Click Roles tab
    await page
      .locator(".node-settings-tab")
      .filter({ hasText: "Roles" })
      .click();

    // Click Create Role button
    await page
      .locator(".ns-btn-primary")
      .filter({ hasText: "Create Role" })
      .click();

    // Should show permission list
    const permList = page.locator(".ns-perm-list");
    await expect(permList).toBeVisible({ timeout: 5_000 });

    // Should have permission checkboxes
    const permItems = permList.locator(".ns-perm-item");
    const permCount = await permItems.count();
    expect(permCount).toBeGreaterThanOrEqual(5);

    // Key permissions should be listed
    await expect(
      permList.getByText("Send Messages")
    ).toBeVisible({ timeout: 3_000 });
    await expect(
      permList.getByText("Manage Channels")
    ).toBeVisible({ timeout: 3_000 });
    await expect(
      permList.getByText("Kick Members")
    ).toBeVisible({ timeout: 3_000 });
    await expect(
      permList.getByText("Administrator")
    ).toBeVisible({ timeout: 3_000 });
  });
});

test.describe("Invite management", () => {
  test("Invites tab shows invite list and create button", async ({
    page,
  }) => {
    await openNodeSettings(page);

    // Click Invites tab
    await page
      .locator(".node-settings-tab")
      .filter({ hasText: "Invites" })
      .click();

    // Should show the Create Invite button
    await expect(
      page.locator(".ns-btn-primary").filter({ hasText: "Create Invite" })
    ).toBeVisible({ timeout: 5_000 });

    // Should show Active Invites section
    await expect(page.getByText("Active Invites")).toBeVisible({
      timeout: 5_000,
    });

    // Should show invite cards
    const inviteCards = page.locator(".ns-invite-card");
    await expect(inviteCards.first()).toBeVisible({ timeout: 5_000 });

    // Should show invite codes
    await expect(
      page.locator(".ns-invite-code").first()
    ).toBeVisible({ timeout: 3_000 });
  });

  test("Create invite form opens with options", async ({ page }) => {
    await openNodeSettings(page);

    // Click Invites tab
    await page
      .locator(".node-settings-tab")
      .filter({ hasText: "Invites" })
      .click();

    // Click Create Invite
    await page
      .locator(".ns-btn-primary")
      .filter({ hasText: "Create Invite" })
      .click();

    // Should show create invite form
    const formCard = page.locator(".ns-form-card");
    await expect(formCard).toBeVisible({ timeout: 5_000 });

    // Should have max uses input
    await expect(
      formCard.locator('.ns-input[type="number"]').first()
    ).toBeVisible({ timeout: 3_000 });

    // Should have Create and Cancel buttons
    await expect(
      formCard.locator(".ns-btn-success").filter({ hasText: "Create" })
    ).toBeVisible({ timeout: 3_000 });
    await expect(
      formCard.locator(".ns-btn-ghost").filter({ hasText: "Cancel" })
    ).toBeVisible({ timeout: 3_000 });
  });
});

test.describe("Moderation", () => {
  test("Moderation tab shows slow mode controls", async ({ page }) => {
    await openNodeSettings(page);

    // Click Moderation tab
    await page
      .locator(".node-settings-tab")
      .filter({ hasText: "Moderation" })
      .click();

    // Should show Slow Mode section title
    await expect(page.getByText("Slow Mode")).toBeVisible({
      timeout: 5_000,
    });

    // Should show description text
    await expect(
      page.getByText("Limit how often users can send messages")
    ).toBeVisible({ timeout: 5_000 });

    // Should show channel rows with slow mode dropdowns
    // (may show loading first, then channel rows)
    const channelRows = page.locator(".ns-channel-row");
    if (await channelRows.first().isVisible({ timeout: 5_000 }).catch(() => false)) {
      // Each channel row should have a select for slow mode
      await expect(channelRows.locator(".ns-select").first()).toBeVisible({
        timeout: 3_000,
      });
    }
  });

  test("Word filter section renders with input and action selector", async ({
    page,
  }) => {
    await openNodeSettings(page);

    // Click Moderation tab
    await page
      .locator(".node-settings-tab")
      .filter({ hasText: "Moderation" })
      .click();

    // Should show Word Filter section
    await expect(page.getByText("Word Filter")).toBeVisible({
      timeout: 5_000,
    });

    // Should show description
    await expect(
      page.getByText("Block or warn when messages contain specific words")
    ).toBeVisible({ timeout: 5_000 });

    // Should have word input
    await expect(
      page.locator('input[placeholder="Enter word to filter..."]')
    ).toBeVisible({ timeout: 5_000 });

    // Should have action selector (Block/Warn)
    const actionSelect = page
      .locator(".ns-select")
      .filter({ has: page.locator('option[value="block"]') });
    await expect(actionSelect.first()).toBeVisible({ timeout: 3_000 });

    // Should have Add button
    await expect(
      page.locator(".ns-btn-success").filter({ hasText: "Add" })
    ).toBeVisible({ timeout: 3_000 });
  });
});

test.describe("Audit log", () => {
  test("Audit Log tab renders with filter and entries", async ({ page }) => {
    await openNodeSettings(page);

    // Click Audit Log tab
    await page
      .locator(".node-settings-tab")
      .filter({ hasText: "Audit Log" })
      .click();

    // Should show filter dropdown
    await expect(page.getByText("Filter by Action")).toBeVisible({
      timeout: 5_000,
    });

    // The filter select should have options
    const filterSelect = page
      .locator(".ns-select")
      .filter({ has: page.locator('option[value="all"]') });
    await expect(filterSelect.first()).toBeVisible({ timeout: 3_000 });

    // Should show Recent Activity section
    await expect(page.getByText("Recent Activity")).toBeVisible({
      timeout: 5_000,
    });
  });
});

test.describe("General settings", () => {
  test("General tab shows node name and description fields", async ({
    page,
  }) => {
    await openNodeSettings(page);

    // General tab should be active by default
    // Should show Node Name label and input
    await expect(page.getByText("Node Name")).toBeVisible({
      timeout: 5_000,
    });

    const nameInput = page.locator('.ns-input[type="text"]').first();
    await expect(nameInput).toBeVisible({ timeout: 3_000 });

    // Should show Description
    await expect(page.getByText("Description")).toBeVisible({
      timeout: 5_000,
    });

    // Should show Save Changes button
    await expect(
      page.locator(".ns-btn-success").filter({ hasText: "Save Changes" })
    ).toBeVisible({ timeout: 5_000 });
  });

  test("Settings modal can be closed", async ({ page }) => {
    await openNodeSettings(page);

    // Close button should be visible
    const closeBtn = page.locator(".settings-close");
    await expect(closeBtn).toBeVisible({ timeout: 5_000 });

    // Click close
    await closeBtn.click();

    // Modal should disappear
    await expect(page.locator(".node-settings-overlay")).not.toBeVisible({
      timeout: 5_000,
    });
  });
});
