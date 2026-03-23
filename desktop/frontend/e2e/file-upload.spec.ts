import { test, expect } from "@playwright/test";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

/**
 * File-upload E2E tests — stage a file, preview it, send, verify attachment.
 * Mocks a fully authenticated state (same pattern as navigation.spec.ts).
 */

// Minimal valid 1×1 transparent PNG (67 bytes)
const MINIMAL_PNG = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
  0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1×1
  0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, // RGBA, deflate
  0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, // IDAT chunk
  0x54, 0x78, 0x9c, 0x62, 0x00, 0x00, 0x00, 0x02,
  0x00, 0x01, 0xe2, 0x21, 0xbc, 0x33, 0x00, 0x00, // compressed data
  0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, // IEND chunk
  0x60, 0x82,
]);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURE_DIR = path.join(__dirname, "fixtures");
const FIXTURE_PATH = path.join(FIXTURE_DIR, "test-image.png");

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

const MOCK_FILE_METADATA = {
  id: "file-001",
  encrypted_filename: "test-image.png",
  file_size_bytes: MINIMAL_PNG.byteLength,
  created_at: Math.floor(Date.now() / 1000),
  uploader_id: "user-001",
};

/** Initial messages (no files) — returned before the upload. */
const MOCK_MESSAGES_EMPTY = {
  messages: [],
  has_more: false,
};

/** Messages returned AFTER the upload — includes the file attachment. */
const MOCK_MESSAGES_WITH_FILE = {
  messages: [
    {
      id: "msg-001",
      channel_id: "chan-001",
      sender_id: "user-001",
      display_name: "TestUser",
      encrypted_payload: "Check out this image",
      created_at: Math.floor(Date.now() / 1000),
      files: [MOCK_FILE_METADATA],
    },
  ],
  has_more: false,
};

// Write the fixture PNG to disk before tests run
test.beforeAll(() => {
  if (!fs.existsSync(FIXTURE_DIR)) {
    fs.mkdirSync(FIXTURE_DIR, { recursive: true });
  }
  fs.writeFileSync(FIXTURE_PATH, MINIMAL_PNG);
});

test.beforeEach(async ({ page }) => {
  // ---- Track upload calls so we can switch message payloads ----
  let uploadCompleted = false;

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
    return route.continue();
  });

  // Mock channels
  await page.route("**/nodes/node-001/channels", (route) =>
    route.fulfill({ status: 200, json: MOCK_CHANNELS })
  );

  // Mock members
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

  // Mock messages — returns the file-bearing message once an upload happened
  await page.route("**/channels/*/messages*", (route) => {
    if (route.request().method() === "GET") {
      return route.fulfill({
        status: 200,
        json: uploadCompleted ? MOCK_MESSAGES_WITH_FILE : MOCK_MESSAGES_EMPTY,
      });
    }
    // POST = sending a message
    return route.fulfill({
      status: 200,
      json: {
        id: "msg-001",
        channel_id: "chan-001",
        sender_id: "user-001",
        display_name: "TestUser",
        encrypted_payload: "Check out this image",
        created_at: Math.floor(Date.now() / 1000),
        files: [MOCK_FILE_METADATA],
      },
    });
  });

  // Mock file upload endpoint: POST /channels/:id/files
  await page.route("**/channels/*/files", (route) => {
    if (route.request().method() === "POST") {
      uploadCompleted = true;
      return route.fulfill({
        status: 200,
        json: { file_id: "file-001", message: "File uploaded" },
      });
    }
    // GET = list channel files
    return route.fulfill({ status: 200, json: [] });
  });

  // Mock file download (for inline image preview in FileAttachment)
  await page.route("**/files/file-001", (route) =>
    route.fulfill({
      status: 200,
      body: MINIMAL_PNG,
      headers: { "Content-Type": "image/png" },
    })
  );

  // Mock avatar endpoint to avoid 404 noise
  await page.route("**/users/*/avatar", (route) =>
    route.fulfill({ status: 404 })
  );

  // Stub WebSocket to prevent connection errors
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

  // Simulate authenticated state
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

test.describe("File upload", () => {
  test("stage a file via file input, see preview, send, and verify attachment", async ({
    page,
  }) => {
    // Wait for the channel list to render
    await expect(page.getByText("general")).toBeVisible({ timeout: 10_000 });

    // Click to open the general channel
    await page.getByText("general").first().click();

    // Wait for the message input area to appear
    const messageInput = page.locator("textarea.message-input");
    await expect(messageInput).toBeVisible({ timeout: 10_000 });

    // ---- Stage a file via the hidden <input type="file"> ----
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(FIXTURE_PATH);

    // ---- Verify the staged-files preview is visible ----
    const stagedPreview = page.locator(".staged-files-preview");
    await expect(stagedPreview).toBeVisible({ timeout: 5_000 });

    // The preview should show the filename
    await expect(
      stagedPreview.locator(".staged-file-name, text=test-image.png").first()
    ).toBeVisible({ timeout: 3_000 });

    // Image files should have a thumbnail preview
    const thumb = stagedPreview.locator(".staged-file-thumb");
    await expect(thumb).toBeVisible({ timeout: 3_000 });

    // ---- Send the message (with optional text) ----
    await messageInput.fill("Check out this image");
    await messageInput.press("Enter");

    // ---- Staged preview should clear after sending ----
    await expect(stagedPreview).not.toBeVisible({ timeout: 10_000 });

    // ---- Verify the file attachment renders in the message list ----
    // The FileAttachment component renders a .file-attachment container
    const attachment = page.locator(".file-attachment").first();
    await expect(attachment).toBeVisible({ timeout: 10_000 });

    // The attachment should show the filename
    await expect(
      attachment.locator(".file-attachment-name, text=test-image.png").first()
    ).toBeVisible({ timeout: 5_000 });
  });

  test("staged file can be removed before sending", async ({ page }) => {
    // Wait for channel list
    await expect(page.getByText("general")).toBeVisible({ timeout: 10_000 });
    await page.getByText("general").first().click();

    const messageInput = page.locator("textarea.message-input");
    await expect(messageInput).toBeVisible({ timeout: 10_000 });

    // Stage a file
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(FIXTURE_PATH);

    // Staged preview should appear
    const stagedPreview = page.locator(".staged-files-preview");
    await expect(stagedPreview).toBeVisible({ timeout: 5_000 });

    // Click the remove button on the staged file
    const removeBtn = stagedPreview.locator(".staged-file-remove").first();
    await expect(removeBtn).toBeVisible({ timeout: 3_000 });
    await removeBtn.click();

    // Staged preview should disappear (no files left)
    await expect(stagedPreview).not.toBeVisible({ timeout: 3_000 });
  });

  test("staged files show count badge", async ({ page }) => {
    await expect(page.getByText("general")).toBeVisible({ timeout: 10_000 });
    await page.getByText("general").first().click();

    const messageInput = page.locator("textarea.message-input");
    await expect(messageInput).toBeVisible({ timeout: 10_000 });

    // Stage a file
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(FIXTURE_PATH);

    // Should show "1 file attached"
    const countText = page.locator(".staged-files-count");
    await expect(countText).toBeVisible({ timeout: 5_000 });
    await expect(countText).toHaveText(/1 file attached/);

    // Clear all staged files
    const clearBtn = page.locator(".staged-files-clear");
    await expect(clearBtn).toBeVisible({ timeout: 3_000 });
    await clearBtn.click();

    // Preview should vanish
    await expect(page.locator(".staged-files-preview")).not.toBeVisible({
      timeout: 3_000,
    });
  });
});
