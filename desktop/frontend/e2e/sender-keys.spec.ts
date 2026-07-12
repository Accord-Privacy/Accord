import { test, expect, Page, BrowserContext } from "@playwright/test";

// Two-client verification that channel group E2EE (Sender Keys) activates:
// Alice creates a node, invites Bob, both exchange messages that must render
// decrypted on the other side via the sender-keys path.
const RUN_ID = Date.now().toString(36);
const PASSWORD = "testpass1234";
const NODE_NAME = `SKNode-${RUN_ID}`;
const ALICE_MESSAGE = `sk-secret-alice-${RUN_ID}`;
const BOB_MESSAGE = `sk-secret-bob-${RUN_ID}`;

async function createAccount(page: Page, username: string, displayName: string) {
  await page.goto("/");
  await page.evaluate(() => localStorage.setItem("accord-onboarding-complete", "true"));
  await expect(page.locator(".brand-accent")).toBeVisible({ timeout: 10_000 });
  await page.click("button:has-text('Create Account')");
  await page.fill('input[placeholder*="Choose a username"]', username);
  await page.fill('input[placeholder*="How others will see you"]', displayName);
  await page.fill('input[placeholder*="Choose a password"]', PASSWORD);
  await page.fill('input[placeholder*="Confirm your password"]', PASSWORD);
  await page.click("button.btn-green:has-text('Create Account')");
  await expect(page.locator("text=Backup Your Recovery Phrase")).toBeVisible({ timeout: 15_000 });
  await page.click("button:has-text(\"I've saved my recovery phrase\")");
  await expect(page.locator(".app")).toBeVisible({ timeout: 15_000 });
}

test.describe.serial("Sender Keys group E2EE (two clients)", () => {
  let ctxA: BrowserContext;
  let ctxB: BrowserContext;
  let alice: Page;
  let bob: Page;

  test.beforeAll(async ({ browser }) => {
    ctxA = await browser.newContext();
    ctxB = await browser.newContext();
    alice = await ctxA.newPage();
    bob = await ctxB.newPage();
  });

  test.afterAll(async () => {
    await ctxA.close();
    await ctxB.close();
  });

  test("Alice creates a node and generates an invite", async () => {
    await createAccount(alice, `alice${RUN_ID}`, `Alice-${RUN_ID}`);

    await alice.locator('[title="Join or Create Node"]').click();
    await alice.click(".modal-card button:has-text('Create a New Node')");
    await alice.fill('input[placeholder="My Community"]', NODE_NAME);
    await alice.click("button:has-text('Create Node')");
    await expect(alice.locator(`text=${NODE_NAME}`)).toBeVisible({ timeout: 10_000 });
  });

  test("Bob joins via invite link", async () => {
    // Alice: open server dropdown → Invite People → copy link text
    await alice.click(".server-header-button");
    await alice.click("button:has-text('Invite People')");
    const inviteLocator = alice.locator(".invite-link-text:not(.invite-link-loading)");
    await expect(inviteLocator).toBeVisible({ timeout: 10_000 });
    const invite = (await inviteLocator.textContent())?.trim();
    expect(invite).toBeTruthy();
    await alice.keyboard.press("Escape");

    await createAccount(bob, `bob${RUN_ID}`, `Bob-${RUN_ID}`);
    await bob.locator('[title="Join or Create Node"]').click();
    await bob.fill('input[placeholder*="accord://"]', invite!);
    await bob.click("button:has-text('Join Node')");
    await expect(bob.locator(`text=${NODE_NAME}`)).toBeVisible({ timeout: 15_000 });
  });

  test("channel messages decrypt on both sides", async () => {
    // Give sender key distributions a moment to propagate after join
    const inputA = alice.locator("textarea.message-input");
    await expect(inputA).toBeVisible({ timeout: 10_000 });
    await inputA.fill(ALICE_MESSAGE);
    await inputA.press("Enter");
    await expect(alice.locator(`.message-content:has-text("${ALICE_MESSAGE}")`)).toBeVisible({ timeout: 10_000 });

    // Bob must see Alice's message decrypted (sender key delivered on join)
    await expect(bob.locator(`.message-content:has-text("${ALICE_MESSAGE}")`)).toBeVisible({ timeout: 20_000 });

    // And the reverse direction
    const inputB = bob.locator("textarea.message-input");
    await expect(inputB).toBeVisible({ timeout: 10_000 });
    await inputB.fill(BOB_MESSAGE);
    await inputB.press("Enter");
    await expect(bob.locator(`.message-content:has-text("${BOB_MESSAGE}")`)).toBeVisible({ timeout: 10_000 });
    await expect(alice.locator(`.message-content:has-text("${BOB_MESSAGE}")`)).toBeVisible({ timeout: 20_000 });
  });
});
