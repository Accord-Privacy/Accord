import { test, expect, Page, BrowserContext } from "@playwright/test";

// Two-client verification of metadata privacy (NMK, Phase 2):
// - Alice creates a node → her client derives the NMK and publishes encrypted
//   name/description/channel-name blobs to the relay
// - Bob joins and exchanges a message → the NMK rides the sender-key
//   distribution over Double Ratchet, so Bob's client can decrypt names
// The relay-side check (encrypted_name blobs present, undecryptable without
// the NMK) lives in scripts/verify-metadata-privacy.sh style sqlite queries —
// here we assert both clients hold the NMK and decrypted metadata.
const RUN_ID = Date.now().toString(36);
const PASSWORD = "testpass1234";
const NODE_NAME = `NMKNode-${RUN_ID}`;
const NODE_DESC = `nmk-secret-desc-${RUN_ID}`;
const PING = `nmk-ping-${RUN_ID}`;

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

/** True once the client has persisted an NMK store for the logged-in user. */
async function hasNmkStore(page: Page): Promise<boolean> {
  return page.evaluate(() => {
    const userId = localStorage.getItem("accord_user_id");
    return !!userId && !!localStorage.getItem(`accord_e2ee_nmk_${userId}`);
  });
}

test.describe.serial("Metadata privacy — NMK (two clients)", () => {
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

  test("Alice creates a node, derives the NMK, and publishes encrypted metadata", async () => {
    await createAccount(alice, `nmka${RUN_ID}`, `NmkAlice-${RUN_ID}`);

    await alice.locator('[title="Join or Create Node"]').click();
    await alice.click(".modal-card button:has-text('Create a New Node')");
    await alice.fill('input[placeholder="My Community"]', NODE_NAME);
    const descInput = alice.locator('textarea[placeholder*="description"], input[placeholder*="description"]').first();
    if (await descInput.isVisible().catch(() => false)) {
      await descInput.fill(NODE_DESC);
    }
    await alice.click("button:has-text('Create Node')");
    await expect(alice.locator(`text=${NODE_NAME}`)).toBeVisible({ timeout: 10_000 });

    // Creator derives + persists the NMK
    await expect.poll(() => hasNmkStore(alice), { timeout: 10_000 }).toBe(true);
  });

  test("Bob joins and receives the NMK over Double Ratchet", async () => {
    await alice.click(".server-header-button");
    await alice.click("button:has-text('Invite People')");
    const inviteLocator = alice.locator(".invite-link-text:not(.invite-link-loading)");
    await expect(inviteLocator).toBeVisible({ timeout: 10_000 });
    const invite = (await inviteLocator.textContent())?.trim();
    expect(invite).toBeTruthy();
    await alice.keyboard.press("Escape");

    await createAccount(bob, `nmkb${RUN_ID}`, `NmkBob-${RUN_ID}`);
    await bob.locator('[title="Join or Create Node"]').click();
    await bob.fill('input[placeholder*="accord://"]', invite!);
    await bob.click("button:has-text('Join Node')");
    await expect(bob.locator(`text=${NODE_NAME}`)).toBeVisible({ timeout: 15_000 });

    // Exchange one message so sender-key + NMK distribution fires both ways
    const inputA = alice.locator("textarea.message-input");
    await expect(inputA).toBeVisible({ timeout: 10_000 });
    await inputA.fill(PING);
    await inputA.press("Enter");
    await expect(bob.locator(`.message-content:has-text("${PING}")`)).toBeVisible({ timeout: 20_000 });

    // Bob must now hold the NMK (received over DR, persisted encrypted)
    await expect.poll(() => hasNmkStore(bob), { timeout: 20_000 }).toBe(true);
  });
});
