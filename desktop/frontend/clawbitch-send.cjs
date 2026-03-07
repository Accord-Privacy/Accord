const { chromium } = require('@playwright/test');
const msg = process.argv[2] || 'Hello from Clawbitch!';
const STORAGE = '/tmp/clawbitch-accord-state.json';
const fs = require('fs');

(async () => {
  const browser = await chromium.launch({ headless: true });
  let context;
  
  if (fs.existsSync(STORAGE)) {
    context = await browser.newContext({ storageState: STORAGE });
    console.log('Reusing saved session');
  } else {
    context = await browser.newContext();
    console.log('Fresh session');
  }
  
  const page = await context.newPage();
  
  // Log console messages for debugging
  page.on('console', msg => {
    if (msg.type() === 'error' || msg.text().includes('E2EE') || msg.text().includes('WebSocket') || msg.text().includes('sender key')) {
      console.log(`[browser] ${msg.text()}`);
    }
  });
  
  await page.goto('http://127.0.0.1:8443');
  await page.waitForTimeout(3000);
  
  const bodyText = await page.textContent('body');
  
  // If we need to create identity
  if (bodyText.includes('Create Identity') || bodyText.includes('Recover Identity')) {
    console.log('Creating new identity...');
    await page.click('text=Create Identity');
    await page.waitForTimeout(1000);
    await page.fill('input:first-of-type', 'Clawbitch');
    const inputs = await page.locator('input[type=password]').all();
    await inputs[0].fill('Clawbitch2026!');
    await inputs[1].fill('Clawbitch2026!');
    await page.click('text=Generate Identity');
    await page.waitForTimeout(3000);
    await page.click('text=Continue');
    await page.waitForTimeout(2000);
    
    // Join node
    const inviteInput = page.locator('input[type=text]').first();
    await inviteInput.fill('accord://MTkyLjE2OC4xLjMxOjg0NDM/HBmDL2gC');
    await page.click('text=Preview');
    await page.waitForTimeout(3000);
    const joinBtn = page.locator('button:has-text("Join")');
    if (await joinBtn.isVisible()) {
      await joinBtn.click();
      console.log('Joined node');
    }
    await page.waitForTimeout(5000);
    
    // Save state immediately after setup
    await context.storageState({ path: STORAGE });
    console.log('Session state saved');
  }
  
  // Wait for channel to fully load and WebSocket to connect
  await page.waitForTimeout(5000);
  
  // Check if we're on a channel
  const hasTextarea = await page.locator('textarea').first().isVisible().catch(() => false);
  if (!hasTextarea) {
    // Might need to click on #general
    const generalLink = page.locator('text=#general, text=general').first();
    if (await generalLink.isVisible()) {
      await generalLink.click();
      await page.waitForTimeout(2000);
    }
  }
  
  // Send message
  const textarea = page.locator('textarea').first();
  if (await textarea.isVisible()) {
    await textarea.fill(msg);
    await page.keyboard.press('Enter');
    console.log('Sent:', msg);
  } else {
    const currentText = await page.textContent('body');
    console.log('No textarea found. Page state:', currentText.substring(0, 500));
  }
  
  // Save state after sending
  await context.storageState({ path: STORAGE });
  
  // Stay alive for sender key distribution to propagate
  console.log('Waiting 15s for E2EE key exchange...');
  await page.waitForTimeout(15000);
  await browser.close();
})().catch(e => console.error(e));
