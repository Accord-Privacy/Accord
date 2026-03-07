const { chromium } = require('@playwright/test');
const msg = process.argv[2] || 'Hello from Clawbitch!';
const STORAGE = '/tmp/clawbitch-accord-state.json';
const fs = require('fs');

(async () => {
  const browser = await chromium.launch({ headless: true });
  let context;
  
  if (fs.existsSync(STORAGE)) {
    context = await browser.newContext({ storageState: STORAGE });
  } else {
    context = await browser.newContext();
  }
  
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:8443');
  await page.waitForTimeout(3000);
  
  const bodyText = await page.textContent('body');
  
  // If we need to create identity
  if (bodyText.includes('Create Identity')) {
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
    await page.locator('input[type=text]').first().fill('accord://MTI3LjAuMC4xOjg0NDM/HBmDL2gC');
    await page.click('text=Preview');
    await page.waitForTimeout(3000);
    await page.click('text=Join');
    await page.waitForTimeout(5000);
  }
  
  // Wait for general channel to load
  await page.waitForTimeout(2000);
  
  // Send message
  const textarea = page.locator('textarea').first();
  if (await textarea.isVisible()) {
    await textarea.fill(msg);
    await page.keyboard.press('Enter');
    console.log('Sent:', msg);
  } else {
    console.log('No textarea found. Page state:', bodyText.substring(0, 300));
  }
  
  // Save state
  await context.storageState({ path: STORAGE });
  
  // Stay alive briefly for E2EE key exchange
  await page.waitForTimeout(10000);
  await browser.close();
})().catch(e => console.error(e));
