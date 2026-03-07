const { chromium } = require('@playwright/test');
(async () => {
  const browser1 = await chromium.launch({ headless: true });
  const browser2 = await chromium.launch({ headless: true });
  
  async function setup(browser, name) {
    const page = await browser.newPage();
    await page.goto('http://127.0.0.1:8443');
    await page.waitForTimeout(3000);
    await page.click('text=Create Identity');
    await page.waitForTimeout(1000);
    await page.fill('input:first-of-type', name);
    const inputs = await page.locator('input[type=password]').all();
    await inputs[0].fill('Clawbitch2026!');
    await inputs[1].fill('Clawbitch2026!');
    await page.click('text=Generate Identity');
    await page.waitForTimeout(3000);
    await page.click('text=Continue');
    await page.waitForTimeout(2000);
    await page.locator('input[type=text]').first().fill('accord://MTkyLjE2OC4xLjMxOjg0NDM/ztOyIvwo');
    await page.click('text=Preview');
    await page.waitForTimeout(3000);
    const j = page.locator('button:has-text("Join")');
    if (await j.isVisible()) await j.click();
    await page.waitForTimeout(5000);
    return page;
  }

  const p1 = await setup(browser1, 'TestUser_CB');
  console.log('User 1 ready');
  const p2 = await setup(browser2, 'TestUser_CB');
  console.log('User 2 ready');

  const t1 = p1.locator('textarea').first();
  const t2 = p2.locator('textarea').first();

  await t1.fill('Message from TestUser_CB #1 - FIRST user');
  await p1.keyboard.press('Enter');
  console.log('U1 sent');
  await p1.waitForTimeout(2000);

  await t2.fill('Message from TestUser_CB #2 - SECOND user');
  await p2.keyboard.press('Enter');
  console.log('U2 sent');
  await p2.waitForTimeout(2000);

  await t1.fill('First user again - should NOT group with second');
  await p1.keyboard.press('Enter');
  console.log('U1 again');
  await p1.waitForTimeout(2000);

  await t2.fill('Second user again - different identity!');
  await p2.keyboard.press('Enter');
  console.log('U2 again');

  console.log('Both online, waiting 2 min...');
  await new Promise(r => setTimeout(r, 120000));
  await browser1.close();
  await browser2.close();
})().catch(e => console.error(e));
