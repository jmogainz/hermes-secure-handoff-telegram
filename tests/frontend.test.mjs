import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { webcrypto } from 'node:crypto';
import { resolve } from 'node:path';

const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch (error) {
  console.error('Playwright is required to run tests/frontend.test.mjs.');
  console.error(error.message);
  process.exit(2);
}

const root = resolve(new URL('..', import.meta.url).pathname);
const webRoot = resolve(root, 'web');
const MARKER = 'telegram-roundtrip-ok';

function encodeBase64Url(value) {
  return Buffer.from(value).toString('base64url');
}

function requestFragment({ id = 'frontend-test-01', expiresAt = Date.now() + 5 * 60 * 1000, publicKey }) {
  return `#request=${encodeBase64Url(JSON.stringify({ v: 1, id, publicKey, expiresAt }))}`;
}

function requestFragmentWithParams(options) {
  return `${requestFragment(options)}&tgWebAppVersion=9.6&tgWebAppPlatform=ios&tgWebAppThemeParams=%7B%7D`;
}

function entryRequestFragment({ publicKey, fields, view, expiresAt = Date.now() + 5 * 60 * 1000 }) {
  const request = {
    v: 4,
    id: `sh_${'S'.repeat(32)}`,
    kind: 'entry',
    origin: 'https://fixture.example',
    expiresAt,
    publicKey,
    fields,
  };
  if (view !== undefined) request.view = view;
  return `#request=${encodeBase64Url(JSON.stringify(request))}&tgWebAppVersion=9.6&tgWebAppPlatform=ios`;
}

async function decryptV4(payload, privateKey) {
  const rawKey = await webcrypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    Buffer.from(payload.wrappedKey, 'base64url'),
  );
  const aes = await webcrypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const plaintext = await webcrypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: Buffer.from(payload.iv, 'base64url'),
      additionalData: new TextEncoder().encode(payload.id),
    },
    aes,
    Buffer.from(payload.ciphertext, 'base64url'),
  );
  return JSON.parse(Buffer.from(plaintext).toString('utf8'));
}

async function makeKeyPair() {
  return webcrypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
}

function makeServer() {
  return createServer(async (request, response) => {
    const pathname = new URL(request.url, 'http://127.0.0.1').pathname;
    const relativePath = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '');
    const filePath = resolve(webRoot, relativePath);
    if (!filePath.startsWith(`${webRoot}/`)) {
      response.writeHead(404);
      response.end('Not found');
      return;
    }

    try {
      const body = await readFile(filePath);
      const contentType = relativePath.endsWith('.html') ? 'text/html; charset=utf-8'
        : relativePath.endsWith('.css') ? 'text/css; charset=utf-8'
          : 'application/javascript; charset=utf-8';
      response.writeHead(200, { 'content-type': contentType });
      response.end(body);
    } catch {
      response.writeHead(404);
      response.end('Not found');
    }
  });
}

async function installTelegramStub(page, { supported = true } = {}) {
  await page.route('https://telegram.org/js/telegram-web-app.js', async (route) => {
    const script = supported
      ? `window.Telegram = { WebView: { initParams: { tgWebAppData: '' } }, WebApp: { platform: 'tdesktop', initData: '', initDataUnsafe: {}, ready() {}, sendData(value) { window.__frontendSentData = value; } } };`
      : `window.Telegram = { WebView: { initParams: { tgWebAppData: '' } }, WebApp: { platform: 'unknown', initData: '', initDataUnsafe: {}, sendData() {} } };`;
    await route.fulfill({
      status: 200,
      contentType: 'application/javascript',
      body: script,
    });
  });
}

async function delayFirstEncrypt(page) {
  await page.evaluate(() => {
    const original = crypto.subtle.encrypt.bind(crypto.subtle);
    let release;
    let delayed = false;
    window.__releaseCrypto = () => release?.();
    crypto.subtle.encrypt = async (...args) => {
      if (delayed) return original(...args);
      delayed = true;
      window.__cryptoStarted = true;
      await new Promise((resolve) => { release = resolve; });
      try { return await original(...args); }
      finally { window.__cryptoFinished = true; }
    };
  });
}

async function assertNoOverflow(page, width, height) {
  await page.setViewportSize({ width, height });
  const metrics = await page.evaluate(() => ({
    viewportWidth: window.innerWidth,
    documentWidth: document.documentElement.scrollWidth,
    bodyWidth: document.body.scrollWidth,
  }));
  assert.equal(metrics.documentWidth, metrics.viewportWidth, `document overflows at ${width}x${height}`);
  assert.equal(metrics.bodyWidth, metrics.viewportWidth, `body overflows at ${width}x${height}`);
}

async function main() {
  const vercel = JSON.parse(await readFile(resolve(webRoot, 'vercel.json'), 'utf8'));
  const csp = vercel.headers?.[0]?.headers?.find((header) => header.key === 'Content-Security-Policy')?.value ?? '';
  assert.match(csp, /script-src 'self' https:\/\/telegram\.org/);
  assert.match(csp, /connect-src 'none'/);
  const html = await readFile(resolve(webRoot, 'index.html'), 'utf8');
  assert.match(html, /https:\/\/telegram\.org\/js\/telegram-web-app\.js/);
  assert.doesNotMatch(html, /<(?:input|textarea|select)\b/i);

  const keyPair = await makeKeyPair();
  const publicKey = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
  const server = makeServer();
  await new Promise((resolveServer) => server.listen(0, '127.0.0.1', resolveServer));
  const { port } = server.address();
  const browser = await chromium.launch({
    channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome',
    headless: true,
    ...(process.env.PLAYWRIGHT_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_EXECUTABLE_PATH } : {}),
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

  try {
    await installTelegramStub(page);
    await page.goto(`http://127.0.0.1:${port}/${requestFragmentWithParams({ publicKey })}`, { waitUntil: 'networkidle' });
    await assertNoOverflow(page, 1440, 900);
    await assertNoOverflow(page, 768, 1024);
    await assertNoOverflow(page, 390, 844);
    assert.equal(await page.locator('input, textarea, select').count(), 0, 'secure controls must not exist before a request');
    assert.equal(await page.locator('#credential-form').count(), 1, 'semantic empty form wrapper should exist');
    assert.match(await page.locator('#status-kicker').textContent(), /Ready to verify/);
    assert.match(await page.getByRole('button', { name: 'Send the connection test' }).textContent(), /Send test/);
    assert.doesNotMatch(await page.locator('body').innerText(), /telegram-roundtrip-ok/);

    await page.getByRole('button', { name: 'Send the connection test' }).click();
    await page.waitForFunction(() => typeof window.__frontendSentData === 'string');
    const sentPayload = await page.evaluate(() => JSON.parse(window.__frontendSentData));
    assert.deepEqual(Object.keys(sentPayload), ['v', 'id', 'ciphertext']);
    assert.equal(sentPayload.v, 1);
    assert.equal(sentPayload.id, 'frontend-test-01');
    assert.ok(/^[A-Za-z0-9_-]+$/.test(sentPayload.ciphertext));
    assert.ok(Buffer.byteLength(JSON.stringify(sentPayload), 'utf8') <= 4096);
    const plaintext = await webcrypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      keyPair.privateKey,
      Buffer.from(sentPayload.ciphertext, 'base64url'),
    );
    assert.equal(Buffer.from(plaintext).toString('ascii'), MARKER);
    assert.match(await page.locator('#status-kicker').textContent(), /Sending/);
    assert.doesNotMatch(await page.locator('#status-message').textContent(), /success|successful/i);

    const segmented = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await installTelegramStub(segmented);
    await segmented.goto(`http://127.0.0.1:${port}/${entryRequestFragment({
      publicKey,
      fields: [{
        id: 'f0',
        label: 'Verification code',
        type: 'tel',
        required: true,
        strategy: 'keyboard',
        component: { kind: 'segmented_code', length: 6, alphabet: 'digits' },
      }],
      view: {
        schema: 'secure-handoff.ui/1',
        kind: 'stack',
        children: [
          { kind: 'text', text: '<img src=x> stays text', tone: 'muted' },
          { kind: 'section', title: 'Verification', children: [{ kind: 'field', field: 'f0' }] },
          { kind: 'divider' },
        ],
      },
    })}`, { waitUntil: 'networkidle' });
    assert.equal(await segmented.locator('.view-stack > .view-text').textContent(), '<img src=x> stays text');
    assert.equal(await segmented.locator('.view-section').count(), 1);
    assert.equal(await segmented.locator('.view-divider').count(), 1);
    assert.equal(await segmented.locator('#field-list img').count(), 0, 'view text must never become HTML');
    const code = segmented.locator('[data-component="segmented_code"]');
    assert.equal(await code.count(), 1, 'segmented-code component must render exactly one plaintext input');
    assert.equal(await code.getAttribute('maxlength'), null, 'segmented input must preserve overlong raw sequences');
    assert.equal(await code.getAttribute('minlength'), '6');
    assert.equal(await code.getAttribute('inputmode'), 'numeric');
    assert.equal(await segmented.locator('#credential-form').getAttribute('autocomplete'), 'off');
    assert.equal(await code.getAttribute('autocomplete'), 'off', 'bridge-origin autofill must stay disabled');
    assert.equal(await code.getAttribute('aria-label'), 'Verification code');
    assert.match(await code.getAttribute('aria-describedby'), /field-f0-hint/);
    await code.pressSequentially('123-456');
    assert.equal(await code.inputValue(), '123-456', 'component must not silently truncate or rewrite owner input');
    assert.equal(await code.evaluate((input) => input.checkValidity()), false);
    await segmented.getByRole('button', { name: 'Send encrypted submission' }).click();
    assert.equal(await segmented.evaluate(() => typeof window.__frontendSentData), 'undefined');
    assert.equal(await code.getAttribute('aria-invalid'), 'true');
    assert.equal(await segmented.locator('#field-f0-error').isVisible(), true);
    assert.match(await segmented.locator('#page-title').textContent(), /check the highlighted field/i);
    await code.fill('123456');
    assert.equal(await code.evaluate((input) => input.checkValidity()), true);
    assert.equal(await segmented.locator('#field-f0-error').isHidden(), true);
    await assertNoOverflow(segmented, 390, 844);
    await segmented.getByRole('button', { name: 'Send encrypted submission' }).click();
    await segmented.waitForFunction(() => typeof window.__frontendSentData === 'string');
    const segmentedPayload = await segmented.evaluate(() => JSON.parse(window.__frontendSentData));
    assert.deepEqual(Object.keys(segmentedPayload), ['v', 'id', 'wrappedKey', 'iv', 'ciphertext']);
    assert.deepEqual(await decryptV4(segmentedPayload, keyPair.privateKey), { values: { f0: '123456' } });
    assert.equal(await code.inputValue(), '', 'plaintext component value must be cleared after sendData');
    await segmented.close();

    const oversizedBody = await browser.newPage();
    await installTelegramStub(oversizedBody);
    await oversizedBody.goto(`http://127.0.0.1:${port}/${entryRequestFragment({
      publicKey,
      fields: Array.from({ length: 4 }, (_, index) => ({
        id: `f${index}`,
        label: `Bounded field ${index + 1}`,
        type: 'text',
        required: true,
        strategy: 'keyboard',
      })),
    })}`, { waitUntil: 'networkidle' });
    for (const input of await oversizedBody.locator('#field-list input').all()) await input.fill('x'.repeat(512));
    await oversizedBody.getByRole('button', { name: 'Send encrypted submission' }).click();
    assert.equal(await oversizedBody.evaluate(() => typeof window.__frontendSentData), 'undefined');
    assert.match(await oversizedBody.locator('#page-title').textContent(), /could not be sent/i);
    assert.deepEqual(await oversizedBody.locator('#field-list input').evaluateAll((inputs) => inputs.map((input) => input.value)), ['', '', '', '']);
    await oversizedBody.close();

    const oversizedUtf8Body = await browser.newPage();
    await installTelegramStub(oversizedUtf8Body);
    await oversizedUtf8Body.goto(`http://127.0.0.1:${port}/${entryRequestFragment({
      publicKey,
      fields: Array.from({ length: 2 }, (_, index) => ({
        id: `f${index}`,
        label: `UTF-8 field ${index + 1}`,
        type: 'text',
        required: true,
        strategy: 'keyboard',
      })),
    })}`, { waitUntil: 'networkidle' });
    for (const input of await oversizedUtf8Body.locator('#field-list input').all()) await input.fill('é'.repeat(512));
    await oversizedUtf8Body.getByRole('button', { name: 'Send encrypted submission' }).click();
    assert.equal(await oversizedUtf8Body.evaluate(() => typeof window.__frontendSentData), 'undefined');
    assert.deepEqual(await oversizedUtf8Body.locator('#field-list input').evaluateAll((inputs) => inputs.map((input) => input.value)), ['', '']);
    await oversizedUtf8Body.close();

    const astralText = await browser.newPage();
    await installTelegramStub(astralText);
    const astralLabel = '🔐'.repeat(80);
    const astralValue = '🚀'.repeat(300);
    await astralText.goto(`http://127.0.0.1:${port}/${entryRequestFragment({
      publicKey,
      fields: [{ id: 'f0', label: astralLabel, type: 'text', required: true, strategy: 'keyboard' }],
    })}`, { waitUntil: 'networkidle' });
    assert.equal(await astralText.locator('label').first().textContent(), `${astralLabel}Required`);
    await astralText.locator('#field-f0').fill(astralValue);
    await astralText.getByRole('button', { name: 'Send encrypted submission' }).click();
    await astralText.waitForFunction(() => typeof window.__frontendSentData === 'string');
    const astralPayload = await astralText.evaluate(() => JSON.parse(window.__frontendSentData));
    assert.deepEqual(await decryptV4(astralPayload, keyPair.privateKey), { values: { f0: astralValue } });
    await astralText.close();

    const rowLayout = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await installTelegramStub(rowLayout);
    await rowLayout.goto(`http://127.0.0.1:${port}/${entryRequestFragment({
      publicKey,
      fields: [
        { id: 'f0', label: 'First', type: 'text', required: true, strategy: 'keyboard' },
        { id: 'f1', label: 'Second', type: 'text', required: true, strategy: 'keyboard' },
      ],
      view: {
        schema: 'secure-handoff.ui/1',
        kind: 'stack',
        children: [{
          kind: 'row',
          children: [{ kind: 'field', field: 'f0' }, { kind: 'field', field: 'f1' }],
        }],
      },
    })}`, { waitUntil: 'networkidle' });
    const desktopRow = await rowLayout.locator('.view-row .field-row').evaluateAll((nodes) => nodes.map((node) => node.getBoundingClientRect().top));
    assert.equal(desktopRow.length, 2);
    assert.ok(Math.abs(desktopRow[0] - desktopRow[1]) < 1, 'two-child row must share a line on desktop');
    await rowLayout.setViewportSize({ width: 390, height: 844 });
    const mobileRow = await rowLayout.locator('.view-row .field-row').evaluateAll((nodes) => nodes.map((node) => node.getBoundingClientRect().top));
    assert.ok(mobileRow[1] > mobileRow[0], 'two-child row must stack on mobile');
    await assertNoOverflow(rowLayout, 390, 844);
    await rowLayout.close();

    const cancelledCrypto = await browser.newPage();
    await installTelegramStub(cancelledCrypto);
    await cancelledCrypto.goto(`http://127.0.0.1:${port}/${entryRequestFragment({
      publicKey,
      fields: [{ id: 'f0', label: 'Secret', type: 'password', required: true, strategy: 'keyboard' }],
    })}`, { waitUntil: 'networkidle' });
    await cancelledCrypto.locator('#field-f0').fill('synthetic-secret');
    await delayFirstEncrypt(cancelledCrypto);
    await cancelledCrypto.getByRole('button', { name: 'Send encrypted submission' }).click();
    await cancelledCrypto.waitForFunction(() => window.__cryptoStarted === true);
    await cancelledCrypto.getByRole('button', { name: 'Cancel' }).click();
    await cancelledCrypto.evaluate(() => window.__releaseCrypto());
    await cancelledCrypto.waitForFunction(() => window.__cryptoFinished === true);
    assert.equal(await cancelledCrypto.evaluate(() => typeof window.__frontendSentData), 'undefined');
    assert.equal(await cancelledCrypto.locator('#field-f0').inputValue(), '');
    await cancelledCrypto.close();

    for (const lifecycleEvent of ['pagehide', 'freeze']) {
      const interruptedCrypto = await browser.newPage();
      await installTelegramStub(interruptedCrypto);
      await interruptedCrypto.goto(`http://127.0.0.1:${port}/${entryRequestFragment({
        publicKey,
        fields: [{ id: 'f0', label: 'Secret', type: 'password', required: true, strategy: 'keyboard' }],
      })}`, { waitUntil: 'networkidle' });
      await interruptedCrypto.locator('#field-f0').fill('synthetic-secret');
      await delayFirstEncrypt(interruptedCrypto);
      await interruptedCrypto.getByRole('button', { name: 'Send encrypted submission' }).click();
      await interruptedCrypto.waitForFunction(() => window.__cryptoStarted === true);
      await interruptedCrypto.evaluate((eventName) => window.dispatchEvent(new Event(eventName)), lifecycleEvent);
      await interruptedCrypto.evaluate(() => window.__releaseCrypto());
      await interruptedCrypto.waitForFunction(() => window.__cryptoFinished === true);
      assert.equal(await interruptedCrypto.evaluate(() => typeof window.__frontendSentData), 'undefined');
      assert.equal(await interruptedCrypto.locator('#field-f0').inputValue(), '');
      await interruptedCrypto.close();
    }

    const expiringCrypto = await browser.newPage();
    await installTelegramStub(expiringCrypto);
    await expiringCrypto.goto(`http://127.0.0.1:${port}/${entryRequestFragment({
      publicKey,
      expiresAt: Date.now() + 2000,
      fields: [{ id: 'f0', label: 'Secret', type: 'password', required: true, strategy: 'keyboard' }],
    })}`, { waitUntil: 'networkidle' });
    await expiringCrypto.locator('#field-f0').fill('synthetic-secret');
    await delayFirstEncrypt(expiringCrypto);
    await expiringCrypto.getByRole('button', { name: 'Send encrypted submission' }).click();
    await expiringCrypto.waitForFunction(() => window.__cryptoStarted === true);
    await expiringCrypto.waitForFunction(
      () => document.querySelectorAll('input, textarea, select').length === 0,
      null,
      { timeout: 3000 },
    );
    await expiringCrypto.evaluate(() => window.__releaseCrypto());
    await expiringCrypto.waitForFunction(() => window.__cryptoFinished === true);
    assert.equal(await expiringCrypto.evaluate(() => typeof window.__frontendSentData), 'undefined');
    await expiringCrypto.close();

    const invalidView = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await installTelegramStub(invalidView);
    await invalidView.goto(`http://127.0.0.1:${port}/${entryRequestFragment({
      publicKey,
      fields: [{
        id: 'f0', label: 'Verification code', type: 'tel', required: true, strategy: 'keyboard',
        component: { kind: 'segmented_code', length: 6, alphabet: 'digits' },
      }],
      view: {
        schema: 'secure-handoff.ui/1',
        kind: 'stack',
        children: [{ kind: 'field', field: 'f0' }, { kind: 'field', field: 'f0' }],
      },
    })}`, { waitUntil: 'networkidle' });
    assert.match(await invalidView.locator('#page-title').textContent(), /link is not valid/i);
    assert.equal(await invalidView.locator('input, textarea, select').count(), 0);
    await invalidView.close();

    for (const invalidLabel of [
      'https://evil.invalid',
      'Continue at //evil.invalid',
      'Verification\u200b code',
      'Verification\u0085 code',
      'Paypa\u3164l security',
      'Broken\ud800 label',
    ]) {
      const invalidText = await browser.newPage();
      await installTelegramStub(invalidText);
      const invalidTextFragment = entryRequestFragment({
        publicKey,
        fields: [{ id: 'f0', label: invalidLabel, type: 'text', required: true, strategy: 'keyboard' }],
      });
      await invalidText.goto(`http://127.0.0.1:${port}/${invalidTextFragment}`);
      assert.match(await invalidText.locator('#page-title').textContent(), /link is not valid/i);
      assert.equal(await invalidText.locator('input, textarea, select').count(), 0);
      await invalidText.close();
    }

    const duplicateJson = JSON.stringify({
      v: 4,
      id: `sh_${'D'.repeat(32)}`,
      kind: 'entry',
      origin: 'https://fixture.example',
      expiresAt: Date.now() + 5 * 60 * 1000,
      publicKey,
      fields: [{ id: 'f0', label: 'Code', type: 'text', required: true, strategy: 'keyboard' }],
    });
    for (const raw of [
      duplicateJson.replace('"kind":"entry"', '"kind":"entry","kind":"entry"'),
      duplicateJson.replace('"label":"Code"', '"label":"Code","label":"Code"'),
    ]) {
      const duplicateKeys = await browser.newPage();
      await installTelegramStub(duplicateKeys);
      await duplicateKeys.goto(
        `http://127.0.0.1:${port}/#request=${encodeBase64Url(raw)}&tgWebAppVersion=9.6&tgWebAppPlatform=ios`,
      );
      assert.match(await duplicateKeys.locator('#page-title').textContent(), /link is not valid/i);
      assert.equal(await duplicateKeys.locator('input, textarea, select').count(), 0);
      await duplicateKeys.close();
    }

    const expiring = await browser.newPage();
    await installTelegramStub(expiring);
    await expiring.goto(`http://127.0.0.1:${port}/${entryRequestFragment({
      publicKey,
      expiresAt: Date.now() + 350,
      fields: [{
        id: 'f0', label: 'Verification code', type: 'tel', required: true, strategy: 'keyboard',
        component: { kind: 'segmented_code', length: 6, alphabet: 'digits' },
      }],
    })}`);
    await expiring.locator('[data-component="segmented_code"]').fill('654321');
    await expiring.waitForFunction(
      () => document.querySelectorAll('input, textarea, select').length === 0,
      null,
      { timeout: 3000 },
    );
    assert.equal(await expiring.locator('#page-title').textContent(), 'This handoff link has expired');
    assert.equal(await expiring.evaluate(() => typeof window.__frontendSentData), 'undefined');
    await expiring.close();

    const missing = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await installTelegramStub(missing);
    await missing.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'networkidle' });
    assert.match(await missing.locator('#page-title').textContent(), /link is missing/i);
    await missing.close();

    const outside = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await installTelegramStub(outside, { supported: false });
    await outside.goto(`http://127.0.0.1:${port}/${requestFragment({ publicKey })}`, { waitUntil: 'networkidle' });
    assert.match(await outside.locator('#page-title').textContent(), /Open this in Telegram/i);
    assert.equal(await outside.locator('#send-button').evaluate((button) => button.hidden), true);
    await outside.close();

    const expired = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await installTelegramStub(expired);
    await expired.goto(`http://127.0.0.1:${port}/${requestFragment({ publicKey, expiresAt: Date.now() - 1 })}`, { waitUntil: 'networkidle' });
    assert.match(await expired.locator('#page-title').textContent(), /link has expired/i);
    assert.equal(await expired.locator('#send-button').evaluate((button) => button.hidden), true);
    await expired.close();

    const invalid = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await installTelegramStub(invalid);
    await invalid.goto(`http://127.0.0.1:${port}/#request=${encodeBase64Url(JSON.stringify({ v: 1, id: 'not valid', publicKey, expiresAt: Date.now() + 60_000 }))}`, { waitUntil: 'networkidle' });
    assert.match(await invalid.locator('#page-title').textContent(), /link is not valid/i);
    await invalid.close();

    const duplicate = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await installTelegramStub(duplicate);
    const duplicateRequest = requestFragment({ publicKey });
    await duplicate.goto(`http://127.0.0.1:${port}/${duplicateRequest}&request=${duplicateRequest.slice('#request='.length)}`, { waitUntil: 'networkidle' });
    assert.match(await duplicate.locator('#page-title').textContent(), /link is not valid/i);
    assert.equal(await duplicate.locator('#send-button').evaluate((button) => button.hidden), true);
    await duplicate.close();

    console.log('frontend browser test: PASS');
    console.log('checked RSA-OAEP round trip, 4096-byte cap, no credential controls, CSP, responsive overflow, and missing/outside/expired/invalid states');
  } finally {
    await browser.close();
    await new Promise((resolveServer) => server.close(resolveServer));
  }
}

main().catch((error) => {
  console.error(`frontend browser test: FAIL — ${error.message}`);
  process.exitCode = 1;
});
