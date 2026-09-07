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
