import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { webcrypto } from 'node:crypto';
import { resolve } from 'node:path';

const { chromium } = createRequire(import.meta.url)('playwright');
const root = resolve(new URL('..', import.meta.url).pathname);
const webRoot = resolve(root, 'web');
const b64 = value => Buffer.from(value).toString('base64url');
const pair = await webcrypto.subtle.generateKey(
  { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true,
  ['encrypt', 'decrypt'],
);
const publicKey = await webcrypto.subtle.exportKey('jwk', pair.publicKey);

const checkout = {
  v: 3,
  id: 'sh_frontend_checkout',
  publicKey,
  expiresAt: Date.now() + 300000,
  origin: 'https://checkout.example',
  provider: 'generic',
  stage: 'checkout_details',
  mode: 'checkout',
  actionLabel: 'Review purchase',
  demo: false,
  fields: [
    { id: 'f0', label: 'Billing name', type: 'text', required: true, autocomplete: 'name' },
    { id: 'f1', label: 'Billing email', type: 'email', required: true, autocomplete: 'email' },
    { id: 'f2', label: 'Card number', type: 'card_number', required: true, autocomplete: 'cc-number', inputMode: 'numeric' },
    { id: 'f3', label: 'Expiration date', type: 'card_expiry', required: true, autocomplete: 'cc-exp', inputMode: 'numeric' },
    { id: 'f4', label: 'Security code', type: 'cvc', required: true, autocomplete: 'cc-csc', inputMode: 'numeric' },
    { id: 'f5', label: 'Country', type: 'select', required: true, options: [{ value: '', label: 'Choose a country' }, { value: 'US', label: 'United States' }] },
  ],
};

const confirmation = {
  v: 3,
  id: 'sh_frontend_confirmation',
  publicKey,
  expiresAt: Date.now() + 300000,
  origin: 'https://checkout.example',
  provider: 'generic',
  stage: 'payment_confirmation',
  mode: 'payment_confirmation',
  actionLabel: 'Authorize purchase',
  demo: false,
  fields: [],
};

const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname;
  const file = pathname === '/' ? 'index.html' : pathname.slice(1);
  try {
    const body = await readFile(resolve(webRoot, file));
    response.writeHead(200, { 'content-type': file.endsWith('.js') ? 'application/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html' });
    response.end(body);
  } catch {
    response.writeHead(404);
    response.end();
  }
});
await new Promise(resolveServer => server.listen(0, '127.0.0.1', resolveServer));
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', headless: true });

async function decryptEnvelope(raw, id) {
  const envelope = JSON.parse(raw);
  const rawKey = await webcrypto.subtle.decrypt({ name: 'RSA-OAEP' }, pair.privateKey, Buffer.from(envelope.wrappedKey, 'base64url'));
  const aes = await webcrypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const plain = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: Buffer.from(envelope.iv, 'base64url'), additionalData: Buffer.from(id) },
    aes,
    Buffer.from(envelope.ciphertext, 'base64url'),
  );
  return JSON.parse(Buffer.from(plain).toString());
}

try {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await page.route('https://telegram.org/js/telegram-web-app.js', route => route.fulfill({
    status: 200,
    contentType: 'application/javascript',
    body: "window.Telegram={WebView:{initParams:{tgWebAppData:''}},WebApp:{platform:'tdesktop',initData:'',initDataUnsafe:{},ready(){},sendData(v){window.__sent=v}}}",
  }));
  const base = `http://127.0.0.1:${server.address().port}/`;
  await page.goto(`${base}#request=${b64(JSON.stringify(checkout))}&tgWebAppVersion=9.6`, { waitUntil: 'networkidle' });
  assert.match(await page.locator('#page-title').textContent(), /Enter checkout details/);
  assert.equal(await page.locator('#field-list input').count(), 5);
  assert.equal(await page.locator('#field-f1').getAttribute('autocomplete'), 'email');
  assert.equal(await page.locator('#field-f2').getAttribute('autocomplete'), 'cc-number');
  assert.equal(await page.locator('#field-f2').getAttribute('inputmode'), 'numeric');
  assert.equal(await page.locator('#field-f4').getAttribute('autocomplete'), 'cc-csc');
  assert.equal(await page.locator('#field-f5').locator('option').count(), 2);
  assert.equal(await page.getByRole('button', { name: 'Review purchase' }).count(), 1);

  await page.locator('#field-f0').fill('Synthetic User');
  await page.locator('#field-f1').fill('synthetic@example.invalid');
  await page.locator('#field-f2').fill('synthetic-card-number');
  await page.locator('#field-f3').fill('synthetic-expiry');
  await page.locator('#field-f4').fill('synthetic-cvc');
  await page.locator('#field-f5').selectOption('US');
  await page.getByRole('button', { name: 'Review purchase' }).click();
  await page.waitForFunction(() => typeof window.__sent === 'string');
  assert.deepEqual(await decryptEnvelope(await page.evaluate(() => window.__sent), checkout.id), {
    values: {
      f0: 'Synthetic User',
      f1: 'synthetic@example.invalid',
      f2: 'synthetic-card-number',
      f3: 'synthetic-expiry',
      f4: 'synthetic-cvc',
      f5: 'US',
    },
  });
  assert.equal(await page.locator('#field-f2').inputValue(), '');

  await page.goto('about:blank');
  await page.goto(`${base}#request=${b64(JSON.stringify(confirmation))}&tgWebAppVersion=9.6`, { waitUntil: 'networkidle' });
  assert.match(await page.locator('#page-title').textContent(), /Authorize purchase/);
  assert.equal(await page.locator('#field-list input').count(), 0);
  await page.getByRole('button', { name: 'Authorize purchase' }).click();
  await page.waitForFunction(() => typeof window.__sent === 'string');
  assert.deepEqual(await decryptEnvelope(await page.evaluate(() => window.__sent), confirmation.id), { confirm: true });
  console.log('frontend checkout browser test: PASS');
} finally {
  await browser.close();
  await new Promise(resolveServer => server.close(resolveServer));
}
