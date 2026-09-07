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
const pair = await webcrypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
const publicKey = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
const request = { v: 3, id: 'sh_frontend_auth', publicKey, expiresAt: Date.now() + 300000, origin: 'https://demo.example', provider: 'generic', stage: 'identifier', mode: 'auth', actionLabel: 'Submit to browser', demo: true, fields: [
  { id: 'f0', label: 'Username or email', type: 'text', required: true },
  { id: 'f1', label: 'Password', type: 'password', required: true },
] };
const server = createServer(async (req, res) => {
  const file = new URL(req.url, 'http://127.0.0.1').pathname === '/' ? 'index.html' : new URL(req.url, 'http://127.0.0.1').pathname.slice(1);
  try { res.writeHead(200, { 'content-type': file.endsWith('.js') ? 'application/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(await readFile(resolve(webRoot, file))); }
  catch { res.writeHead(404); res.end(); }
});
await new Promise(resolveServer => server.listen(0, '127.0.0.1', resolveServer));
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', headless: true });
try {
  const page = await browser.newPage();
  await page.route('https://telegram.org/js/telegram-web-app.js', route => route.fulfill({ status: 200, contentType: 'application/javascript', body: "window.Telegram={WebView:{initParams:{tgWebAppData:''}},WebApp:{platform:'tdesktop',initData:'',initDataUnsafe:{},ready(){},sendData(v){window.__sent=v}}}" }));
  await page.goto(`http://127.0.0.1:${server.address().port}/#request=${b64(JSON.stringify(request))}&tgWebAppVersion=9.6`, { waitUntil: 'networkidle' });
  assert.equal(await page.locator('#field-list input').count(), 2);
  assert.match(await page.locator('#page-title').textContent(), /Enter account identifier/);
  assert.match(await page.locator('#status-message').textContent(), /username or email/);
  assert.equal(await page.locator('#credential-form').getAttribute('autocomplete'), 'on');
  assert.equal(await page.locator('#field-f0').getAttribute('autocomplete'), 'username');
  assert.equal(await page.locator('#field-f0').getAttribute('name'), 'username');
  assert.equal(await page.locator('#field-f1').getAttribute('autocomplete'), 'current-password');
  assert.equal(await page.locator('#field-f1').getAttribute('name'), 'password');
  assert.match(await page.locator('#request-origin').textContent(), /^https:\/\/demo\.example$/);
  assert.match(await page.locator('body').innerText(), /Demo example: demo/);
  assert.match(await page.locator('body').innerText(), /Demo example: demo-pass/);
  await page.getByRole('button', { name: 'Submit to browser' }).click();
  assert.equal(await page.locator('.app-card').getAttribute('data-state'), 'secureReady');
  assert.equal(await page.locator('#field-f0').isVisible(), true);
  assert.equal(await page.locator('#field-f0').evaluate(input => input === document.activeElement), true);
  assert.equal(await page.evaluate(() => window.__sent), undefined);
  await page.locator('#field-f0').fill('demo');
  await page.locator('#field-f1').fill('demo-pass');
  await page.getByRole('button', { name: 'Submit to browser' }).click();
  await page.waitForFunction(() => typeof window.__sent === 'string');
  const envelope = JSON.parse(await page.evaluate(() => window.__sent));
  assert.deepEqual(Object.keys(envelope), ['v', 'id', 'wrappedKey', 'iv', 'ciphertext']);
  const raw = await webcrypto.subtle.decrypt({ name: 'RSA-OAEP' }, pair.privateKey, Buffer.from(envelope.wrappedKey, 'base64url'));
  const aes = await webcrypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
  const plain = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(envelope.iv, 'base64url'), additionalData: Buffer.from(request.id) }, aes, Buffer.from(envelope.ciphertext, 'base64url'));
  assert.deepEqual(JSON.parse(Buffer.from(plain).toString()), { values: { f0: 'demo', f1: 'demo-pass' } });
  assert.equal(await page.locator('#field-f0').inputValue(), '');
  assert.equal(await page.locator('#field-f1').inputValue(), '');

  const slowRequest = { ...request, id: 'sh_frontend_auth_slow', expiresAt: Date.now() + 60000 };
  // A hash-only goto reuses the old document; a new request needs a fresh Mini App.
  await page.goto('about:blank');
  await page.goto(`http://127.0.0.1:${server.address().port}/#request=${b64(JSON.stringify(slowRequest))}&tgWebAppVersion=9.6`, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => document.querySelector('.app-card')?.dataset.state === 'secureReady');
  await page.evaluate((deadline) => {
    const originalEncrypt = SubtleCrypto.prototype.encrypt;
    SubtleCrypto.prototype.encrypt = async function (...args) {
      const result = await originalEncrypt.apply(this, args);
      Date.now = () => deadline + 1;
      return result;
    };
  }, slowRequest.expiresAt);
  await page.locator('#field-f0').fill('demo');
  await page.locator('#field-f1').fill('demo-pass');
  await page.getByRole('button', { name: 'Submit to browser' }).click();
  await page.waitForFunction(() => document.querySelector('#page-title')?.textContent === 'The link has expired');
  assert.equal(await page.locator('#field-f0').inputValue(), '');
  assert.equal(await page.locator('#field-f1').inputValue(), '');
  assert.equal(await page.evaluate(() => window.__sent), undefined);
  console.log('frontend auth browser test: PASS');
} finally { await browser.close(); await new Promise(resolveServer => server.close(resolveServer)); }
