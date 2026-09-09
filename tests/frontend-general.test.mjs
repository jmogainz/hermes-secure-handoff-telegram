import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { chromium } from 'playwright';

// Synthetic, isolated browser only. Never attach to a live profile or load the real SDK.
const pair = await webcrypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
const publicKey = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
const field = (type, index = 0, extra = {}) => ({ id: `f${index}`, label: `Synthetic ${type}`, type, required: true, ...extra });
const request = (fields, extra = {}) => ({ v: 3, id: 'sh_synthetic_general', publicKey, expiresAt: Date.now() + 300000, origin: 'https://synthetic.example', provider: 'generic', stage: 'general_form', mode: 'form', actionLabel: 'Fill fields', demo: false, fields, ...extra });
const server = createServer(async (req, res) => {
  const path = new URL(req.url, 'http://127.0.0.1').pathname;
  const file = { '/': 'index.html', '/app.js': 'app.js', '/styles.css': 'styles.css' }[path];
  if (!file) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'content-type': file.endsWith('.js') ? 'application/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html' });
  res.end(await readFile(new URL(`../web/${file}`, import.meta.url)));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || 'chromium', headless: true });
const base = `http://127.0.0.1:${server.address().port}/`;
const tests = [];
const browserErrors = [];
function test(name, fn) { tests.push([name, fn]); }
async function open(payload, setup) {
  const page = await browser.newPage({ viewport: { width: 320, height: 640 } });
  page.on('pageerror', () => browserErrors.push('Unexpected page error'));
  await page.route('**/*', route => {
    if (route.request().url().startsWith(base)) return route.continue();
    if (route.request().url() === 'https://telegram.org/js/telegram-web-app.js') return route.fulfill({ contentType: 'application/javascript', body: "window.Telegram={WebApp:{platform:'ios',initData:'',ready(){},close(){window.__closed=true},sendData(v){window.__sent=(window.__sent||[]).concat(v)}}}" });
    return route.abort();
  });
  if (setup) await page.addInitScript(setup);
  await page.goto(`${base}#request=${Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload)).toString('base64url')}`);
  await page.waitForFunction(() => document.querySelector('.app-card')?.dataset.state !== 'loading');
  return page;
}
async function decrypt(raw) {
  const envelope = JSON.parse(raw);
  assert.deepEqual(Object.keys(envelope), ['v', 'id', 'wrappedKey', 'iv', 'ciphertext']);
  assert.equal(envelope.v, 3);
  assert.ok(Buffer.byteLength(raw) <= 4096);
  const rawKey = await webcrypto.subtle.decrypt({ name: 'RSA-OAEP' }, pair.privateKey, Buffer.from(envelope.wrappedKey, 'base64url'));
  const aes = await webcrypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
  const plain = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(envelope.iv, 'base64url'), additionalData: Buffer.from(envelope.id) }, aes, Buffer.from(envelope.ciphertext, 'base64url'));
  return JSON.parse(Buffer.from(plain).toString());
}

test('generic typed controls send only the existing encrypted v3 values envelope', async () => {
  const entries = [
    ['textarea', 'Synthetic multiline\nsecond line'], ['checkbox', 'true'], ['date', '2026-09-07'],
    ['time', '13:45'], ['datetime-local', '2026-09-07T13:45'], ['month', '2026-09'], ['week', '2026-W37'],
    ['url', 'https://synthetic.example/path'], ['search', 'synthetic query'], ['color', '#12ab34'], ['range', '42'],
    ['number', '2.5'], ['select', 'choice-a'],
  ];
  const fields = entries.map(([type], i) => field(type, i, type === 'select' ? { options: [{ value: 'choice-a', label: 'Choice A' }, { value: 'choice-b', label: 'Choice B' }] } : {}));
  const page = await open(request(fields));
  try {
    assert.equal(await page.locator('.app-card').getAttribute('data-state'), 'secureReady');
    assert.equal(await page.getByRole('button', { name: 'Fill fields', exact: true }).count(), 1);
    const expected = {};
    for (const [[type, value], i] of entries.map((entry, i) => [entry, i])) {
      const input = page.locator(`#field-f${i}`);
      assert.equal(await input.evaluate(el => el.tagName.toLowerCase()), ['textarea', 'select'].includes(type) ? type : 'input');
      if (!['textarea', 'select'].includes(type)) assert.equal(await input.getAttribute('type'), type);
      if (type === 'checkbox') await input.check();
      else if (type === 'select') await input.selectOption(value);
      else if (type === 'range' || type === 'color') await input.evaluate((el, v) => { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); }, value);
      else await input.fill(value);
      expected[`f${i}`] = value;
    }
    await page.getByRole('button', { name: 'Fill fields', exact: true }).click();
    await page.waitForFunction(() => window.__sent?.length === 1);
    const raw = await page.evaluate(() => window.__sent[0]);
    assert.ok(!raw.includes('Synthetic multiline'));
    assert.deepEqual(await decrypt(raw), { values: expected });
  } finally { await page.close(); }
});

test('malformed or unsupported metadata is rejected before rendering controls', async () => {
  const cases = [
    request([field('text')], {composition:{layout:'sections',groups:[{title:'details',fields:[]}]}}),
    request([field('text')], {composition:{layout:'hidden',groups:[{title:'details',fields:['f0']}]}}),
    request([field('text')], {composition:{layout:'stack',groups:[{title:'<script>bad</script>',fields:['f0']}]}}),
    request([field('text')], {composition:{layout:'stack',groups:[{title:'details',fields:['f0','f0']}]}}),
    request([field('text')], {composition:{layout:'stack',groups:[{title:'details',fields:['f1']}]}}),
    request([field('text')], {composition:{layout:'stack',groups:[{title:'details',fields:['f0'],hidden:true}]}}),
    request([field('text')], {composition:{layout:'stack',groups:[{title:'details',fields:['f0']}],html:'<input>'}}),
    request([field('checkbox')], {composition:{layout:'stack',groups:[{title:'details',fields:['f0']}]}}),
    request([field('file')]), request([field('radio')]), request([field('text')], { mode: 'unknown' }),
    request([field('text')], { mode: 'form', actionLabel: 'Buy now' }),
    request([field('text', 0, { min: 0 })]), request([field('text', 0, { value: 'untrusted-prefill' })]),
    request([field('text', 0, { required: 'true' })]), request([field('text', 0, { label: 'x'.repeat(81) })]),
    request([field('text', 0, { label: 'Hidden\u007fcontrol' })]),
    request([field('text')], { stage: 'x'.repeat(65) }), request([field('text')], { provider: 'x'.repeat(65) }),
    request([field('text')], { unknown: true }), request([field('text')], { expiresAt: Number.MAX_SAFE_INTEGER }),
    JSON.stringify(request([field('text')])).replace(/"expiresAt":\d+/, '"expiresAt":1e999'),
    request([field('text', 0, { frameOrdinal: 64 })]), request([field('text', 0, { frameOrdinal: -1 })]), request([field('text', 0, { frameOrdinal: '1' })]),
    request([field('select', 0, { options: [{ value: 'a', label: 'A' }, { value: 'a', label: 'Duplicate' }] })]),
    request([field('select', 0, { options: [] })]), request([field('select', 0, { options: [{ value: 'x', label: 'X', disabled: false }] })]),
    request([field('text'), field('text')]), request([]),
    request([field('text')], { mode: 'payment_confirmation', actionLabel: 'Authorize purchase' }),
  ];
  const accepted = [];
  for (const [index, payload] of cases.entries()) {
    const page = await open(payload);
    if (await page.locator('.app-card').getAttribute('data-state') !== 'error' || await page.locator('#field-list input, #field-list select, #field-list textarea').count() !== 0) accepted.push(index);
    await page.close();
  }
  assert.deepEqual(accepted, [], 'No malformed case may reach the editable form');
});

test('required and typed validation rejects bad values and clears every control', async () => {
  const cases = [
    ['email', 'not-an-email'], ['url', 'not-a-url'], ['number', 'Infinity'], ['date', '2026-02-30'],
    ['time', '25:61'], ['datetime-local', '2026-13-01T13:00'], ['month', '2026-13'], ['week', '2026-W99'],
    ['text', '   '], ['textarea', 'x'.repeat(513)], ['checkbox', 'false'], ['select', 'forged-choice'],
  ];
  const failures = [];
  for (const [type, value] of cases) {
    const target = field(type, 1, type === 'select' ? { options: [{ value: 'a', label: 'A' }] } : {});
    const page = await open(request([field('text'), target, field('checkbox', 2, { required: false })]));
    await page.locator('#field-f0').fill('Synthetic must be erased');
    await page.locator('#field-f2').check();
    await page.locator('#field-f1').evaluate((el, value) => {
      if (el.type === 'checkbox') el.checked = false;
      else if (el.tagName === 'SELECT') { el.add(new Option('Forged', value)); el.value = value; }
      else { if (!['text', 'textarea', 'email', 'url'].includes(el.type)) el.type = 'text'; el.value = value; }
    }, value);
    await page.locator('#send-button').click();
    await page.waitForTimeout(60);
    const result = await page.evaluate(() => ({ sent: !!window.__sent?.length, cleared: document.querySelector('#field-f0').value === '' && !document.querySelector('#field-f2').checked, invalid: document.querySelector('#field-f1').getAttribute('aria-invalid') === 'true', focus: document.activeElement.id }));
    if (result.sent || !result.cleared || !result.invalid || result.focus !== 'field-f1') failures.push({ type, ...result });
    await page.close();
  }
  assert.deepEqual(failures, []);
});

test('select requires an explicit choice and optional checkbox encrypts false as a string', async () => {
  const page = await open(request([field('select', 0, { options: [{ value: 'a', label: 'A' }] }), field('checkbox', 1, { required: false })]));
  try {
    assert.equal(await page.locator('#field-f0').inputValue(), '', 'Do not silently select the first radio/select choice');
    await page.locator('#send-button').click();
    assert.equal(await page.evaluate(() => window.__sent), undefined);
    await page.locator('#field-f0').selectOption('a');
    await page.locator('#send-button').click();
    await page.waitForFunction(() => window.__sent?.length === 1);
    assert.deepEqual(await decrypt(await page.evaluate(() => window.__sent[0])), { values: { f0: 'a', f1: 'false' } });
  } finally { await page.close(); }
});

test('large native selects use exact-label entry without publishing option values', async () => {
  const page = await open(request([field('select', 0, { selectionMode: 'search' }), field('email', 1)]));
  try {
    const input = page.locator('#field-f0');
    assert.equal(await input.evaluate(el => el.tagName.toLowerCase()), 'input');
    assert.equal(await input.getAttribute('type'), 'text');
    assert.match(await input.getAttribute('placeholder'), /exact option label/i);
    await input.fill('Country 69');
    await page.locator('#field-f1').fill('synthetic@example.test');
    await page.locator('#send-button').click();
    await page.waitForFunction(() => window.__sent?.length === 1);
    assert.deepEqual(await decrypt(await page.evaluate(() => window.__sent[0])), { values: { f0: 'Country 69', f1: 'synthetic@example.test' } });
  } finally { await page.close(); }
});

test('submission cleanup covers success, crypto failure, send failure, expiry and missing controls', async () => {
  for (const ending of ['success', 'crypto', 'transport', 'expired', 'oversized', 'missing']) {
    const fields = [field('textarea'), field('checkbox', 1), field('select', 2, { options: [{ value: 'a', label: 'A' }] }), field('color', 3), field('range', 4)];
    if (ending === 'oversized') for (let i = 5; i < 10; i++) fields.push(field('textarea', i));
    const payload = request(fields);
    const page = await open(payload);
    try {
      await page.locator('#field-f0').fill('Synthetic private text');
      await page.locator('#field-f1').check();
      await page.locator('#field-f2').selectOption('a');
      await page.locator('#field-f3').evaluate(el => { el.value = '#12ab34'; });
      await page.locator('#field-f4').evaluate(el => { el.value = '42'; });
      if (ending === 'crypto') await page.evaluate(() => { SubtleCrypto.prototype.generateKey = async () => { throw Error('synthetic failure'); }; });
      if (ending === 'transport') await page.evaluate(() => { Telegram.WebApp.sendData = () => { throw Error('synthetic failure'); }; });
      if (ending === 'expired') await page.evaluate(deadline => { Date.now = () => deadline + 1; }, payload.expiresAt);
      if (ending === 'oversized') for (let i = 5; i < 10; i++) await page.locator(`#field-f${i}`).fill('x'.repeat(500));
      if (ending === 'missing') await page.locator('#field-f2').evaluate(el => el.remove());
      await page.locator('#send-button').click();
      await page.waitForFunction(() => window.__sent?.length === 1 || ['error', 'send-failed'].includes(document.querySelector('.app-card').dataset.state));
      assert.equal(await page.locator('#field-f0').inputValue(), '', ending);
      assert.equal(await page.locator('#field-f1').isChecked(), false, ending);
      if (ending !== 'missing') assert.equal(await page.locator('#field-f2').inputValue(), '', ending);
      assert.notEqual(await page.locator('#field-f3').inputValue(), '#12ab34', ending);
      assert.notEqual(await page.locator('#field-f4').inputValue(), '42', ending);
      const leak = await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length, cookies: document.cookie, secretInMarkup: document.body.innerHTML.includes('Synthetic private text') }));
      assert.deepEqual(leak, { local: 0, session: 0, cookies: '', secretInMarkup: false });
      if (ending !== 'success') assert.equal(await page.evaluate(() => window.__sent), undefined);
      if (ending === 'crypto' || ending === 'transport') {
        assert.match(await page.locator('#status-message').textContent(), /cleared/i);
        assert.doesNotMatch(await page.locator('#page-title').textContent(), /connection test/i);
      }
    } finally { await page.close(); }
  }
});

test('cancel and pagehide scrub plaintext and stop an in-flight encryption before sendData', async () => {
  for (const ending of ['cancel', 'pagehide']) {
    const page = await open(request([field('textarea'), field('checkbox', 1)]));
    try {
      await page.locator('#field-f0').fill('Synthetic pending text');
      await page.locator('#field-f1').check();
      await page.evaluate(() => {
        const generate = SubtleCrypto.prototype.generateKey;
        SubtleCrypto.prototype.generateKey = async function (...args) {
          window.__enteredCrypto = true;
          await new Promise(resolve => { window.__releaseCrypto = resolve; });
          return generate.apply(this, args);
        };
      });
      await page.locator('#send-button').click();
      await page.waitForFunction(() => window.__enteredCrypto);
      if (ending === 'cancel') {
        assert.equal(await page.getByRole('button', { name: 'Cancel', exact: true }).count(), 1);
        await page.getByRole('button', { name: 'Cancel', exact: true }).click();
      } else await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
      assert.equal(await page.locator('#field-f0').inputValue(), '', ending);
      assert.equal(await page.locator('#field-f1').isChecked(), false, ending);
      await page.evaluate(async () => { window.__releaseCrypto(); await new Promise(resolve => setTimeout(resolve, 150)); });
      assert.equal(await page.evaluate(() => window.__sent), undefined, 'A closed request must never resume sending');
      assert.equal(await page.locator('#send-button').isEnabled(), false);
      if (ending === 'cancel') assert.equal(await page.evaluate(() => window.__closed), true);
    } finally { await page.close(); }
  }
});

test('typed controls stay readable and accessible on a narrow mobile viewport', async () => {
  const page = await open(request([field('textarea'), field('checkbox', 1), field('select', 2, { options: [{ value: 'a', label: 'A'.repeat(100) }] }), field('range', 3)]));
  try {
    assert.match(await page.locator('#status-message').textContent(), /fill.*(not|without).*submit/i);
    assert.equal(await page.getByRole('button', { name: 'Cancel', exact: true }).count(), 1);
    for (const type of ['textarea', 'checkbox', 'select', 'range']) {
      const input = page.getByLabel(`Synthetic ${type}`, { exact: true });
      const style = await input.evaluate(el => ({ font: parseFloat(getComputedStyle(el).fontSize), height: el.getBoundingClientRect().height, description: el.getAttribute('aria-describedby') }));
      assert.ok(style.font >= 16, `${type} must not trigger iOS text zoom`);
      assert.ok(style.height >= 44, `${type} must have a touch-sized target`);
      assert.match(style.description, /^status-message error-f\d+$/);
    }
    for (const [width, height] of [[320, 640], [375, 812], [768, 1024], [1280, 720]]) {
      await page.setViewportSize({ width, height });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `No horizontal overflow at ${width}px`);
    }
    assert.equal(await page.locator('#credential-form').getAttribute('aria-describedby'), 'status-message');
  } finally { await page.close(); }
});

test('expiry during idle entry or public-key import leaves no editable request', async () => {
  const deadline = Date.now() + 1400;
  const page = await open(request([field('text')], { expiresAt: deadline }));
  try {
    await page.locator('#field-f0').fill('Synthetic expires soon');
    await page.waitForTimeout(1500);
    assert.equal(await page.locator('#field-f0').inputValue(), '');
    assert.equal(await page.locator('#send-button').isEnabled(), false);
    assert.match(await page.locator('#page-title').textContent(), /expired/i);
  } finally { await page.close(); }
  const delayed = await open(request([field('text')], { expiresAt: Date.now() + 60000 }), () => {
    const original = SubtleCrypto.prototype.importKey;
    SubtleCrypto.prototype.importKey = async function (...args) {
      const key = await original.apply(this, args);
      Date.now = () => Number.MAX_SAFE_INTEGER;
      return key;
    };
  });
  try {
    assert.equal(await delayed.locator('#field-list input').count(), 0);
    assert.match(await delayed.locator('#page-title').textContent(), /expired/i);
  } finally { await delayed.close(); }
});

test('professional form layout puts scope before entry and exposes field-level errors', async () => {
  const page = await open(request([field('email')]));
  try {
    assert.equal(await page.locator('#status-kicker').evaluate(el => getComputedStyle(el).position !== 'absolute'), true);
    assert.ok(await page.locator('#page-title').evaluate(el => parseFloat(getComputedStyle(el).fontSize)) >= 24);
    assert.equal(await page.locator('#status-message').evaluate(el => !!(el.compareDocumentPosition(document.querySelector('#credential-form')) & Node.DOCUMENT_POSITION_FOLLOWING)), true);
    assert.equal(await page.getByRole('group', { name: 'Requested fields' }).count(), 1);
    assert.equal(await page.locator('#field-count').textContent(), '1 field');
    assert.match(await page.locator('#privacy-note').textContent(), /encrypted/i);
    for (const selector of ['#send-button', '#cancel-button']) assert.ok((await page.locator(selector).boundingBox()).height >= 48);
    await page.locator('#field-f0').fill('invalid email');
    await page.locator('#send-button').click();
    assert.equal(await page.locator('#error-f0').isVisible(), true);
    assert.match(await page.locator('#error-f0').textContent(), /valid email/i);
    assert.match(await page.locator('#field-f0').getAttribute('aria-describedby'), /error-f0/);
  } finally { await page.close(); }
});

test('legacy confirmation is blocked without a bound transaction summary', async () => {
  const page = await open(request([], { mode: 'payment_confirmation', stage: 'payment_confirmation', actionLabel: 'Authorize purchase' }));
  try {
    assert.match(await page.locator('#status-message').textContent(), /transaction summary/i);
    assert.doesNotMatch(await page.locator('#page-title').textContent(), /authorize purchase/i);
    assert.equal(await page.locator('#send-button').isVisible(), false);
    assert.equal(await page.locator('#send-button').isEnabled(), false);
    await page.locator('#credential-form').evaluate(el => el.dispatchEvent(new Event('submit', { cancelable: true })));
    assert.equal(await page.evaluate(() => window.__sent), undefined);
    assert.equal(await page.getByRole('button', { name: 'Cancel', exact: true }).count(), 1);
  } finally { await page.close(); }
});

test('optional select cannot submit an empty value absent from the published choices', async () => {
  const page = await open(request([field('select', 0, { required: false, options: [{ value: 'choice-a', label: 'A' }] })]));
  try {
    await page.locator('#send-button').click();
    await page.waitForTimeout(80);
    assert.equal(await page.evaluate(() => window.__sent), undefined);
    assert.equal(await page.locator('#field-f0').getAttribute('aria-invalid'), 'true');
  } finally { await page.close(); }
});

let failed = 0;
try {
  for (const [name, run] of tests) {
    try { await run(); console.log(`PASS ${name}`); }
    catch (error) { failed += 1; console.error(`FAIL ${name}: ${error.stack}`); }
  }
  if (process.env.FRONTEND_SCREENSHOT_PATH) {
    const page = await open(request([
      field('textarea', 0, { label: 'Notes' }),
      field('select', 1, { label: 'Preference', options: [{ value: 'choice-a', label: 'Option A' }, { value: 'choice-b', label: 'Option B' }] }),
      field('date', 2, { label: 'Date', required: false }),
      field('checkbox', 3, { label: 'Include updates', required: false }),
    ]));
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.locator('#field-f0').inputValue(), '');
    assert.equal(await page.locator('#field-f1').inputValue(), '');
    assert.equal(await page.locator('#field-f2').inputValue(), '');
    assert.equal(await page.locator('#field-f3').isChecked(), false);
    await page.screenshot({ path: process.env.FRONTEND_SCREENSHOT_PATH, fullPage: true });
    await page.setViewportSize({ width: 1280, height: 1040 });
    await page.screenshot({ path: process.env.FRONTEND_SCREENSHOT_PATH.replace(/\.png$/, '-desktop.png'), fullPage: true });
    await page.close();
  }
  assert.deepEqual(browserErrors, [], 'No unhandled browser errors');
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
console.log(`frontend general: ${tests.length - failed}/${tests.length} passed`);
if (failed) process.exitCode = 1;
