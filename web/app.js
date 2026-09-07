(() => {
  'use strict';

  const FIXED_MARKER = 'telegram-roundtrip-ok';
  const MAX_SEND_DATA_BYTES = 4096;
  const MAX_FRAGMENT_CHARS = 8192;
  const MAX_REQUEST_BYTES = 4096;
  const MAX_ID_LENGTH = 128;
  const MAX_TTL_MS = 10 * 60 * 1000;
  const CLOCK_SKEW_MS = 30 * 1000;
  const MAX_FIELDS = 24;
  const ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
  const FIELD_TYPES = new Set(['text', 'email', 'tel', 'number', 'password', 'otp', 'card_number', 'card_expiry', 'cvc', 'select']);
  const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];

  const dom = {
    card: document.querySelector('.app-card'),
    kicker: document.querySelector('#status-kicker'),
    title: document.querySelector('#page-title'),
    message: document.querySelector('#status-message'),
    privacyNote: document.querySelector('#privacy-note'),
    sendButton: document.querySelector('#send-button'),
    secondary: document.querySelector('#secondary-message'),
    details: document.querySelector('#v2-details'),
    form: document.querySelector('#credential-form'),
    origin: document.querySelector('#request-origin'),
    fields: document.querySelector('#field-list'),
  };

  const state = {
    request: null,
    publicKey: null,
    telegram: null,
    sending: false,
    version: 1,
  };

  const stageCopy = {
    identifier: {
      title: 'Enter account identifier',
      message: 'Enter the username or email for this browser.',
    },
    password: {
      title: 'Enter password',
      message: 'Enter the password for this browser.',
    },
    one_time_code: {
      title: 'Enter one-time code',
      message: 'Enter the one-time code for this browser.',
    },
    checkout_details: {
      title: 'Enter checkout details',
      message: 'Entries are encrypted locally before transmission.',
    },
    payment_confirmation: {
      title: 'Authorize purchase',
      message: 'Review the browser page, then confirm the purchase.',
    },
  };

  function resolveStageCopy(stage) {
    if (stage && stageCopy[stage]) {
      return stageCopy[stage];
    }
    if (stage) {
      const words = stage
        .split(/[_-]+/)
        .filter(Boolean)
        .map((w) => (w.length <= 3 ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()))
        .join(' ');
      return {
        title: `Enter ${words}`,
        message: 'Entries are encrypted locally before transmission.',
      };
    }
    return {
      title: 'Enter credentials',
      message: 'Entries are encrypted locally before transmission.',
    };
  }

  const views = {
    loading: {
      kicker: 'Preparing secure check',
      title: 'Check your Telegram connection',
      message: 'Loading the one-time connection test.',
    },
    ready: {
      kicker: 'Ready to verify',
      title: 'Check your Telegram connection',
      message: 'Send a fixed test marker through this Telegram window.',
    },
    sending: {
      kicker: 'Sending…',
      title: 'Connection test in progress',
      message: 'Sending the fixed test marker through Telegram. Telegram will close this window automatically.',
    },
    sendFailed: {
      kicker: 'Telegram could not send it',
      title: 'Try the connection test again',
      message: 'Telegram did not accept this test right now. Reopen the link from the chat and try once more.',
    },
    missing: {
      kicker: 'Can’t open this test',
      title: 'This link is missing',
      message: 'Open the connection test from the Telegram message again. This page needs its one-time request marker.',
    },
    outside: {
      kicker: 'Telegram is required',
      title: 'Open this in Telegram',
      message: 'This connection test only runs from a Telegram keyboard button. Return to the chat and tap “Open connection test”.',
    },
    expired: {
      kicker: 'This request is no longer active',
      title: 'The link has expired',
      message: 'For your safety, connection test links work only briefly. Return to Telegram and request a fresh link.',
    },
    invalid: {
      kicker: 'Can’t verify this link',
      title: 'This link is not valid',
      message: 'The connection request is incomplete or malformed. Return to Telegram and request a fresh link.',
    },
    unsupported: {
      kicker: 'Telegram is unavailable',
      title: 'This Telegram view is unsupported',
      message: 'Open the connection test using the Telegram keyboard button on an up-to-date Telegram app.',
    },
    v2Ready: {
      kicker: 'Ready to submit',
      title: 'Enter credentials',
      message: 'Entries are encrypted locally before transmission.',
    },
    v2Sending: {
      kicker: 'Submitting…',
      title: 'Sending encrypted details',
      message: 'Telegram is sending the encrypted submission to the browser.',
    },
  };

  class RequestError extends Error {
    constructor(code) {
      super(code);
      this.code = code;
    }
  }

  function render(viewName) {
    let view = views[viewName];
    if (!view) return;

    if (viewName === 'v2Ready') {
      const stageInfo = resolveStageCopy(state.request?.stage);
      view = { ...view, ...stageInfo };
    }

    const isError = ['missing', 'outside', 'expired', 'invalid', 'unsupported'].includes(viewName);
    const isRetry = viewName === 'sendFailed';
    const isSending = viewName === 'sending' || viewName === 'v2Sending';
    const isSecure = state.version === 2 || state.version === 3;
    const showButton = viewName === 'ready' || isRetry || viewName === 'v2Ready';

    dom.card.dataset.state = isError ? 'error' : isRetry ? 'send-failed' : viewName;
    if (dom.kicker) dom.kicker.textContent = view.kicker;
    dom.title.textContent = view.title;
    dom.message.textContent = view.message;
    if (dom.secondary) dom.secondary.textContent = view.secondary || '';
    dom.sendButton.hidden = !showButton && !isSending;
    dom.sendButton.disabled = isSending;
    const actionLabel = state.request?.actionLabel || 'Submit to browser';
    const buttonText = isSecure
      ? (isSending ? 'Submitting…' : state.version === 3 ? actionLabel : 'Submit to browser')
      : (isRetry ? 'Try again' : isSending ? 'Sending…' : 'Send test');
    const span = dom.sendButton.querySelector('span');
    if (span) {
      span.textContent = buttonText;
    } else {
      dom.sendButton.textContent = buttonText;
    }
    dom.sendButton.setAttribute('aria-label', isSecure
      ? (isSending ? 'Submitting to browser' : actionLabel)
      : (isRetry ? 'Try the connection test again' : isSending ? 'Sending the connection test' : 'Send the connection test'));
    if (dom.privacyNote) {
      dom.privacyNote.setAttribute('data-state', isError || isRetry ? 'error' : 'default');
      if (isSecure && viewName === 'v2Ready') {
        dom.privacyNote.textContent = state.request?.mode === 'payment_confirmation'
          ? 'Confirm only after reviewing the live browser page.'
          : 'Encrypted locally in this page. Telegram receives only the encrypted submission.';
      }
    }
    dom.details.hidden = !isSecure || ['missing', 'outside', 'expired', 'invalid', 'unsupported'].includes(viewName);
  }

  function decodeBase64Url(value, maxBytes) {
    if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
      throw new RequestError('invalid');
    }

    const padded = value + '='.repeat((4 - (value.length % 4)) % 4);
    let binary;
    try {
      binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
    } catch {
      throw new RequestError('invalid');
    }

    if (binary.length > maxBytes) {
      throw new RequestError('invalid');
    }

    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }

  function decodeUtf8(bytes) {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      throw new RequestError('invalid');
    }
  }

  function modulusBitLength(bytes) {
    let first = 0;
    while (first < bytes.length && bytes[first] === 0) first += 1;
    if (first === bytes.length) return 0;

    let bits = (bytes.length - first - 1) * 8;
    let value = bytes[first];
    while (value > 0) {
      bits += 1;
      value >>>= 1;
    }
    return bits;
  }

  function validatePublicJwk(publicKey) {
    if (!publicKey || typeof publicKey !== 'object' || Array.isArray(publicKey)) {
      throw new RequestError('invalid');
    }

    if (publicKey.kty !== 'RSA' || typeof publicKey.n !== 'string' || typeof publicKey.e !== 'string') {
      throw new RequestError('invalid');
    }

    if (PRIVATE_JWK_MEMBERS.some((member) => Object.prototype.hasOwnProperty.call(publicKey, member))) {
      throw new RequestError('invalid');
    }

    if (publicKey.alg !== undefined && publicKey.alg !== 'RSA-OAEP-256') {
      throw new RequestError('invalid');
    }

    if (publicKey.key_ops !== undefined && (!Array.isArray(publicKey.key_ops) || !publicKey.key_ops.includes('encrypt'))) {
      throw new RequestError('invalid');
    }

    const modulus = decodeBase64Url(publicKey.n, 512);
    const exponent = decodeBase64Url(publicKey.e, 16);
    if (modulusBitLength(modulus) < 2048 || exponent.length === 0) {
      throw new RequestError('invalid');
    }
  }

  function parseRequest() {
    const fragment = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : '';
    if (!fragment) throw new RequestError('missing');
    if (fragment.length > MAX_FRAGMENT_CHARS) {
      throw new RequestError('invalid');
    }

    let params;
    try {
      params = new URLSearchParams(fragment);
    } catch {
      throw new RequestError('invalid');
    }
    const requests = params.getAll('request');
    if (requests.length === 0) throw new RequestError('missing');
    if (requests.length !== 1 || !requests[0]) throw new RequestError('invalid');

    const encodedRequest = requests[0];
    const requestJson = decodeUtf8(decodeBase64Url(encodedRequest, MAX_REQUEST_BYTES));
    let request;
    try {
      request = JSON.parse(requestJson);
    } catch {
      throw new RequestError('invalid');
    }

    if (!request || typeof request !== 'object' || Array.isArray(request) || ![1, 2, 3].includes(request.v)) {
      throw new RequestError('invalid');
    }

    if (typeof request.id !== 'string' || request.id.length > MAX_ID_LENGTH || !ID_PATTERN.test(request.id)) {
      throw new RequestError('invalid');
    }

    if (!Number.isSafeInteger(request.expiresAt)) {
      throw new RequestError('invalid');
    }

    if (request.expiresAt <= Date.now()) {
      throw new RequestError('expired');
    }

    if (request.expiresAt - Date.now() > MAX_TTL_MS + CLOCK_SKEW_MS) {
      throw new RequestError('invalid');
    }

    validatePublicJwk(request.publicKey);
    if (request.v === 2) validateV2Request(request);
    if (request.v === 3) validateV3Request(request);
    return request;
  }

  function validateV2Request(request) {
    let origin;
    try { origin = new URL(request.origin); } catch { throw new RequestError('invalid'); }
    if (origin.protocol !== 'https:' || origin.origin !== request.origin || origin.username || origin.password || origin.search || origin.hash) throw new RequestError('invalid');
    if (!Array.isArray(request.fields) || request.fields.length < 1 || request.fields.length > 4) throw new RequestError('invalid');
    if (request.stage !== undefined && (typeof request.stage !== 'string' || !ID_PATTERN.test(request.stage))) throw new RequestError('invalid');
    if (request.provider !== undefined && (typeof request.provider !== 'string' || !ID_PATTERN.test(request.provider))) throw new RequestError('invalid');
    const ids = new Set();
    for (const field of request.fields) {
      if (!field || typeof field !== 'object' || typeof field.id !== 'string' || !ID_PATTERN.test(field.id) || ids.has(field.id)) throw new RequestError('invalid');
      if (typeof field.label !== 'string' || !field.label.trim() || field.label.length > 80 || !['text', 'password', 'otp'].includes(field.type)) throw new RequestError('invalid');
      if (typeof field.required !== 'boolean') throw new RequestError('invalid');
      ids.add(field.id);
    }
    if (typeof request.demo !== 'boolean') throw new RequestError('invalid');
  }

  function validateV3Request(request) {
    let origin;
    try { origin = new URL(request.origin); } catch { throw new RequestError('invalid'); }
    if (origin.protocol !== 'https:' || origin.origin !== request.origin || origin.username || origin.password || origin.search || origin.hash) throw new RequestError('invalid');
    if (!['auth', 'checkout', 'payment_confirmation'].includes(request.mode)) throw new RequestError('invalid');
    if (typeof request.actionLabel !== 'string' || !request.actionLabel.trim() || request.actionLabel.length > 80 || /[\x00-\x1f]/.test(request.actionLabel)) throw new RequestError('invalid');
    if (!Array.isArray(request.fields) || request.fields.length > MAX_FIELDS) throw new RequestError('invalid');
    if (request.mode === 'payment_confirmation' ? request.fields.length !== 0 : request.fields.length < 1) throw new RequestError('invalid');
    if (request.stage !== undefined && (typeof request.stage !== 'string' || !ID_PATTERN.test(request.stage))) throw new RequestError('invalid');
    if (request.provider !== undefined && (typeof request.provider !== 'string' || !ID_PATTERN.test(request.provider))) throw new RequestError('invalid');
    const ids = new Set();
    const fieldIdPattern = /^f(?:[0-9]|1[0-9]|2[0-3])$/;
    const safeOption = value => typeof value === 'string' && value.length > 0 && value.length <= 128 && !/[\x00-\x1f]/.test(value);
    for (const field of request.fields) {
      if (!field || typeof field !== 'object' || typeof field.id !== 'string' || !fieldIdPattern.test(field.id) || ids.has(field.id)) throw new RequestError('invalid');
      if (typeof field.label !== 'string' || !field.label.trim() || field.label.length > 80 || /[\x00-\x1f]/.test(field.label) || !FIELD_TYPES.has(field.type)) throw new RequestError('invalid');
      if (typeof field.required !== 'boolean') throw new RequestError('invalid');
      if (field.autocomplete !== undefined && (typeof field.autocomplete !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(field.autocomplete))) throw new RequestError('invalid');
      if (field.inputMode !== undefined && !['text', 'numeric', 'decimal', 'tel', 'email'].includes(field.inputMode)) throw new RequestError('invalid');
      if (field.type === 'select') {
        if (!Array.isArray(field.options) || field.options.length < 1 || field.options.length > 64) throw new RequestError('invalid');
        for (const option of field.options) {
          if (!option || typeof option !== 'object' || Object.keys(option).length !== 2 || !safeOption(option.value) || !safeOption(option.label)) throw new RequestError('invalid');
        }
      } else if (field.options !== undefined) {
        throw new RequestError('invalid');
      }
      ids.add(field.id);
    }
    if (typeof request.demo !== 'boolean') throw new RequestError('invalid');
  }

  function defaultFieldAttributes(field) {
    const defaults = {
      text: { name: 'username', autocomplete: 'off', inputMode: 'text', type: 'text', enterKeyHint: 'next' },
      email: { name: 'email', autocomplete: 'email', inputMode: 'email', type: 'email', enterKeyHint: 'next' },
      tel: { name: 'tel', autocomplete: 'tel', inputMode: 'tel', type: 'tel', enterKeyHint: 'next' },
      number: { name: 'number', autocomplete: 'off', inputMode: 'decimal', type: 'text', enterKeyHint: 'next' },
      password: { name: 'password', autocomplete: 'current-password', inputMode: 'text', type: 'password', enterKeyHint: 'go' },
      otp: { name: 'one-time-code', autocomplete: 'one-time-code', inputMode: 'numeric', type: 'text', enterKeyHint: 'done' },
      card_number: { name: 'cardnumber', autocomplete: 'cc-number', inputMode: 'numeric', type: 'password', enterKeyHint: 'next' },
      card_expiry: { name: 'cc-exp', autocomplete: 'cc-exp', inputMode: 'numeric', type: 'text', enterKeyHint: 'next' },
      cvc: { name: 'csc', autocomplete: 'cc-csc', inputMode: 'numeric', type: 'password', enterKeyHint: 'done' },
    };
    return defaults[field.type] || defaults.text;
  }

  function renderV2Fields(request) {
    dom.origin.textContent = request.origin;
    dom.fields.replaceChildren();
    if (request.v === 3 && request.mode === 'payment_confirmation') return;
    for (const field of request.fields) {
      const wrapper = document.createElement('div'); wrapper.className = 'field-row';
      const label = document.createElement('label'); label.textContent = field.label; label.htmlFor = `field-${field.id}`;
      if (field.required) { const required = document.createElement('span'); required.textContent = 'Required'; required.className = 'required-mark'; label.appendChild(required); }
      const select = field.type === 'select';
      const input = document.createElement(select ? 'select' : 'input');
      input.id = `field-${field.id}`;
      input.name = field.type === 'select' ? field.id : defaultFieldAttributes(field).name;
      input.setAttribute('aria-label', field.label);
      input.required = field.required;
      input.dataset.fieldType = field.type;
      if (select) {
        for (const option of field.options || []) {
          const element = document.createElement('option');
          element.value = option.value;
          element.textContent = option.label;
          input.appendChild(element);
        }
      } else {
        const attributes = defaultFieldAttributes(field);
        input.type = attributes.type;
        input.maxLength = 512;
        input.autocomplete = field.autocomplete || attributes.autocomplete;
        input.enterKeyHint = attributes.enterKeyHint;
        input.inputMode = field.inputMode || attributes.inputMode;
        input.autocapitalize = 'none';
        input.autocorrect = 'off';
        input.spellcheck = false;
      }
      wrapper.append(label, input);
      if (request.demo && field.type === 'text') { const hint = document.createElement('small'); hint.textContent = 'Demo example: demo'; wrapper.appendChild(hint); }
      if (request.demo && field.type === 'password') { const hint = document.createElement('small'); hint.textContent = 'Demo example: demo-pass'; wrapper.appendChild(hint); }
      dom.fields.appendChild(wrapper);
    }
  }

  function findTelegramWebApp() {
    const telegram = globalThis.Telegram;
    const webApp = telegram && telegram.WebApp;
    if (!webApp || typeof webApp.sendData !== 'function') return null;

    const platform = typeof webApp.platform === 'string' ? webApp.platform.trim().toLowerCase() : '';
    if (!platform || platform === 'unknown') return null;

    const initParams = telegram.WebView && telegram.WebView.initParams;
    const hasInitContext = Object.prototype.hasOwnProperty.call(webApp, 'initData')
      || Object.prototype.hasOwnProperty.call(webApp, 'initDataUnsafe')
      || Boolean(initParams && typeof initParams === 'object' && Object.prototype.hasOwnProperty.call(initParams, 'tgWebAppData'));
    return hasInitContext ? webApp : null;
  }

  async function importPublicKey(publicJwk) {
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
      throw new RequestError('unsupported');
    }

    try {
      return await globalThis.crypto.subtle.importKey(
        'jwk',
        publicJwk,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt'],
      );
    } catch {
      throw new RequestError('invalid');
    }
  }

  function encodeBase64Url(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function utf8ByteLength(value) {
    return new TextEncoder().encode(value).byteLength;
  }

  async function sendTest() {
    if (state.sending || !state.request || !state.publicKey || !state.telegram) return;

    if (state.version === 2 || state.version === 3) return sendSecure();
    state.sending = true;
    render('sending');

    try {
      const markerBytes = new TextEncoder().encode(FIXED_MARKER);
      const ciphertext = await globalThis.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        state.publicKey,
        markerBytes,
      );
      const payload = JSON.stringify({
        v: 1,
        id: state.request.id,
        ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
      });

      if (utf8ByteLength(payload) > MAX_SEND_DATA_BYTES) {
        throw new RequestError('invalid');
      }

      if (Date.now() >= state.request.expiresAt) {
        throw new RequestError('expired');
      }
      await Promise.resolve(state.telegram.sendData(payload));
      // Telegram's service handler owns the acknowledgement. Keep this page in
      // “Sending…” until the user sees that acknowledgement in the chat.
    } catch (error) {
      state.sending = false;
      render(error instanceof RequestError && views[error.code]
        ? error.code
        : 'sendFailed');
    }
  }

  async function sendSecure() {
    if (state.sending) return;
    const confirmation = state.version === 3 && state.request.mode === 'payment_confirmation';
    const values = {};
    const controls = [];
    if (!confirmation) {
      for (const field of state.request.fields) {
        const input = document.getElementById(`field-${field.id}`);
        if (!input) { render('invalid'); return; }
        controls.push(input);
        const value = input.value;
        if (value.length > 512) { input.setCustomValidity('This field is too long.'); input.reportValidity(); input.focus(); return; }
        input.setCustomValidity('');
        if (field.required && !value) { input.reportValidity(); input.focus(); return; }
        values[field.id] = value;
      }
    }
    state.sending = true; render('v2Sending');
    let plainBytes;
    let rawKeyBytes;
    try {
      const plain = JSON.stringify(confirmation ? { confirm: true } : { values });
      plainBytes = new TextEncoder().encode(plain);
      if (plainBytes.byteLength > 2048 || Date.now() >= state.request.expiresAt) throw new RequestError(Date.now() >= state.request.expiresAt ? 'expired' : 'invalid');
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(state.request.id) }, key, plainBytes);
      rawKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', key));
      const wrappedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, state.publicKey, rawKeyBytes);
      const payload = JSON.stringify({ v: state.version, id: state.request.id, wrappedKey: encodeBase64Url(new Uint8Array(wrappedKey)), iv: encodeBase64Url(iv), ciphertext: encodeBase64Url(new Uint8Array(ciphertext)) });
      if (utf8ByteLength(payload) > MAX_SEND_DATA_BYTES) throw new RequestError('invalid');
      if (Date.now() >= state.request.expiresAt) throw new RequestError('expired');
      for (const input of controls) input.value = '';
      plainBytes.fill(0);
      rawKeyBytes.fill(0);
      await Promise.resolve(state.telegram.sendData(payload));
    } catch (error) {
      for (const input of controls) input.value = '';
      if (plainBytes) plainBytes.fill(0);
      if (rawKeyBytes) rawKeyBytes.fill(0);
      state.sending = false; render(error instanceof RequestError && views[error.code] ? error.code : 'sendFailed');
    }
  }

  async function boot() {
    render('loading');

    let request;
    try {
      request = parseRequest();
    } catch (error) {
      render(error instanceof RequestError && views[error.code] ? error.code : 'invalid');
      return;
    }

    const telegram = findTelegramWebApp();
    if (!telegram) {
      render('outside');
      return;
    }

    try {
      const publicKey = await importPublicKey(request.publicKey);
      state.request = request;
      state.version = request.v;
      state.publicKey = publicKey;
      state.telegram = telegram;
      if (request.v === 2 || request.v === 3) { renderV2Fields(request); render('v2Ready'); }
      else render('ready');
      if (typeof telegram.ready === 'function') telegram.ready();
    } catch (error) {
      render(error instanceof RequestError && views[error.code] ? error.code : 'unsupported');
    }
  }

  dom.form.addEventListener('submit', (event) => {
    event.preventDefault();
    void sendTest();
  });
  window.addEventListener('pagehide', () => {
    if (state.request && (state.version === 2 || state.version === 3)) for (const field of state.request.fields) { const input = document.getElementById(`field-${field.id}`); if (input) input.value = ''; }
  });
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    void boot();
  }
})();
