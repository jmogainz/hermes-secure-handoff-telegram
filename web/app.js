(() => {
  'use strict';

  const CONNECTION_MARKER = 'telegram-roundtrip-ok';
  const MAX_FRAGMENT_CHARS = 8192;
  const MAX_REQUEST_BYTES = 4096;
  const MAX_SEND_BYTES = 4096;
  const MAX_PLAINTEXT_BYTES = 2048;
  const MAX_FIELDS = 24;
  const MAX_VALUE_CHARS = 512;
  const MAX_VIEW_NODES = 64;
  const MAX_VIEW_DEPTH = 6;
  const MAX_VIEW_CHILDREN = 24;
  const MAX_TTL_MS = 10 * 60 * 1000;
  const CLOCK_SKEW_MS = 30 * 1000;
  const ID_RE = /^sh_[A-Za-z0-9_-]{32}$/;
  const FIELD_ID_RE = /^f(?:[0-9]|1[0-9]|2[0-3])$/;
  const TOKEN_RE = /^[A-Za-z0-9_-]+$/;
  const FIELD_TYPES = new Set([
    'text', 'password', 'email', 'tel', 'url', 'number', 'search',
    'textarea', 'select', 'checkbox', 'radio', 'date', 'time',
    'datetime-local', 'month', 'week', 'color', 'range',
  ]);
  const STRATEGIES = new Set(['keyboard', 'fill', 'select', 'check']);

  const dom = {
    card: document.querySelector('.app-card'),
    form: document.querySelector('#credential-form'),
    kicker: document.querySelector('#status-kicker'),
    title: document.querySelector('#page-title'),
    message: document.querySelector('#status-message'),
    details: document.querySelector('#secure-details'),
    origin: document.querySelector('#request-origin'),
    fieldGroup: document.querySelector('#field-group'),
    fields: document.querySelector('#field-list'),
    fieldCount: document.querySelector('#field-count'),
    send: document.querySelector('#send-button'),
    cancel: document.querySelector('#cancel-button'),
    privacy: document.querySelector('#privacy-note'),
  };

  const state = {
    request: null,
    sending: false,
    buffers: new Set(),
    expiryTimer: null,
    submissionGeneration: 0,
  };

  class RequestError extends Error {
    constructor(reason) { super(reason); this.reason = reason; }
  }

  const COMPONENTS = Object.freeze({
    segmented_code: Object.freeze({
      validate(component, field) {
        if (!exactKeys(component, ['kind', 'length', 'alphabet']) ||
            !Number.isSafeInteger(component.length) || component.length < 4 || component.length > 12 ||
            !['digits', 'alphanumeric'].includes(component.alphabet) || field.strategy !== 'keyboard' ||
            field.required !== true || field.type !== (component.alphabet === 'digits' ? 'tel' : 'text')) {
          throw new RequestError('invalid');
        }
      },
      configure(input, component) {
        input.dataset.component = 'segmented_code';
        input.dataset.segmentCount = String(component.length);
        input.minLength = component.length;
        input.inputMode = component.alphabet === 'digits' ? 'numeric' : 'text';
        input.pattern = component.alphabet === 'digits'
          ? `[0-9]{${component.length}}`
          : `[0-9A-Za-z]{${component.length}}`;
        input.classList.add('segmented-code-input');
        input.spellcheck = false;
        input.autocapitalize = 'off';
        input.addEventListener('input', () => {
          input.setCustomValidity('');
          input.removeAttribute('aria-invalid');
        });
      },
      accepts(value, component) {
        if (codePointLength(value) !== component.length) return false;
        return component.alphabet === 'digits' ? /^[0-9]+$/.test(value) : /^[0-9A-Za-z]+$/.test(value);
      },
      hint(component) {
        return `${component.length}-character ${component.alphabet === 'digits' ? 'numeric' : 'alphanumeric'} code`;
      },
    }),
  });

  function setText(kicker, title, message, stateName = 'ready') {
    dom.card.dataset.state = stateName;
    dom.kicker.textContent = kicker;
    dom.title.textContent = title;
    dom.message.textContent = message;
  }

  function exactKeys(value, keys) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const actual = Object.keys(value);
    return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
  }

  function utf8Length(value) { return new TextEncoder().encode(value).byteLength; }
  function codePointLength(value) { return [...value].length; }

  function strictJson(source) {
    if (typeof source !== 'string') throw new RequestError('invalid');
    let index = 0;
    const fail = () => { throw new RequestError('invalid'); };
    const skipWhitespace = () => {
      while (index < source.length && /[\u0009\u000a\u000d\u0020]/.test(source[index])) index += 1;
    };

    function parseString() {
      if (source[index] !== '"') fail();
      const start = index;
      index += 1;
      while (index < source.length) {
        const character = source[index];
        if (character === '"') {
          index += 1;
          try { return JSON.parse(source.slice(start, index)); }
          catch { fail(); }
        }
        if (source.charCodeAt(index) <= 0x1f) fail();
        if (character === '\\') {
          index += 1;
          const escape = source[index];
          if ('"\\/bfnrt'.includes(escape)) {
            index += 1;
            continue;
          }
          if (escape === 'u' && /^[0-9a-fA-F]{4}$/.test(source.slice(index + 1, index + 5))) {
            index += 5;
            continue;
          }
          fail();
        }
        index += 1;
      }
      fail();
    }

    function parseNumber() {
      const match = source.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
      if (!match) fail();
      index += match[0].length;
      const value = Number(match[0]);
      if (!Number.isFinite(value)) fail();
      return value;
    }

    function parseArray(depth) {
      const result = [];
      index += 1;
      skipWhitespace();
      if (source[index] === ']') {
        index += 1;
        return result;
      }
      while (true) {
        result.push(parseValue(depth + 1));
        skipWhitespace();
        if (source[index] === ']') {
          index += 1;
          return result;
        }
        if (source[index] !== ',') fail();
        index += 1;
        skipWhitespace();
      }
    }

    function parseObject(depth) {
      const result = Object.create(null);
      const keys = new Set();
      index += 1;
      skipWhitespace();
      if (source[index] === '}') {
        index += 1;
        return result;
      }
      while (true) {
        const key = parseString();
        if (keys.has(key)) fail();
        keys.add(key);
        skipWhitespace();
        if (source[index] !== ':') fail();
        index += 1;
        result[key] = parseValue(depth + 1);
        skipWhitespace();
        if (source[index] === '}') {
          index += 1;
          return result;
        }
        if (source[index] !== ',') fail();
        index += 1;
        skipWhitespace();
      }
    }

    function parseValue(depth) {
      if (depth > 64) fail();
      skipWhitespace();
      const character = source[index];
      if (character === '"') return parseString();
      if (character === '{') return parseObject(depth);
      if (character === '[') return parseArray(depth);
      if (source.startsWith('true', index)) { index += 4; return true; }
      if (source.startsWith('false', index)) { index += 5; return false; }
      if (source.startsWith('null', index)) { index += 4; return null; }
      if (character === '-' || /[0-9]/.test(character)) return parseNumber();
      fail();
    }

    const value = parseValue(0);
    skipWhitespace();
    if (index !== source.length) fail();
    return value;
  }

  function decodeBase64Url(value) {
    if (typeof value !== 'string' || !value || !TOKEN_RE.test(value)) throw new RequestError('invalid');
    try {
      const standard = value.replace(/-/g, '+').replace(/_/g, '/');
      const raw = atob(standard + '='.repeat((4 - standard.length % 4) % 4));
      const bytes = Uint8Array.from(raw, (character) => character.charCodeAt(0));
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch { throw new RequestError('invalid'); }
  }

  function encodeBase64Url(value) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function safeText(value, maximum) {
    return typeof value === 'string' && value.trim().length > 0 && codePointLength(value) <= maximum &&
      !/[\p{Cc}\p{Cf}\p{Cs}\u034f\u115f\u1160\u17b4\u17b5\u3164\uffa0\ufe00-\ufe0f\u{e0100}-\u{e01ef}]/u.test(value) &&
      !/(?:\/\/|(?:https?|tg|javascript|data|file|mailto|tel):)/i.test(value);
  }

  function validatePublicKey(key) {
    const allowed = new Set(['kty', 'n', 'e', 'alg', 'ext', 'key_ops']);
    if (!key || typeof key !== 'object' || Array.isArray(key) ||
        Object.keys(key).some((name) => !allowed.has(name)) ||
        key.kty !== 'RSA' || typeof key.n !== 'string' || key.n.length < 300 ||
        key.n.length > 350 || !TOKEN_RE.test(key.n) || key.e !== 'AQAB' ||
        (key.alg !== undefined && key.alg !== 'RSA-OAEP-256') ||
        (key.ext !== undefined && key.ext !== true) ||
        (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || !key.key_ops.includes('encrypt')))) {
      throw new RequestError('invalid');
    }
  }

  function validateExpiry(expiresAt) {
    if (!Number.isSafeInteger(expiresAt)) throw new RequestError('invalid');
    if (expiresAt <= Date.now()) throw new RequestError('expired');
    if (expiresAt - Date.now() > MAX_TTL_MS + CLOCK_SKEW_MS) throw new RequestError('invalid');
  }

  function validateOrigin(origin) {
    if (typeof origin !== 'string' || origin.length > 4096 || /[\x00-\x20\x7f\\]/.test(origin)) throw new RequestError('invalid');
    let parsed;
    try { parsed = new URL(origin); } catch { throw new RequestError('invalid'); }
    if (parsed.protocol !== 'https:' || parsed.origin !== origin || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
      throw new RequestError('invalid');
    }
  }

  function validateV1(request) {
    if (!exactKeys(request, ['v', 'id', 'publicKey', 'expiresAt']) || request.v !== 1 ||
        typeof request.id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(request.id)) throw new RequestError('invalid');
    validateExpiry(request.expiresAt);
    validatePublicKey(request.publicKey);
  }

  function validateEntryField(field, seen) {
    const keys = field?.component === undefined
      ? ['id', 'label', 'type', 'required', 'strategy']
      : ['id', 'label', 'type', 'required', 'strategy', 'component'];
    if (!exactKeys(field, keys) ||
        typeof field.id !== 'string' || !FIELD_ID_RE.test(field.id) || seen.has(field.id) ||
        !safeText(field.label, 80) || !FIELD_TYPES.has(field.type) ||
        typeof field.required !== 'boolean' || !STRATEGIES.has(field.strategy)) throw new RequestError('invalid');
    if (field.type === 'select' && field.strategy !== 'select') throw new RequestError('invalid');
    if ((field.type === 'checkbox' || field.type === 'radio') && field.strategy !== 'check') throw new RequestError('invalid');
    if (!['select', 'checkbox', 'radio'].includes(field.type) && !['keyboard', 'fill'].includes(field.strategy)) throw new RequestError('invalid');
    if (field.component !== undefined) {
      const renderer = COMPONENTS[field.component?.kind];
      if (!renderer) throw new RequestError('invalid');
      renderer.validate(field.component, field);
    }
    seen.add(field.id);
  }

  function validateView(view, fieldIds) {
    let count = 0;
    const seen = new Set();
    function walk(node, depth, root = false) {
      count += 1;
      if (count > MAX_VIEW_NODES || depth > MAX_VIEW_DEPTH || !node || typeof node !== 'object' || Array.isArray(node)) {
        throw new RequestError('invalid');
      }
      if (node.kind === 'field') {
        if (root || !exactKeys(node, ['kind', 'field']) || typeof node.field !== 'string' ||
            !fieldIds.has(node.field) || seen.has(node.field)) throw new RequestError('invalid');
        seen.add(node.field);
        return;
      }
      if (node.kind === 'text') {
        if (root || !exactKeys(node, ['kind', 'text', 'tone']) || !safeText(node.text, 240) ||
            !['normal', 'muted'].includes(node.tone)) throw new RequestError('invalid');
        return;
      }
      if (node.kind === 'divider') {
        if (root || !exactKeys(node, ['kind'])) throw new RequestError('invalid');
        return;
      }
      if (!['stack', 'row', 'section'].includes(node.kind)) throw new RequestError('invalid');
      const keys = root
        ? ['schema', 'kind', 'children']
        : node.kind === 'section' ? ['kind', 'title', 'children'] : ['kind', 'children'];
      if (!exactKeys(node, keys) || (root && node.schema !== 'secure-handoff.ui/1') ||
          (node.kind === 'section' && !safeText(node.title, 80)) ||
          !Array.isArray(node.children) || node.children.length < 1 || node.children.length > MAX_VIEW_CHILDREN) {
        throw new RequestError('invalid');
      }
      for (const child of node.children) walk(child, depth + 1, false);
    }
    if (view?.kind !== 'stack') throw new RequestError('invalid');
    walk(view, 1, true);
    if (seen.size !== fieldIds.size || [...fieldIds].some((fieldId) => !seen.has(fieldId))) throw new RequestError('invalid');
  }

  function validateV4(request) {
    if (request.v !== 4 || typeof request.id !== 'string' || !ID_RE.test(request.id)) throw new RequestError('invalid');
    validateExpiry(request.expiresAt);
    validatePublicKey(request.publicKey);
    validateOrigin(request.origin);
    if (request.kind === 'entry') {
      const keys = request.view === undefined
        ? ['v', 'id', 'origin', 'expiresAt', 'publicKey', 'kind', 'fields']
        : ['v', 'id', 'origin', 'expiresAt', 'publicKey', 'kind', 'fields', 'view'];
      if (!exactKeys(request, keys) ||
          !Array.isArray(request.fields) || request.fields.length < 1 || request.fields.length > MAX_FIELDS) throw new RequestError('invalid');
      const seen = new Set();
      for (const field of request.fields) validateEntryField(field, seen);
      if (request.view !== undefined) validateView(request.view, seen);
      return;
    }
    if (request.kind === 'action_approval') {
      if (!exactKeys(request, ['v', 'id', 'origin', 'expiresAt', 'publicKey', 'kind', 'approvalNonce', 'summary']) ||
          typeof request.approvalNonce !== 'string' || !/^approve_[A-Za-z0-9_-]{24}$/.test(request.approvalNonce) ||
          !safeText(request.summary, 160)) throw new RequestError('invalid');
      return;
    }
    throw new RequestError('invalid');
  }

  function parseRequest() {
    if (location.hash.length > MAX_FRAGMENT_CHARS) throw new RequestError('invalid');
    const params = new URLSearchParams(location.hash.slice(1));
    const requests = params.getAll('request');
    if (requests.length === 0) throw new RequestError('missing');
    if (requests.length !== 1) throw new RequestError('invalid');
    for (const key of params.keys()) {
      if (key !== 'request' && !key.startsWith('tgWebApp')) throw new RequestError('invalid');
    }
    const raw = decodeBase64Url(requests[0]);
    if (utf8Length(raw) > MAX_REQUEST_BYTES) throw new RequestError('invalid');
    const request = strictJson(raw);
    if (request?.v === 1) validateV1(request);
    else if (request?.v === 4) validateV4(request);
    else throw new RequestError('invalid');
    return request;
  }

  function telegram() {
    const webApp = window.Telegram?.WebApp;
    if (!webApp || typeof webApp.ready !== 'function' || typeof webApp.sendData !== 'function' || webApp.platform === 'unknown') return null;
    return webApp;
  }

  function clearBuffers() {
    for (const buffer of state.buffers) buffer.fill(0);
    state.buffers.clear();
  }

  function clearPlaintext() {
    clearBuffers();
    for (const input of dom.fields.querySelectorAll('input, textarea, select')) {
      if (input.type === 'checkbox' || input.type === 'radio') input.checked = false;
      input.value = '';
      input.removeAttribute('value');
      input.setCustomValidity('');
      input.removeAttribute('aria-invalid');
    }
    for (const error of dom.fields.querySelectorAll('.field-error')) {
      error.textContent = '';
      error.hidden = true;
    }
  }

  function invalidateSubmission() {
    state.submissionGeneration += 1;
    state.sending = false;
  }

  function expireRequest() {
    if (state.expiryTimer !== null) clearTimeout(state.expiryTimer);
    state.expiryTimer = null;
    invalidateSubmission();
    clearPlaintext();
    state.request = null;
    dom.fields.replaceChildren();
    showFailure('expired');
  }

  function ensureFresh() {
    if (!state.request || state.request.expiresAt <= Date.now()) {
      expireRequest();
      return false;
    }
    return true;
  }

  function scheduleExpiry(request) {
    if (state.expiryTimer !== null) clearTimeout(state.expiryTimer);
    state.expiryTimer = setTimeout(expireRequest, Math.max(0, request.expiresAt - Date.now()));
  }

  function assertSubmissionActive(request, generation) {
    if (request.expiresAt <= Date.now()) {
      expireRequest();
      throw new RequestError('expired');
    }
    if (state.request !== request || state.submissionGeneration !== generation) {
      throw new RequestError('cancelled');
    }
  }

  function fieldInput(field) {
    let input;
    if (field.strategy === 'check') {
      input = document.createElement('input');
      input.type = 'checkbox';
    } else if (field.type === 'textarea') {
      input = document.createElement('textarea');
    } else {
      input = document.createElement('input');
      const nativeType = field.strategy === 'select' ? 'text' : field.type;
      input.type = ['text', 'password', 'email', 'tel', 'url', 'number', 'search', 'date', 'time', 'datetime-local', 'month', 'week', 'color', 'range'].includes(nativeType) ? nativeType : 'text';
      if (field.strategy === 'select') input.placeholder = 'Type the option label shown in the browser';
    }
    input.id = `field-${field.id}`;
    input.name = field.id;
    input.required = field.required;
    if (field.component !== undefined) COMPONENTS[field.component.kind].configure(input, field.component);
    input.autocomplete = 'off';
    input.autocapitalize = 'none';
    input.autocorrect = 'off';
    input.spellcheck = false;
    input.setAttribute('aria-label', field.label);
    return input;
  }

  function renderField(field) {
      const fieldRow = document.createElement('div');
      fieldRow.className = 'field-row';
      const label = document.createElement('label');
      label.htmlFor = `field-${field.id}`;
      label.textContent = field.label;
      if (field.required) {
        const mark = document.createElement('span');
        mark.className = 'required-mark';
        mark.textContent = 'Required';
        label.appendChild(mark);
      }
      const input = fieldInput(field);
      fieldRow.append(label, input);
      const descriptions = [];
      if (field.component !== undefined) {
        const hint = document.createElement('small');
        hint.id = `field-${field.id}-hint`;
        hint.textContent = COMPONENTS[field.component.kind].hint(field.component);
        descriptions.push(hint.id);
        fieldRow.appendChild(hint);
      }
      const error = document.createElement('small');
      error.id = `field-${field.id}-error`;
      error.className = 'field-error';
      error.setAttribute('role', 'alert');
      error.hidden = true;
      descriptions.push(error.id);
      input.setAttribute('aria-describedby', descriptions.join(' '));
      input.setAttribute('aria-errormessage', error.id);
      const clearError = () => {
        input.setCustomValidity('');
        input.removeAttribute('aria-invalid');
        error.textContent = '';
        error.hidden = true;
      };
      input.addEventListener('input', clearError);
      input.addEventListener('change', clearError);
      fieldRow.appendChild(error);
      return fieldRow;
  }

  function renderViewNode(node, fields) {
    if (node.kind === 'field') return renderField(fields.get(node.field));
    if (node.kind === 'text') {
      const text = document.createElement('p');
      text.className = 'view-text';
      text.dataset.tone = node.tone;
      text.textContent = node.text;
      return text;
    }
    if (node.kind === 'divider') {
      const divider = document.createElement('hr');
      divider.className = 'view-divider';
      return divider;
    }
    const container = document.createElement(node.kind === 'section' ? 'section' : 'div');
    container.className = `view-${node.kind}`;
    if (node.kind === 'section') {
      const title = document.createElement('h2');
      title.textContent = node.title;
      container.appendChild(title);
    }
    for (const child of node.children) container.appendChild(renderViewNode(child, fields));
    return container;
  }

  function renderEntry(request) {
    dom.fieldGroup.hidden = false;
    dom.fieldGroup.querySelector('legend span:first-child').textContent = 'Agent-requested fields';
    dom.fieldCount.textContent = `${request.fields.length} ${request.fields.length === 1 ? 'field' : 'fields'}`;
    if (request.view !== undefined) {
      dom.fields.appendChild(renderViewNode(request.view, new Map(request.fields.map((field) => [field.id, field]))));
    } else {
      for (const field of request.fields) dom.fields.appendChild(renderField(field));
    }
    dom.send.querySelector('span').textContent = 'Send securely';
    dom.send.setAttribute('aria-label', 'Send encrypted submission');
    setText('Secure entry ready', 'Enter the requested information', 'Telegram will deliver the encrypted submission. Goku will inspect the live browser afterward.');
  }

  function renderAction(request) {
    dom.fieldGroup.hidden = false;
    dom.fieldGroup.querySelector('legend span:first-child').textContent = 'Approval';
    dom.fieldCount.textContent = '1 action';
    const summary = document.createElement('p');
    summary.className = 'action-summary';
    summary.textContent = request.summary;
    const row = document.createElement('div');
    row.className = 'action-approval-row';
    const label = document.createElement('label');
    const approval = document.createElement('input');
    approval.type = 'checkbox';
    approval.id = 'action-approval';
    label.htmlFor = approval.id;
    label.append(approval, document.createTextNode(' I approve one attempt on the exact selected browser action.'));
    row.appendChild(label);
    dom.fields.append(summary, row);
    dom.send.querySelector('span').textContent = 'Approve action';
    dom.send.setAttribute('aria-label', 'Approve the selected browser action');
    dom.send.disabled = true;
    approval.addEventListener('change', () => { dom.send.disabled = !approval.checked || state.sending; });
    setText('Action approval ready', 'Review the selected browser action', 'Approval authorizes one mechanical attempt. Goku will inspect the live browser afterward.');
  }

  function renderConnection() {
    dom.details.hidden = true;
    dom.send.querySelector('span').textContent = 'Send test';
    dom.send.setAttribute('aria-label', 'Send the connection test');
    setText('Ready to verify', 'Check your Telegram connection', 'Send the one-time encrypted connection test.');
  }

  async function importRsaKey(request) {
    return crypto.subtle.importKey('jwk', request.publicKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  }

  async function connectionEnvelope(request, generation) {
    const key = await importRsaKey(request);
    assertSubmissionActive(request, generation);
    const plaintext = new TextEncoder().encode(CONNECTION_MARKER);
    state.buffers.add(plaintext);
    const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, plaintext);
    assertSubmissionActive(request, generation);
    return { v: 1, id: request.id, ciphertext: encodeBase64Url(ciphertext) };
  }

  async function encryptedEnvelope(request, bodyFactory, generation) {
    const rsa = await importRsaKey(request);
    assertSubmissionActive(request, generation);
    const aes = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    assertSubmissionActive(request, generation);
    const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', aes));
    assertSubmissionActive(request, generation);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = new TextEncoder().encode(request.id);
    state.buffers.add(rawKey); state.buffers.add(iv); state.buffers.add(aad);
    let body = bodyFactory();
    const plaintext = new TextEncoder().encode(JSON.stringify(body));
    body = null;
    if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) throw new RequestError('invalid');
    state.buffers.add(plaintext);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, aes, plaintext);
    assertSubmissionActive(request, generation);
    const wrappedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsa, rawKey);
    assertSubmissionActive(request, generation);
    return {
      v: 4,
      id: request.id,
      wrappedKey: encodeBase64Url(wrappedKey),
      iv: encodeBase64Url(iv),
      ciphertext: encodeBase64Url(ciphertext),
    };
  }

  function entryBody(request) {
    const values = {};
    for (const field of request.fields) {
      const input = document.querySelector(`#field-${field.id}`);
      let value = field.strategy === 'check' ? String(input.checked) : input.value;
      const missing = field.required && (field.strategy === 'check' ? !input.checked : !value);
      const componentInvalid = field.component !== undefined && value !== '' &&
        !COMPONENTS[field.component.kind].accepts(value, field.component);
      if (codePointLength(value) > MAX_VALUE_CHARS || missing || componentInvalid) {
        const error = document.querySelector(`#field-${field.id}-error`);
        input.setAttribute('aria-invalid', 'true');
        if (error) {
          error.textContent = missing
            ? 'This field is required.'
            : componentInvalid
              ? `Enter the complete ${COMPONENTS[field.component.kind].hint(field.component)}.`
              : 'This value is too long.';
          error.hidden = false;
        }
        input.focus();
        throw new RequestError('field');
      }
      values[field.id] = value;
    }
    return { values };
  }

  function actionBody(request) {
    const approval = document.querySelector('#action-approval');
    if (!approval || !approval.checked) throw new RequestError('approval');
    return { approve: request.approvalNonce };
  }

  async function submit(event) {
    event.preventDefault();
    if (state.sending || !state.request || !ensureFresh()) return;
    state.sending = true;
    const generation = ++state.submissionGeneration;
    dom.send.disabled = true;
    setText('Sending', 'Sending encrypted submission', 'Telegram is receiving the payload. No webpage outcome is claimed.', 'sending');
    try {
      const request = state.request;
      const payload = request.v === 1
        ? await connectionEnvelope(request, generation)
        : await encryptedEnvelope(
          request,
          () => request.kind === 'entry' ? entryBody(request) : actionBody(request),
          generation,
        );
      assertSubmissionActive(request, generation);
      const serialized = JSON.stringify(payload);
      if (utf8Length(serialized) > MAX_SEND_BYTES) throw new RequestError('invalid');
      assertSubmissionActive(request, generation);
      telegram().sendData(serialized);
      state.request = null;
      if (state.expiryTimer !== null) clearTimeout(state.expiryTimer);
      state.expiryTimer = null;
      state.submissionGeneration += 1;
      clearPlaintext();
      dom.privacy.textContent = request.v === 4
        ? 'Encrypted submission sent to the local executor. Goku will inspect the exact live browser.'
        : 'Encrypted connection test sent.';
    } catch (error) {
      state.sending = false;
      if (error instanceof RequestError && error.reason === 'field') {
        clearBuffers();
        dom.send.disabled = false;
        setText('Check entry', 'Check the highlighted field', 'No data was sent. Fix the field and try again.', 'error');
        return;
      }
      if (error instanceof RequestError && (error.reason === 'cancelled' || error.reason === 'expired')) {
        clearBuffers();
        return;
      }
      clearPlaintext();
      const approval = document.querySelector('#action-approval');
      dom.send.disabled = Boolean(approval && !approval.checked);
      setText('Not sent', 'The handoff could not be sent', 'Nothing was claimed about the browser. Close this view and ask Goku for a fresh handoff.', 'error');
    }
  }

  function showFailure(reason) {
    dom.send.hidden = true;
    dom.cancel.hidden = true;
    dom.details.hidden = true;
    if (reason === 'missing') setText('Unavailable', 'This handoff link is missing', 'Ask Goku for a fresh Telegram handoff.', 'error');
    else if (reason === 'expired') setText('Expired', 'This handoff link has expired', 'Ask Goku for a fresh Telegram handoff.', 'error');
    else setText('Unavailable', 'This handoff link is not valid', 'Close this view and ask Goku for a fresh handoff.', 'error');
  }

  function start() {
    const webApp = telegram();
    if (!webApp) {
      setText('Telegram required', 'Open this in Telegram', 'This handoff works only inside the Telegram Mini App.', 'error');
      return;
    }
    webApp.ready();
    try {
      const request = parseRequest();
      state.request = request;
      dom.fields.replaceChildren();
      dom.details.hidden = request.v === 1;
      dom.origin.textContent = request.origin || '';
      dom.send.hidden = false;
      dom.cancel.hidden = false;
      dom.privacy.hidden = false;
      dom.privacy.textContent = request.v === 4
        ? 'Values are encrypted before leaving this Mini App. The plugin never selects submit during entry, but any applied input, selection, or check may activate website handlers. Goku inspects the live browser afterward.'
        : 'The connection marker is encrypted before it leaves this Mini App.';
      if (request.v === 1) renderConnection();
      else if (request.kind === 'entry') renderEntry(request);
      else renderAction(request);
      scheduleExpiry(request);
    } catch (error) {
      showFailure(error instanceof RequestError ? error.reason : 'invalid');
    }
  }

  dom.form.addEventListener('submit', submit);
  dom.cancel.addEventListener('click', () => {
    invalidateSubmission();
    state.request = null;
    if (state.expiryTimer !== null) clearTimeout(state.expiryTimer);
    state.expiryTimer = null;
    clearPlaintext();
    const webApp = telegram();
    if (webApp && typeof webApp.close === 'function') webApp.close();
  });
  function suspendRequest() {
    invalidateSubmission();
    clearPlaintext();
  }
  window.addEventListener('pagehide', suspendRequest);
  window.addEventListener('freeze', suspendRequest);
  window.addEventListener('pageshow', () => {
    if (state.request && ensureFresh()) {
      const approval = document.querySelector('#action-approval');
      dom.send.disabled = Boolean(approval && !approval.checked);
    }
  });
  start();
})();
