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
  // Same purchase display policy as purchase_facts._LEAF; shared regression vectors.
  // Reject, never normalize authoritative identity. Natural RTL letters remain valid.
  const UNSAFE_PURCHASE_DISPLAY = /[\p{Cc}\p{Cf}\p{Cs}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}]/u;
  const ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
  const FIELD_TYPES = new Set(['text', 'email', 'tel', 'number', 'password', 'otp', 'card_number', 'card_expiry', 'cvc', 'select', 'textarea', 'checkbox', 'date', 'time', 'datetime-local', 'month', 'week', 'url', 'search', 'color', 'range']);
  const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];

  const dom = {
    card: document.querySelector('.app-card'),
    kicker: document.querySelector('#status-kicker'),
    title: document.querySelector('#page-title'),
    message: document.querySelector('#status-message'),
    privacyNote: document.querySelector('#privacy-note'),
    sendButton: document.querySelector('#send-button'),
    cancelButton: document.querySelector('#cancel-button'),
    secondary: document.querySelector('#secondary-message'),
    details: document.querySelector('#secure-details'),
    form: document.querySelector('#credential-form'),
    origin: document.querySelector('#request-origin'),
    fields: document.querySelector('#field-list'),
    fieldGroup: document.querySelector('#field-group'),
    fieldCount: document.querySelector('#field-count'),
  };

  const state = {
    request: null,
    publicKey: null,
    telegram: null,
    sending: false,
    version: 1,
    closed: false,
    buffers: new Set(),
    expiryTimer: null,
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
    paymentBlocked: {
      kicker: 'Manual review required',
      title: 'Review payment in the browser',
      message: 'This request has no bound transaction summary. Payment approval is unavailable here. Review the details and complete any purchase yourself on the provider’s page.',
    },
    cancelled: {
      kicker: 'Request closed',
      title: 'Handoff cancelled',
      message: 'Entries were cleared. Reopen the handoff from Telegram to try again.',
    },
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
    secureReady: {
      kicker: 'Ready to submit',
      title: 'Enter secure details',
      message: 'Use the iOS keyboard or Passwords suggestions when available. Entries are encrypted locally before transmission.',
    },
    secureSending: {
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

    if (viewName === 'secureReady') {
      const stageInfo = state.request?.mode === 'form'
        ? { title: 'Fill browser fields', message: 'Fills the selected browser fields without clicking Submit. Entries are encrypted locally.' }
        : resolveStageCopy(state.request?.stage);
      view = { ...view, ...stageInfo, kicker: { form: 'Fill only', auth: 'Secure sign-in', checkout: 'Checkout details' }[state.request?.mode] || view.kicker };
      if (state.request?.mode === 'purchase_approval') view = { kicker: 'Explicit purchase approval', title: 'Review purchase', message: 'Complete purchase authorizes one bound checkout action. Review the selected facts and limitations. This does not prove payment or ownership; provider verification is required.' };
      if (state.request?.mode === 'source_approval') view = { kicker: 'Source selection only', title: 'Review selected source', message: 'Review the exact product page in the original browser. Allow only a public, nonpersonal product page suitable for selected purchase metadata. This does not authorize a purchase or certify privacy, price, or financial terms.' };
      if (state.request?.mode === 'checkout') view.message = 'Send the requested details securely. This does not authorize a purchase. Complete any payment yourself in the browser.';
    }

    const isError = ['missing', 'outside', 'expired', 'invalid', 'unsupported', 'cancelled'].includes(viewName);
    const isRetry = viewName === 'sendFailed';
    const isSending = viewName === 'sending' || viewName === 'secureSending';
    const isBlocked = viewName === 'paymentBlocked';
    const isSecure = state.version === 3;
    if (isSecure && isRetry) view = { kicker: 'Submission not confirmed', title: 'Your entries were cleared', message: 'We could not confirm this submission. Your entries were cleared for privacy. Check Telegram before trying again.' };
    const showButton = viewName === 'ready' || isRetry || viewName === 'secureReady';

    dom.card.dataset.state = isError ? 'error' : isRetry ? 'send-failed' : viewName;
    if (dom.kicker) dom.kicker.textContent = view.kicker;
    dom.title.textContent = view.title;
    dom.message.textContent = view.message;
    if (dom.secondary) dom.secondary.textContent = view.secondary || '';
    dom.sendButton.hidden = !showButton && !isSending;
    dom.sendButton.disabled = isSending || isError || isBlocked || state.closed ||
      (state.request?.transaction?.contract === 'observed_action_v1' && !document.getElementById('purchase-acknowledgment')?.checked) ||
      (state.request?.mode === 'source_approval' && !document.getElementById('source-acknowledgment')?.checked);
    dom.form.setAttribute('aria-busy', String(isSending));
    if (isError || isRetry || isBlocked) clearPlaintext();
    if (isError) { state.closed = true; state.publicKey = null; clearTimeout(state.expiryTimer); }
    for (const control of dom.fields.querySelectorAll('input, textarea, select')) control.disabled = isSending || isError || state.closed;
    dom.cancelButton.hidden = !isSecure || isError || state.closed;
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
      dom.privacyNote.hidden = !isSecure || isError || isBlocked;
      dom.privacyNote.textContent = 'Encrypted on this device. This page does not store your entries.';
    }
    dom.details.hidden = !isSecure || isError;
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

    if (!request || typeof request !== 'object' || Array.isArray(request) || ![1, 3].includes(request.v)) {
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
    if (request.v === 3) validateV3Request(request);
    return request;
  }

  function validateV3Request(request) {
    const allowedKeys = new Set(['v', 'id', 'expiresAt', 'publicKey', 'origin', 'mode', 'actionLabel', 'fields', 'stage', 'provider', 'demo', 'transaction', 'composition', 'source']);
    if (Object.keys(request).some(key => !allowedKeys.has(key))) throw new RequestError('invalid');
    let origin;
    try { origin = new URL(request.origin); } catch { throw new RequestError('invalid'); }
    if (origin.protocol !== 'https:' || origin.origin !== request.origin || origin.username || origin.password || origin.search || origin.hash) throw new RequestError('invalid');
    if (!['auth', 'checkout', 'payment_confirmation', 'purchase_approval', 'source_approval', 'form'].includes(request.mode)) throw new RequestError('invalid');
    if (typeof request.actionLabel !== 'string' || !request.actionLabel.trim() || request.actionLabel.length > 80 || /[\x00-\x1f\x7f]/.test(request.actionLabel)) throw new RequestError('invalid');
    if (request.mode === 'form' && request.actionLabel !== 'Fill fields') throw new RequestError('invalid');
    if (!Array.isArray(request.fields) || request.fields.length > MAX_FIELDS) throw new RequestError('invalid');
    if (['payment_confirmation', 'purchase_approval', 'source_approval'].includes(request.mode) ? request.fields.length !== 0 : request.fields.length < 1) throw new RequestError('invalid');
    if (request.mode === 'source_approval') {
      const source=request.source;
      const keys=['v','id','expiresAt','publicKey','origin','mode','actionLabel','fields','stage','provider','demo','source'];
      if (Object.keys(request).length!==keys.length || keys.some(k=>!Object.hasOwn(request,k)) ||
          request.stage!=='source_approval' || request.provider!=='generic' || request.demo!==false ||
          request.actionLabel!=='Allow selected source' || !source || Array.isArray(source) ||
          Object.keys(source).length!==2 || typeof source.nonce!=='string' || !/^sg_[A-Za-z0-9_-]{32}$/.test(source.nonce) ||
          !Number.isInteger(source.ordinal) || source.ordinal<1 || source.ordinal>64) throw new RequestError('invalid');
      Object.freeze(source);
    } else if (request.source!==undefined) throw new RequestError('invalid');
    if (request.mode === 'purchase_approval') {
      const t = request.transaction;
      if (t?.contract === 'observed_action_v1') {
        validateObservedPurchase(request);
      } else {
      if (t?.contract !== undefined) throw new RequestError('invalid');
      const keys = ['item', 'merchant', 'currency', 'totalIncludingTax', 'renewal', 'terms'];
      if (request.actionLabel !== 'Complete purchase' || request.stage !== 'purchase_approval' || !t ||
          Object.keys(t).length !== 2 || typeof t.id !== 'string' || !/^tx_[A-Za-z0-9_-]{32}$/.test(t.id) ||
          !t.summary || Object.keys(t.summary).length !== keys.length || keys.some(k => typeof t.summary[k] !== 'string' ||
          !t.summary[k].trim() || t.summary[k].length > 512 || /[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/.test(t.summary[k])) ||
          !/^[A-Z]{3}$/.test(t.summary.currency) || !/^(0|[1-9][0-9]{0,8})\.[0-9]{2}$/.test(t.summary.totalIncludingTax)) throw new RequestError('invalid');
      const recurring = new RegExp('^Renews (daily|weekly|monthly|annually) at ' + t.summary.currency + ' (0|[1-9][0-9]{0,8})\\.[0-9]{2} including tax; cancel before renewal\\.$');
      if (t.summary.renewal !== 'No renewal. One-time purchase.' && !recurring.test(t.summary.renewal)) throw new RequestError('invalid');
      Object.freeze(t.summary); Object.freeze(t);
      }
    } else if (request.transaction !== undefined) throw new RequestError('invalid');
    const safeToken = /^[A-Za-z0-9_-]{1,64}$/;
    if (request.stage !== undefined && (typeof request.stage !== 'string' || !safeToken.test(request.stage))) throw new RequestError('invalid');
    if (request.provider !== undefined && (typeof request.provider !== 'string' || !safeToken.test(request.provider))) throw new RequestError('invalid');
    const ids = new Set();
    const fieldIdPattern = /^f(?:[0-9]|1[0-9]|2[0-3])$/;
    const safeOption = value => typeof value === 'string' && value.length <= 128 && !/[\x00-\x1f\x7f]/.test(value);
    const allowedFieldKeys = new Set(['id', 'label', 'type', 'required', 'autocomplete', 'inputMode', 'options', 'selectionMode']);
    for (const field of request.fields) {
      if (!field || typeof field !== 'object' || Array.isArray(field) || Object.keys(field).some(key => !allowedFieldKeys.has(key)) || typeof field.id !== 'string' || !fieldIdPattern.test(field.id) || ids.has(field.id)) throw new RequestError('invalid');
      if (typeof field.label !== 'string' || !field.label.trim() || field.label.length > 80 || /[\x00-\x1f\x7f]/.test(field.label) || !FIELD_TYPES.has(field.type)) throw new RequestError('invalid');
      if (typeof field.required !== 'boolean') throw new RequestError('invalid');
      if (field.autocomplete !== undefined && (typeof field.autocomplete !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(field.autocomplete))) throw new RequestError('invalid');
      if (field.inputMode !== undefined && !['text', 'numeric', 'decimal', 'tel', 'email'].includes(field.inputMode)) throw new RequestError('invalid');
      if (field.selectionMode !== undefined && field.selectionMode !== 'search') throw new RequestError('invalid');
      if (field.type === 'select') {
        if (field.selectionMode === 'search') {
          if (field.options !== undefined) throw new RequestError('invalid');
        } else {
          if (!Array.isArray(field.options) || field.options.length < 1 || field.options.length > 64) throw new RequestError('invalid');
          const values = new Set();
          for (const option of field.options) {
            if (!option || typeof option !== 'object' || Array.isArray(option) || Object.keys(option).length !== 2 || !safeOption(option.value) || !safeOption(option.label) || !option.label.trim() || values.has(option.value)) throw new RequestError('invalid');
            values.add(option.value);
          }
        }
      } else if (field.options !== undefined || field.selectionMode !== undefined) {
        throw new RequestError('invalid');
      }
      ids.add(field.id);
    }
    if (request.composition !== undefined) {
      const c = request.composition;
      const titles = ['details','contact','address','payment','other'];
      if (request.mode !== 'form' || !c || Object.keys(c).length !== 2 ||
          !['stack','sections'].includes(c.layout) || !Array.isArray(c.groups) || c.groups.length < 1 || c.groups.length > 8) throw new RequestError('invalid');
      const visualIds = [];
      for (const group of c.groups) {
        if (!group || Object.keys(group).length !== 2 || !titles.includes(group.title) ||
            !Array.isArray(group.fields) || group.fields.length < 1 || group.fields.length > MAX_FIELDS ||
            group.fields.some(id => !ids.has(id))) throw new RequestError('invalid');
        visualIds.push(...group.fields);
      }
      if (visualIds.length !== ids.size || new Set(visualIds).size !== ids.size ||
          request.fields.some(f => ['checkbox','range','color'].includes(f.type) || f.selectionMode)) throw new RequestError('invalid');
    }
    if (typeof request.demo !== 'boolean') throw new RequestError('invalid');
  }

  function validateObservedPurchase(request) {
    const t=request.transaction;
    const exact=(o,keys)=>o && typeof o==='object' && !Array.isArray(o) && Object.keys(o).length===keys.length && keys.every(k=>Object.hasOwn(o,k));
    const ref=(s,p)=>typeof s==='string' && new RegExp('^'+p+'[A-Za-z0-9_-]{32}$').test(s);
    if(request.actionLabel!=='Complete purchase' || request.stage!=='purchase_approval' ||
       !exact(t,['contract','revision','facts','action','coverage','id','warningVersion']) ||
       !ref(t.id,'tx_') || !ref(t.revision,'pr_') || t.coverage!=='selected_facts_only' ||
       t.warningVersion!=='unresolved_terms_v1' || !exact(t.action,['ref','role','label']) ||
       !ref(t.action.ref,'pa_') || t.action.role!=='purchase_action' || t.action.label!=='Bound purchase action' ||
       !Array.isArray(t.facts) || t.facts.length<2 || t.facts.length>23) throw new RequestError('invalid');
    const roles=[], refs=new Set(), currencies=new Set();
    const precision={USD:2,EUR:2,GBP:2,CAD:2,AUD:2,NZD:2,JPY:0,KWD:3};
    for(const f of t.facts) {
      if(!f || !ref(f.ref,'pf_') || refs.has(f.ref)) throw new RequestError('invalid');
      refs.add(f.ref); roles.push(f.role);
      if(f.role==='item') {
        if(!exact(f,['ref','role','value','provenance']) || f.provenance!=='public_product_matched' ||
           typeof f.value!=='string' || !f.value || f.value.length>160 || f.value!==f.value.trim() || UNSAFE_PURCHASE_DISPLAY.test(f.value)) throw new RequestError('invalid');
      } else {
        if(!['displayed_total','subtotal','tax','fee','discount'].includes(f.role) ||
           !exact(f,['ref','role','amount','currency','provenance']) || f.provenance!=='checkout_observation' ||
           !Object.hasOwn(precision,f.currency) || typeof f.amount!=='string') throw new RequestError('invalid');
        const digits=precision[f.currency];
        if(!new RegExp('^(0|[1-9][0-9]{0,8})'+(digits?'\\.[0-9]{'+digits+'}':'')+'$').test(f.amount)) throw new RequestError('invalid');
        currencies.add(f.currency);
      }
      Object.freeze(f);
    }
    if(roles.filter(r=>r==='item').length!==1 || roles.filter(r=>r==='displayed_total').length!==1 || currencies.size!==1) throw new RequestError('invalid');
    Object.freeze(t.facts); Object.freeze(t.action); Object.freeze(t);
  }

  function defaultFieldAttributes(field, request) {
    const defaults = {
      text: { name: 'username', autocomplete: 'off', inputMode: 'text', type: 'text', enterKeyHint: 'next' },
      email: { name: 'email', autocomplete: 'email', inputMode: 'email', type: 'email', enterKeyHint: 'next' },
      tel: { name: 'tel', autocomplete: 'tel', inputMode: 'tel', type: 'tel', enterKeyHint: 'next' },
      number: { name: 'number', autocomplete: 'off', inputMode: 'decimal', type: 'number', enterKeyHint: 'next' },
      password: { name: 'password', autocomplete: 'current-password', inputMode: 'text', type: 'password', enterKeyHint: 'go' },
      otp: { name: 'one-time-code', autocomplete: 'one-time-code', inputMode: 'numeric', type: 'text', enterKeyHint: 'done' },
      card_number: { name: 'cardnumber', autocomplete: 'cc-number', inputMode: 'numeric', type: 'password', enterKeyHint: 'next' },
      card_expiry: { name: 'cc-exp', autocomplete: 'cc-exp', inputMode: 'numeric', type: 'text', enterKeyHint: 'next' },
      cvc: { name: 'csc', autocomplete: 'cc-csc', inputMode: 'numeric', type: 'password', enterKeyHint: 'done' },
    };
    if (field.type === 'select' && field.selectionMode === 'search') {
      return { name: field.id, autocomplete: 'off', inputMode: 'text', type: 'text', enterKeyHint: 'next' };
    }
    if (field.type === 'text' && request?.mode === 'auth' && request.stage === 'identifier') {
      return { ...defaults.text, name: 'username', autocomplete: 'username' };
    }
    return defaults[field.type] || { name: field.id, autocomplete: 'off', type: field.type, enterKeyHint: 'next' };
  }

  function renderSecureFields(request) {
    dom.origin.textContent = request.origin;
    dom.fields.replaceChildren();
    dom.fieldCount.textContent = `${request.fields.length} ${request.fields.length === 1 ? 'field' : 'fields'}`;
    dom.fieldGroup.hidden = request.mode === 'payment_confirmation';
    if (request.mode === 'source_approval') {
      dom.fieldGroup.hidden=true;
      const note=document.createElement('p');
      note.textContent=`Browser-context tab ${request.source.ordinal} at ${request.origin}. The ordinal is the runtime browser-context list position, not a page title or a guarantee of visual tab order. Review the exact page in the original browser; if you cannot identify it unambiguously, cancel. Do not allow account, billing, checkout, or personal pages. Only the restricted product-name source may be used; this is not permission to expose private data.`;
      const label=document.createElement('label'),ack=document.createElement('input');
      ack.type='checkbox';ack.id='source-acknowledgment';ack.checked=false;
      label.append(ack,document.createTextNode(' I reviewed this exact source in the original browser and select it as a public, nonpersonal product page suitable for selected purchase metadata. No purchase is authorized.'));
      dom.details.append(note,label);
      ack.addEventListener('change',()=>{dom.sendButton.disabled=!ack.checked || state.closed || state.sending;});
      return;
    }
    if (request.mode === 'purchase_approval') {
      dom.fieldGroup.hidden = true;
      const summary = document.createElement('dl');
      summary.id = 'transaction-summary';
      if (request.transaction.contract === 'observed_action_v1') {
        const labels={item:'Item',displayed_total:'Displayed checkout total',subtotal:'Subtotal',tax:'Tax',fee:'Fee',discount:'Discount'};
        const row=(label,value)=>{const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value;summary.append(dt,dd);};
        row('Website',request.origin);
        for(const f of request.transaction.facts) row(labels[f.role],f.role==='item'?f.value:f.currency+' '+f.amount);
        row('Renewal','Not established from the selected facts');
        row('Other terms','Only selected facts are shown. The full contract has not been reviewed here.');
        row('Payment method','Uses the payment method currently selected on the website; details are not shown here.');
        row('Authorization','One click on this checkout’s Bound purchase action. It may charge you or start a subscription. This does not guarantee the merchant’s final charge or that every term appears here.');
        dom.details.append(summary);
        const label=document.createElement('label'),ack=document.createElement('input');
        ack.type='checkbox';ack.id='purchase-acknowledgment';ack.checked=false;
        label.append(ack,document.createTextNode(' I understand the unresolved terms shown above and want to submit this checkout.'));
        dom.details.append(label);
        ack.addEventListener('change',()=>{dom.sendButton.disabled=!ack.checked || state.closed || state.sending;});
        return;
      }
      const labels = { item: 'Item / domain', merchant: 'Merchant', currency: 'Currency', totalIncludingTax: 'Total including tax', renewal: 'Renewal / recurrence', terms: 'Terms' };
      for (const [key, label] of Object.entries(labels)) {
        const dt = document.createElement('dt'), dd = document.createElement('dd');
        dt.textContent = label; dd.textContent = request.transaction.summary[key];
        summary.append(dt, dd);
      }
      dom.details.append(summary);
      return;
    }
    if (request.v === 3 && request.mode === 'payment_confirmation') return;
    const containers = new Map();
    let visualFields = request.fields;
    if (request.composition) {
      dom.fields.dataset.compositionLayout = request.composition.layout;
      const names = {details:'Details',contact:'Contact',address:'Address',payment:'Payment',other:'Other'};
      for (const group of request.composition.groups) {
        const section = document.createElement('section'); section.className = 'composition-group';
        const heading = document.createElement('h3'); heading.textContent = names[group.title];
        section.appendChild(heading); dom.fields.appendChild(section);
        for (const id of group.fields) containers.set(id,section);
      }
      visualFields = request.composition.groups.flatMap(g => g.fields.map(id => request.fields.find(f => f.id === id)));
    }
    for (const field of visualFields) {
      const wrapper = document.createElement('div'); wrapper.className = 'field-row';
      const label = document.createElement('label'); label.textContent = field.label; label.htmlFor = `field-${field.id}`;
      if (field.required) { const required = document.createElement('span'); required.textContent = 'Required'; required.className = 'required-mark'; label.appendChild(required); }
      const searchSelect = field.type === 'select' && field.selectionMode === 'search';
      const select = field.type === 'select' && !searchSelect;
      const input = document.createElement(select ? 'select' : field.type === 'textarea' ? 'textarea' : 'input');
      input.id = `field-${field.id}`;
      input.name = select || searchSelect ? field.id : defaultFieldAttributes(field, request).name;
      input.setAttribute('aria-label', field.label);
      input.setAttribute('aria-describedby', `status-message error-${field.id}`);
      input.required = field.required;
      input.dataset.fieldType = field.type;
      if (select) {
        if (!field.options.some(option => option.value === '')) {
          const placeholder = document.createElement('option');
          placeholder.value = ''; placeholder.textContent = 'Choose an option';
          placeholder.disabled = field.required;
          input.appendChild(placeholder);
        }
        for (const option of field.options || []) {
          const element = document.createElement('option');
          element.value = option.value;
          element.textContent = option.label;
          input.appendChild(element);
        }
        input.value = '';
      } else {
        const attributes = defaultFieldAttributes(field, request);
        if (field.type !== 'textarea') input.type = attributes.type;
        if (field.type === 'number') input.step = 'any';
        input.maxLength = 512;
        input.autocomplete = field.autocomplete || attributes.autocomplete;
        input.enterKeyHint = attributes.enterKeyHint;
        if (field.inputMode || attributes.inputMode) input.inputMode = field.inputMode || attributes.inputMode;
        input.autocapitalize = 'none';
        input.autocorrect = 'off';
        input.spellcheck = false;
        if (searchSelect) input.placeholder = 'Type the exact option label shown in the browser';
      }
      wrapper.append(label, input);
      const error = document.createElement('small');
      error.id = `error-${field.id}`; error.className = 'field-error'; error.hidden = true;
      error.setAttribute('role', 'alert');
      wrapper.appendChild(error);
      if (request.demo && field.type === 'text') { const hint = document.createElement('small'); hint.textContent = 'Demo example: demo'; wrapper.appendChild(hint); }
      if (request.demo && field.type === 'password') { const hint = document.createElement('small'); hint.textContent = 'Demo example: demo-pass'; wrapper.appendChild(hint); }
      if (searchSelect) { const hint = document.createElement('small'); hint.textContent = 'Type the option label exactly as it appears in the browser.'; wrapper.appendChild(hint); }
      (containers.get(field.id) || dom.fields).appendChild(wrapper);
    }
  }

  function clearPlaintext() {
    for (const buffer of state.buffers) buffer.fill(0);
    state.buffers.clear();
    for (const error of dom.fields.querySelectorAll('.field-error')) { error.textContent = ''; error.hidden = true; }
    for (const input of dom.fields.querySelectorAll('input, textarea, select')) {
      input.value = '';
      if (input.tagName === 'SELECT') input.selectedIndex = -1;
      if (input.tagName === 'INPUT') input.checked = false;
      input.removeAttribute('value');
      input.removeAttribute('checked');
      input.setCustomValidity('');
      input.removeAttribute('aria-invalid');
    }
  }

  function validTypedValue(field, input, value) {
    if (value.length > 512) return false;
    if (field.type === 'checkbox') return !field.required || value === 'true';
    if (field.required && !(field.type === 'password' ? value : value.trim())) return false;
    if (field.type === 'select') return field.selectionMode === 'search' ? Boolean(value.trim()) : field.options.some(option => option.value === value);
    if (!value) return !input.validity.badInput;
    if (['number', 'range'].includes(field.type)) {
      if (!/^-?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(value) || !Number.isFinite(Number(value))) return false;
      if (field.type === 'range' && (Number(value) < 0 || Number(value) > 100 || !Number.isInteger(Number(value)))) return false;
    }
    // WebKit can render month/week as text. Validate the wire type independently
    // of the rendered input type, and never rely on native validation alone.
    if (['date', 'datetime-local', 'month', 'week'].includes(field.type)) {
      const pattern = { date: /^(\d{4})-(\d{2})-(\d{2})$/, 'datetime-local': /^(\d{4})-(\d{2})-(\d{2})T(.+)$/, month: /^(\d{4})-(\d{2})$/, week: /^(\d{4})-W(\d{2})$/ }[field.type];
      const parts = value.match(pattern);
      if (!parts || Number(parts[1]) < 1) return false;
      const year = Number(parts[1]), unit = Number(parts[2]);
      if (field.type === 'week') {
        const jan = new Date(`${parts[1]}-01-01T00:00:00Z`).getUTCDay();
        const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
        if (unit < 1 || unit > (jan === 4 || (jan === 3 && leap) ? 53 : 52)) return false;
      } else {
        if (unit < 1 || unit > 12) return false;
        if (parts[3]) {
          const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
          const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][unit - 1];
          if (Number(parts[3]) < 1 || Number(parts[3]) > days) return false;
        }
        if (field.type === 'datetime-local' && !validTime(parts[4])) return false;
      }
    }
    if (field.type === 'time' && !validTime(value)) return false;
    if (field.type === 'color' && !/^#[0-9a-f]{6}$/i.test(value)) return false;
    const probe = document.createElement('input');
    probe.type = defaultFieldAttributes(field, state.request).type;
    probe.step = 'any';
    probe.value = value;
    const valid = !probe.validity.typeMismatch && !probe.validity.badInput;
    probe.value = '';
    return valid;
  }

  function validTime(value) {
    return /^(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d{1,3})?)?$/.test(value);
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
    if (state.closed || state.sending || !state.request || !state.publicKey || !state.telegram) return;
    if (state.request.mode === 'payment_confirmation') { render('paymentBlocked'); return; }

    if (state.version === 3) return sendSecure();
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

  async function sendSecure(denySource = false) {
    if (state.closed || state.sending || state.request.mode === 'payment_confirmation') return;
    if (state.request.transaction?.contract === 'observed_action_v1' && !document.getElementById('purchase-acknowledgment')?.checked) return;
    if (state.request.mode === 'source_approval' && !denySource && !document.getElementById('source-acknowledgment')?.checked) return;
    const values = {};
    const controls = [];
    for (const field of state.request.fields) {
      const input = document.getElementById(`field-${field.id}`);
      if (!input) { clearPlaintext(); render('invalid'); return; }
      controls.push(input);
      const value = field.type === 'checkbox' ? String(input.checked) : input.value;
      input.setCustomValidity('');
      if (!validTypedValue(field, input, value)) {
        clearPlaintext();
        input.setAttribute('aria-invalid', 'true');
        input.setCustomValidity('Check this field. Entries were cleared for privacy.');
        const error = document.getElementById(`error-${field.id}`);
        error.textContent = { email: 'Enter a valid email address.', url: 'Enter a complete, valid URL.', checkbox: 'Select this required checkbox.', select: field.selectionMode === 'search' ? 'Enter the exact option label shown in the browser.' : 'Choose one of the listed options.' }[field.type] || 'Check this field and enter a valid value.';
        error.hidden = false;
        dom.message.textContent = 'Check the highlighted field and enter your details again. All entries were cleared for privacy.';
        input.focus(); input.reportValidity(); return;
      }
    }
    for (const [index, field] of state.request.fields.entries()) values[field.id] = field.type === 'checkbox' ? String(controls[index].checked) : controls[index].value;
    state.sending = true; render('secureSending');
    let plainBytes;
    let rawKeyBytes;
    try {
      plainBytes = new TextEncoder().encode(JSON.stringify(state.request.mode === 'source_approval' ? (denySource ? { deny: state.request.source.nonce } : { grant: state.request.source.nonce }) : state.request.mode === 'purchase_approval' ? { approve: state.request.transaction.id } : { values }));
      for (const id of Object.keys(values)) delete values[id];
      clearPlaintext();
      state.buffers.add(plainBytes);
      if (plainBytes.byteLength > 2048 || Date.now() >= state.request.expiresAt) throw new RequestError(Date.now() >= state.request.expiresAt ? 'expired' : 'invalid');
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      if (state.closed) return;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(state.request.id) }, key, plainBytes);
      plainBytes.fill(0);
      if (state.closed) return;
      rawKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', key));
      state.buffers.add(rawKeyBytes);
      if (state.closed) return;
      const wrappedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, state.publicKey, rawKeyBytes);
      rawKeyBytes.fill(0);
      if (state.closed) return;
      const payload = JSON.stringify({ v: state.version, id: state.request.id, wrappedKey: encodeBase64Url(new Uint8Array(wrappedKey)), iv: encodeBase64Url(iv), ciphertext: encodeBase64Url(new Uint8Array(ciphertext)) });
      if (utf8ByteLength(payload) > MAX_SEND_DATA_BYTES) throw new RequestError('invalid');
      if (Date.now() >= state.request.expiresAt) throw new RequestError('expired');
      clearPlaintext();
      for (const id of Object.keys(values)) delete values[id];
      plainBytes.fill(0);
      rawKeyBytes.fill(0);
      await Promise.resolve(state.telegram.sendData(payload));
      state.closed = true;
      state.publicKey = null;
      clearTimeout(state.expiryTimer);
      dom.cancelButton.hidden = true;
    } catch (error) {
      if (!state.closed) {
        state.sending = false;
        if (state.request.mode === 'purchase_approval') {
          state.closed = true; state.publicKey = null; clearTimeout(state.expiryTimer);
          render('sendFailed');
          dom.message.textContent = 'Purchase submission could not be confirmed. Do not retry; verify the provider result first.';
        } else render(error instanceof RequestError && views[error.code] ? error.code : 'sendFailed');
      }
    } finally {
      for (const id of Object.keys(values)) delete values[id];
      clearPlaintext();
      if (plainBytes) plainBytes.fill(0);
      if (rawKeyBytes) rawKeyBytes.fill(0);
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
      if (state.closed) return;
      if (Date.now() >= request.expiresAt) throw new RequestError('expired');
      state.request = request;
      state.version = request.v;
      state.publicKey = publicKey;
      state.telegram = telegram;
      if (request.v === 3) { renderSecureFields(request); render(request.mode === 'payment_confirmation' ? 'paymentBlocked' : 'secureReady'); }
      else render('ready');
      state.expiryTimer = setTimeout(() => {
        if (!state.closed) render('expired');
      }, Math.max(0, request.expiresAt - Date.now()));
      if (typeof telegram.ready === 'function') telegram.ready();
    } catch (error) {
      if (state.closed) return;
      render(error instanceof RequestError && views[error.code] ? error.code : 'unsupported');
    }
  }

  dom.form.addEventListener('submit', (event) => {
    event.preventDefault();
    void sendTest();
  });
  function closeRequest() {
    state.closed = true;
    state.publicKey = null;
    clearPlaintext();
    render('cancelled');
  }
  dom.cancelButton.addEventListener('click', () => {
    if (state.request?.mode === 'source_approval') { void sendSecure(true); return; }
    closeRequest();
    try { state.telegram?.close?.(); } catch { /* Closing is best-effort; plaintext is already cleared. */ }
  });
  dom.form.addEventListener('input', event => {
    if (event.target.matches('input, textarea, select')) {
      event.target.setCustomValidity('');
      event.target.removeAttribute('aria-invalid');
      const error = document.getElementById(`error-${event.target.id.replace('field-', '')}`);
      if (error) { error.hidden = true; error.textContent = ''; }
    }
  });
  window.addEventListener('pagehide', closeRequest);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    void boot();
  }
})();
