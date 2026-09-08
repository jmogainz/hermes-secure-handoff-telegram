"""Retained final-review fixtures. Bare Verify expectation corrected to fill-only.
Disposable intercepted Chromium and synthetic values only.
"""
import asyncio
import pytest
from test_security_boundary import fixture, encrypted, submit

@pytest.mark.asyncio
@pytest.mark.parametrize('hint', ['username', 'current-password'])
@pytest.mark.parametrize('button', ['Submit', 'Continue', 'Next'])
async def test_legitimate_non_auth_form_never_explicitly_submits(fixture, hint, button):
    purpose = 'Delete account' if hint == 'current-password' else 'Change public username'
    kind = 'password' if hint == 'current-password' else 'text'
    c, s, p = await fixture(f'<main><h1>{purpose}</h1><form action="/account/settings"><label>{purpose}<input type="{kind}" autocomplete="{hint}"></label><button>{button}</button></form></main><script>document.querySelector("form").onsubmit=e=>{{e.preventDefault();window.nonAuthSubmissions=(window.nonAuthSubmissions||0)+1}}</script>')
    result = await c._run('present', {}, (7,7,None))
    assert result['status'] == 'waiting_for_handoff'
    assert s.request['mode'] == 'form'
    await submit(c, encrypted(s.request, s.key, {'values': {'f0':'SYNTHETIC'}}))
    assert await p.evaluate('window.nonAuthSubmissions || 0') == 0
    assert s.status == 'filled'
    assert s.key is None and s.request is None and s.commit_guard is None
    assert not s.refs and not s.commit_slots

@pytest.mark.asyncio
@pytest.mark.parametrize('button', ['Sign in', 'Log in', 'Verify'])
async def test_meaningful_auth_action_and_terminal_cleanup(fixture, button):
    c, s, p = await fixture(f'<form action="/login"><input type="password" autocomplete="current-password"><button type="button" onclick="window.authClicks=1;document.body.innerHTML=\'Done\'">{button}</button></form>')
    await c._run('present', {}, (7,7,None))
    expected_auth = button in {'Sign in', 'Log in'}
    assert s.request['mode'] == ('auth' if expected_auth else 'form')
    await submit(c, encrypted(s.request, s.key, {'values': {'f0':'SYNTHETIC'}}))
    assert await p.evaluate('window.authClicks || 0') == (1 if expected_auth else 0)
    assert s.status == ('submitted' if expected_auth else 'filled')
    assert s.key is None and s.request is None and s.commit_guard is None
    assert not s.refs and not s.commit_slots

@pytest.mark.asyncio
@pytest.mark.parametrize('ending', ['close', 'expiry', 'rejected'])
async def test_terminal_releases_capability(fixture, ending):
    c, s, p = await fixture('<form><input></form>')
    await c._run('present', {'mode':'form'}, (7,7,None))
    raw = encrypted(s.request, s.key, {'values': {'f0':'SYNTHETIC'}})
    if ending == 'close':
        await c._close((7,7,None))
    elif ending == 'expiry':
        await c._deadline_expired(s, s.request['id'])
    else:
        await p.locator('input').evaluate('e=>e.name="different-purpose"')
        await submit(c, raw)
    assert s.key is None and s.request is None and s.commit_guard is None
    assert not s.refs and not s.commit_slots and s.document is None
    await submit(c, raw)
    assert await p.locator('input').input_value() == ''
