"""Disposable Chromium only; all field content is synthetic."""
import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from telegram.ext import ApplicationHandlerStop
from test_checkout_flow import disposable_controller, Bot, envelope, update
from plugin.demo_site import start_demo

from synthetic_purchase_source import SUMMARY, contract
from plugin import purchase_approval
from urllib.parse import urlsplit
LABELS = ['Item', 'Merchant', 'Currency', 'Total including tax', 'Renewal', 'Terms']

@asynccontextmanager
async def checkout(tmp_path, *, reviewed=False):
    """Generic sources default closed; engine tests opt into synthetic provenance."""
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    controller.loop = asyncio.get_running_loop()
    controller.bot = Bot()
    s = None
    source_patch = pytest.MonkeyPatch()
    try:
        s = await controller._new_session((7, 8, 42), site.login_url, demo=True)
        details = ''.join(f'<dt>{label}</dt><dd>{value}</dd>' for label, value in zip(LABELS, SUMMARY.values()))
        await s.page.set_content('<main><form id="checkout" method="post" action="/purchase">'
            '<input name="billing" autocomplete="cc-number" aria-label="Card number">'
            '<dl aria-label="Transaction summary">' + details + '</dl>'
            '<button id="buy" type="submit">Complete purchase</button></form></main>'
            '<script>window.clicks=0;document.querySelector("form").onsubmit=e=>{e.preventDefault();window.clicks++}</script>')
        assert (await controller._snapshot(s))['status'] == 'waiting_for_handoff'
        if reviewed:
            async def reviewed_source(bound_session):
                assert bound_session is s
                return contract()
            url = urlsplit(s.page.url)
            source_patch.setitem(purchase_approval._REVIEWED_SOURCES,
                                 f'{url.scheme}://{url.netloc}', reviewed_source)
        yield controller, s
    finally:
        source_patch.undo()
        if s:
            await controller._close((7, 8, 42))
            await controller._dispose(s)
        site.close()

async def deliver(controller, s, body=None, raw=None, owner=7):
    event = update(raw or envelope(s, body))
    event.effective_user.id = owner
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(event, SimpleNamespace(bot=controller.bot))

async def fill(controller, s):
    await deliver(controller, s, {'values': {f['id']: 'synthetic-only' for f in s.request['fields']}})

@pytest.mark.asyncio
async def test_fresh_bound_approval_authorizes_exactly_one_click(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        first = s.request['id']
        first_key = s.key
        await fill(controller, s)
        assert s.status == 'waiting_for_confirmation'
        assert s.request['id'] != first
        assert s.key is not None and s.key is not first_key
        assert s.request['mode'] == 'purchase_approval'
        assert s.request['fields'] == []
        assert s.request['transaction']['summary'] == SUMMARY
        assert s.request['actionLabel'] == 'Complete purchase'
        assert await s.page.evaluate('window.clicks') == 0
        raw = envelope(s, {'approve': s.request['transaction']['id']})
        await deliver(controller, s, raw=raw)
        assert s.status == 'purchase_submitted'
        assert s.request is None and s.key is None
        assert await s.page.evaluate('window.clicks') == 1
        await deliver(controller, s, raw=raw)
        assert await s.page.evaluate('window.clicks') == 1
        messages = json.dumps(controller.bot.sent, default=str)
        assert 'synthetic-only' not in messages
        assert 'not proof' in messages

@pytest.mark.asyncio
async def test_present_retains_pending_approval_without_refill(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        await fill(controller, s)
        request = s.request
        assert (await controller._run('present', {}, (7, 8, 42)))['status'] == 'waiting_for_confirmation'
        assert s.request is request
        assert s.request['mode'] == 'purchase_approval'
        await deliver(controller, s, {'approve': request['transaction']['id']})
        assert (await controller._run('read', {}, (7, 8, 42)))['status'] == 'purchase_submitted'
        assert (await controller._run('present', {}, (7, 8, 42)))['status'] == 'purchase_submitted'
        assert s.request is None
        assert await s.page.evaluate('window.clicks') == 1
