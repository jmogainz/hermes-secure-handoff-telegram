"""Regression matrix against real isolated Chromium, never the operator profile."""
import asyncio
import base64
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_purchase_approval import checkout, fill, deliver, envelope

@pytest.mark.asyncio
@pytest.mark.parametrize('script', [
    *[f"document.querySelectorAll('dd')[{i}].textContent += ' changed'" for i in range(6)],
    "document.querySelector('#buy').outerHTML=document.querySelector('#buy').outerHTML",
    "document.querySelector('form').outerHTML=document.querySelector('form').outerHTML",
    "document.querySelector('dl').outerHTML=document.querySelector('dl').outerHTML",
    "document.querySelector('dd').outerHTML=document.querySelector('dd').outerHTML",
    "document.querySelector('input').value='changed-synthetic'",
    "document.querySelector('#buy').textContent='Pay'",
    "document.querySelector('#buy').disabled=true",
    "document.querySelector('form').target='_blank'",
    "document.querySelector('#buy').formAction='/different'",
    "history.pushState({},'', '/different')",
    "document.querySelector('dl').style.opacity='0'",
    "document.querySelector('dl').after(document.querySelector('dl').cloneNode(true))",
])
async def test_changed_binding_blocks_click(tmp_path,script):
    async with checkout(tmp_path, reviewed=True) as (controller,s):
        await fill(controller,s)
        raw=envelope(s, {'approve':s.request['transaction']['id']})
        await s.page.evaluate(script)
        await deliver(controller,s,raw=raw)
        assert s.status=='rejected'
        assert s.request is None and s.key is None
        assert await s.page.evaluate('window.clicks')==0

@pytest.mark.asyncio
async def test_document_replacement_blocks_click(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller,s):
        await fill(controller,s)
        raw=envelope(s, {'approve':s.request['transaction']['id']})
        await s.page.reload()
        await deliver(controller,s,raw=raw)
        assert s.status=='rejected' and s.request is None
        assert await s.page.evaluate('window.clicks || 0')==0

@pytest.mark.asyncio
@pytest.mark.parametrize('body', [{'confirm':True}, {'values':{}}, {'approve':'wrong'}, {'approve':True}])
async def test_wrong_or_legacy_approval_denied(tmp_path,body):
    async with checkout(tmp_path, reviewed=True) as (controller,s):
        await fill(controller,s)
        await deliver(controller,s,body)
        assert s.status=='rejected'
        assert await s.page.evaluate('window.clicks')==0

@pytest.mark.asyncio
async def test_wrong_owner_then_concurrent_double_tap(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller,s):
        details=envelope(s, {'values':{'f0':'synthetic-only'}})
        await deliver(controller,s,raw=details)
        raw=envelope(s, {'approve':s.request['transaction']['id']})
        await deliver(controller,s,raw=raw,owner=99)
        assert s.status=='waiting_for_confirmation'
        await deliver(controller,s,raw=details)
        assert s.status=='waiting_for_confirmation'
        await asyncio.gather(deliver(controller,s,raw=raw),deliver(controller,s,raw=raw))
        assert await s.page.evaluate('window.clicks')==1

@pytest.mark.asyncio
@pytest.mark.parametrize('operation', ['cancel','expire','expire_at_commit','change_at_commit'])
async def test_revocation_and_commit_time_checks(tmp_path,operation):
    async with checkout(tmp_path, reviewed=True) as (controller,s):
        await fill(controller,s)
        raw=envelope(s, {'approve':s.request['transaction']['id']})
        if operation=='cancel':
            await s.lock.acquire()
            submission=asyncio.create_task(deliver(controller,s,raw=raw))
            await asyncio.sleep(0)
            controller._invalidate(s,'cancelled')
            s.lock.release()
            await submission
        elif operation=='expire':
            s.request['expiresAt']=int(time.time()*1000)-1
            await deliver(controller,s,raw=raw)
        else:
            guard=s.commit_guard
            class RaceGuard:
                async def evaluate(self,expression,arg=None):
                    if 'g.commit' in expression:
                        if operation=='expire_at_commit':
                            await guard.evaluate('g=>g.deadline=0')
                        else:
                            await s.page.locator('dd').nth(3).evaluate("e=>e.textContent='99.99'")
                    return await guard.evaluate(expression,arg)
                async def dispose(self): await guard.dispose()
            s.commit_guard=RaceGuard()
            await deliver(controller,s,raw=raw)
        assert s.status in {'cancelled','expired','rejected'}
        assert await s.page.evaluate('window.clicks')==0

@pytest.mark.asyncio
async def test_real_frontend_crypto_to_controller_roundtrip(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller,s):
        mini=await s.context.new_page()
        await mini.set_viewport_size({'width':390,'height':844})
        web=Path(__file__).parents[1]/'web'
        async def route(route):
            name=route.request.url.split('/').pop().split('#')[0] or 'index.html'
            if name not in {'index.html','app.js','styles.css'}:
                await route.abort(); return
            await route.fulfill(path=str(web/name),content_type='application/javascript' if name.endswith('.js') else 'text/css' if name.endswith('.css') else 'text/html')
        await mini.route('https://mini.example/**',route)
        await mini.route('https://telegram.org/**',lambda r:r.fulfill(content_type='application/javascript',body="window.Telegram={WebView:{initParams:{tgWebAppData:''}},WebApp:{platform:'tdesktop',initData:'',initDataUnsafe:{},ready(){},sendData(v){window.sent=v}}}"))
        async def open_request():
            encoded=base64.urlsafe_b64encode(json.dumps(s.request).encode()).decode().rstrip('=')
            await mini.goto('https://mini.example/#request='+encoded+'&tgWebAppVersion=9.6')
        try:
            await open_request()
            assert await mini.locator('#field-f0').input_value() == ''
            await mini.locator('#field-f0').fill('synthetic-only')
            await mini.get_by_role('button',name='Review purchase',exact=True).click()
            await mini.wait_for_function('typeof window.sent === "string"')
            await deliver(controller,s,raw=await mini.evaluate('window.sent'))
            assert s.status=='waiting_for_confirmation'
            await mini.goto('about:blank')
            await open_request()
            assert '12.34' in await mini.locator('#transaction-summary').inner_text()
            assert await mini.locator('#field-list input').count()==0
            await mini.get_by_role('button',name='Complete purchase',exact=True).click()
            await mini.wait_for_function('typeof window.sent === "string"')
            await deliver(controller,s,raw=await mini.evaluate('window.sent'))
            assert s.status=='purchase_submitted'
            assert await s.page.evaluate('window.clicks')==1
            assert 'synthetic-only' not in json.dumps(controller.bot.sent,default=str)
            assert 'synthetic-only' not in (tmp_path/'secure_handoff_receipts.jsonl').read_text()
        finally:
            await mini.close()
