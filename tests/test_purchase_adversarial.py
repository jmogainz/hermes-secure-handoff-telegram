import asyncio
import time
from types import SimpleNamespace

import pytest
from test_purchase_approval import checkout, fill, deliver, envelope

@pytest.mark.asyncio
async def test_post_click_transport_failure_is_terminal_outcome_unknown(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        await fill(controller, s)
        raw = envelope(s, {'approve': s.request['transaction']['id']})
        original = s.commit_guard
        class LostAcknowledgment:
            async def evaluate(self, expression, arg=None):
                result = await original.evaluate(expression, arg)
                if 'g.commit' in expression:
                    raise ConnectionError('synthetic lost acknowledgement')
                return result
            async def dispose(self):
                await original.dispose()
        s.commit_guard = LostAcknowledgment()
        await deliver(controller, s, raw=raw)
        assert s.status == 'outcome_unknown'
        assert s.request is None and s.key is None
        await deliver(controller, s, raw=raw)
        assert await s.page.evaluate('window.clicks') == 1
        assert (await controller._run('present', {}, (7,8,42)))['status'] == 'outcome_unknown'

@pytest.mark.asyncio
@pytest.mark.parametrize('index,text', [(4,'Unknown'), (4,'Auto-renews'), (5,'TBD'), (3,'$12.34'), (2,'$'), (3,'12.34 plus applicable tax'), (0,'example.test\u202e')])
@pytest.mark.parametrize('reviewed', [False, True])
async def test_incomplete_summary_cannot_publish_approval(tmp_path,index,text, reviewed):
    async with checkout(tmp_path, reviewed=reviewed) as (controller, s):
        await s.page.locator('dd').nth(index).evaluate('(e,t)=>e.textContent=t', text)
        await fill(controller, s)
        assert s.status == 'human_action_required'
        assert s.request is None and s.key is None
        assert await s.page.evaluate('window.clicks') == 0

@pytest.mark.asyncio
async def test_summary_change_then_restore_invalidates_original_approval(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller,s):
        await fill(controller,s)
        raw=envelope(s, {'approve':s.request['transaction']['id']})
        await s.page.locator('dd').nth(3).evaluate("e=>{const t=e.textContent;e.textContent='99.99';e.textContent=t;}")
        await deliver(controller,s,raw=raw)
        assert s.status=='rejected'
        assert await s.page.evaluate('window.clicks')==0

@pytest.mark.asyncio
@pytest.mark.parametrize('reviewed', [False, True])
async def test_echoed_private_field_in_summary_is_not_published(tmp_path, reviewed):
    async with checkout(tmp_path, reviewed=reviewed) as (controller,s):
        await s.page.evaluate("document.querySelector('input').addEventListener('input',e=>document.querySelector('dd').textContent=e.target.value)")
        await fill(controller,s)
        assert s.status=='human_action_required'
        assert 'synthetic-only' not in str(controller.bot.sent)
        assert await s.page.evaluate('window.clicks')==0

@pytest.mark.asyncio
async def test_cancelled_task_after_click_scrubs_with_unknown_outcome(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller,s):
        await fill(controller,s)
        raw=envelope(s, {'approve':s.request['transaction']['id']})
        guard=s.commit_guard
        class CancelAfterClick:
            async def evaluate(self,expression,arg=None):
                result=await guard.evaluate(expression,arg)
                if 'g.commit' in expression: raise asyncio.CancelledError
                return result
            async def dispose(self): await guard.dispose()
        s.commit_guard=CancelAfterClick()
        with pytest.raises(asyncio.CancelledError):
            await controller._web_data(__import__('test_checkout_flow').update(raw),SimpleNamespace(bot=controller.bot))
        assert s.status=='outcome_unknown'
        assert s.request is None and s.key is None
        assert await s.page.evaluate('window.clicks')==1

@pytest.mark.asyncio
async def test_cancelled_publication_revokes_delivered_approval(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller,s):
        original=controller._send
        async def cancel_publish(*args,**kwargs):
            await original(*args,**kwargs)
            raise asyncio.CancelledError
        controller._send=cancel_publish
        with pytest.raises(asyncio.CancelledError):
            await controller._web_data(__import__('test_checkout_flow').update(envelope(s,{'values':{'f0':'synthetic-only'}})),SimpleNamespace(bot=controller.bot))
        assert s.request is None and s.key is None
        assert s.commit_guard is None
        assert await s.page.evaluate('window.clicks')==0
