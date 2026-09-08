"""Owner-issued source selection through production tools and encrypted Mini App."""
import asyncio
import json
from types import SimpleNamespace
from telegram.ext import ApplicationHandlerStop
from test_checkout_flow import envelope, update
import pytest
from test_purchase_acquisition import attached, tool, deliver, IDENT
from test_observed_purchase_integration import miniapp

async def request_source(c,s):
    found=await tool(c,action='discover_catalog_sources',session_ref=s.session_ref)
    assert found['status']=='catalog_sources_available', found
    assert len(found['refs'])==1
    assert set(found['refs'][0])=={'catalog_ref','origin','ordinal'}
    result=await tool(c,action='request_source_approval',session_ref=s.session_ref,catalog_ref=found['refs'][0]['catalog_ref'])
    assert result['status']=='waiting_for_source_approval', result
    assert not s.catalog_grants
    return found

@pytest.mark.asyncio
async def test_owner_source_approval_to_purchase_via_tools_and_webcrypto(tmp_path,monkeypatch):
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    try:
        fields=await tool(c,action='discover_components',session_ref=s.session_ref)
        assert (await tool(c,action='discover_purchase_sources',session_ref=s.session_ref))['status']=='blocked'
        await request_source(c,s)
        assert s.request['fields']==[]
        assert 'PRIVATE' not in json.dumps(s.request)
        assert 'Synthetic notebook' not in json.dumps(s.request)
        app=await miniapp(s,c)
        assert await app.locator('#source-acknowledgment').is_checked() is False
        assert await app.get_by_role('button',name='Allow selected source',exact=True).is_disabled()
        assert 'original browser' in await app.locator('body').inner_text()
        await app.locator('#source-acknowledgment').check()
        await app.get_by_role('button',name='Allow selected source',exact=True).click()
        await app.wait_for_function('typeof window.sent === "string"')
        raw=await app.evaluate('window.sent')
        await deliver(c,raw)
        assert s.status=='composition_available'
        assert len(s.catalog_grants)==1 and s.purchase_factory is None
        await deliver(c,raw)
        assert len(s.catalog_grants)==1
        await app.close()
        found=await tool(c,action='discover_purchase_sources',session_ref=s.session_ref)
        assert found['status']=='purchase_sources_available',found
        assert (await tool(c,action='select_purchase_sources',session_ref=s.session_ref,source_revision=found['source_revision'],source_refs=[r['source_ref'] for r in found['refs']]))['status']=='purchase_intent_armed'
        assert (await tool(c,action='present_composition',snapshot_ref=fields['snapshot_ref'],layout='stack',groups=[{'title':'payment','refs':[r['ref'] for r in fields['refs']]}]))['status']=='waiting_for_handoff'
        app=await miniapp(s,c)
        assert await app.locator('#field-f0').input_value()==''
        await app.locator('#field-f0').fill('synthetic entry')
        await app.get_by_role('button',name='Fill fields',exact=True).click()
        await app.wait_for_function('typeof window.sent === "string"')
        await deliver(c,await app.evaluate('window.sent'))
        assert s.status=='purchase_review_ready'
        assert await page.evaluate('window.clicks')==0
        await app.close()
        review=await tool(c,action='inspect_purchase',session_ref=s.session_ref)
        assert (await tool(c,action='compose_purchase',session_ref=s.session_ref,revision=review['revision'],fact_refs=[r['ref'] for r in review['facts']],action_ref=review['actions'][0]['ref']))['status']=='waiting_for_confirmation'
        app=await miniapp(s,c)
        await app.locator('#purchase-acknowledgment').check()
        await app.get_by_role('button',name='Complete purchase',exact=True).click()
        await app.wait_for_function('typeof window.sent === "string"')
        await deliver(c,await app.evaluate('window.sent'))
        assert s.status=='purchase_submitted'
        assert await page.evaluate('window.clicks')==1
        await app.close()
    finally: await c._close(IDENT)

@pytest.mark.asyncio
async def test_miniapp_deny_consumes_source_request(tmp_path,monkeypatch):
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    try:
        await tool(c,action='discover_components',session_ref=s.session_ref)
        await request_source(c,s)
        grant=envelope(s,{'grant':s.request['source']['nonce']})
        app=await miniapp(s,c)
        await app.locator('#cancel-button').click()
        await app.wait_for_function('typeof window.sent === "string"',timeout=1500)
        await deliver(c,await app.evaluate('window.sent'))
        assert s.status=='cancelled'
        await deliver(c,grant)
        assert not s.catalog_grants and s.source_entry is None and s.source_pending is None
        assert await page.evaluate('window.clicks')==0
        await app.close()
    finally: await c._close(IDENT)

@pytest.mark.asyncio
@pytest.mark.parametrize('failure',['wrong_nonce','extra','boolean','wrong_owner','wrong_chat','wrong_thread','expiry','catalog_navigation','checkout_navigation','mutation_aba','cancel','replacement','foreign_context','catalog_history_aba','checkout_history_aba'])
async def test_source_approval_denied_stale_foreign_replay(tmp_path,monkeypatch,failure):
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    try:
        await tool(c,action='discover_components',session_ref=s.session_ref)
        await request_source(c,s)
        grant=s.source_pending['grant']
        body={'grant':s.request['source']['nonce']}
        if failure=='wrong_nonce': body={'grant':'sg_'+'Z'*32}
        if failure=='extra': body['public']=True
        if failure=='boolean': body={'grant':True}
        raw=envelope(s,body)
        if failure=='expiry': s.request['expiresAt']=0
        if failure=='catalog_navigation': await catalog.goto('https://catalog.example/other')
        if failure=='checkout_navigation': await page.goto('https://checkout.example/other')
        if failure=='mutation_aba': await catalog.evaluate("let n=document.querySelector('h1'),t=n.textContent;n.textContent='private';n.textContent=t")
        if failure.endswith('_history_aba'):
            target=catalog if failure=='catalog_history_aba' else page
            await target.evaluate("let u=location.href;history.pushState({},'', '#changed');history.replaceState({},'',u)")
        if failure=='foreign_context': s.context=object()
        if failure=='cancel':
            event=update(raw);event.effective_chat.id=7
            await c.cancel_from_update(event)
        if failure=='replacement': await tool(c,action='attach',mode='compose',origin='https://checkout.example')
        if failure.startswith('wrong_') and failure!='wrong_nonce':
            event=update(raw);event.effective_chat.id=7
            if failure=='wrong_owner': event.effective_user.id=8
            if failure=='wrong_chat': event.effective_chat.id=8
            if failure=='wrong_thread': event.effective_message.message_thread_id=43
            with pytest.raises(ApplicationHandlerStop): await c._web_data(event,SimpleNamespace(bot=c.bot))
            assert not s.catalog_grants and s.status=='waiting_for_source_approval'
            # A foreign submission cannot burn the legitimate owner's approval.
            await deliver(c,raw)
            assert s.status=='composition_available' and len(s.catalog_grants)==1
            await deliver(c,raw)
            assert len(s.catalog_grants)==1
        else:
            await deliver(c,raw); await deliver(c,raw)
            assert not s.catalog_grants and s.purchase_factory is None
            assert s.source_entry is None and s.source_pending is None
            assert grant.closed
        assert await page.evaluate('window.clicks')==0
    finally:
        await c._close(IDENT)
        await c._dispose(s)
