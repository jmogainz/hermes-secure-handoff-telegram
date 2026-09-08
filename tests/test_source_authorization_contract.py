"""Strict source-selection schemas and lifecycle at real tool/Telegram boundaries."""
import asyncio
import copy
import json
from types import SimpleNamespace
import pytest
from test_source_authorization import request_source
from test_purchase_acquisition import attached, tool, deliver, IDENT
from test_checkout_flow import envelope, update
from test_observed_purchase_integration import miniapp

@pytest.mark.asyncio
async def test_request_tool_schema_and_foreign_stale_refs(tmp_path,monkeypatch):
    from jsonschema import validate, ValidationError
    from plugin.secure_handoff import SCHEMA
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    try:
        await tool(c,action='discover_components',session_ref=s.session_ref)
        found=await tool(c,action='discover_catalog_sources',session_ref=s.session_ref)
        payload={'action':'request_source_approval','session_ref':s.session_ref,'catalog_ref':found['refs'][0]['catalog_ref']}
        validate(payload,SCHEMA['parameters'])
        for extra in [{'public':True},{'text':'PRIVATE'},{'origin':'https://other.example'},{'selector':'h1'},{'value':'PRIVATE'},{'nonce':'sg_'+'Z'*32}]:
            invalid={**payload,**extra}
            with pytest.raises(ValidationError): validate(invalid,SCHEMA['parameters'])
            assert (await tool(c,**invalid))['status']=='invalid'
        with monkeypatch.context() as mp:
            mp.setattr(c,'_identity',lambda:(8,8,42))
            assert (await tool(c,**payload))['status'] in {'forbidden','rejected'}
        await tool(c,action='discover_catalog_sources',session_ref=s.session_ref)
        assert (await tool(c,**payload))['status']=='rejected'
        assert not s.catalog_grants and not c.bot.sent
    finally: await c._close(IDENT)

@pytest.mark.asyncio
@pytest.mark.parametrize('change',['field','copy','source_extra','ordinal_bool','ordinal_zero','nonce','origin_path','transaction','composition','stage','provider','demo'])
async def test_source_manifest_rejects_arbitrary_copy_and_values(tmp_path,monkeypatch,change):
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    try:
        await tool(c,action='discover_components',session_ref=s.session_ref)
        await request_source(c,s)
        original=s.request
        s.request=copy.deepcopy(original)
        if change=='field': s.request['fields']=[{'id':'f0','label':'PRIVATE','type':'text','required':False}]
        if change=='copy': s.request['actionLabel']='PRIVATE text'
        if change=='source_extra': s.request['source']['text']='PRIVATE text'
        if change=='ordinal_bool': s.request['source']['ordinal']=True
        if change=='ordinal_zero': s.request['source']['ordinal']=0
        if change=='nonce': s.request['source']['nonce']='sg_invalid'
        if change=='origin_path': s.request['origin']='https://catalog.example/private'
        if change=='transaction': s.request['transaction']={}
        if change=='composition': s.request['composition']={}
        if change=='stage': s.request['stage']='general_form'
        if change=='provider': s.request['provider']='arbitrary'
        if change=='demo': s.request['demo']=True
        app=await miniapp(s,c)
        from plugin.secure_handoff import _b64
        await app.goto(c.config.mini_app_url.rstrip('/')+'#request='+_b64(json.dumps(s.request).encode()))
        await app.reload()
        await app.wait_for_function("document.querySelector('.app-card').dataset.state !== 'loading'")
        assert await app.locator('#source-acknowledgment').count()==0
        assert 'PRIVATE' not in await app.locator('body').inner_text()
        assert await app.locator('#send-button').is_disabled()
        await app.close()
        s.request=original
    finally: await c._close(IDENT)

@pytest.mark.asyncio
async def test_owner_grant_has_status_only_wakeup(tmp_path,monkeypatch):
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    wakes=[]
    async def wake(adapter,text,source): wakes.append(text)
    c.adapter=object()
    monkeypatch.setattr(c,'_deliver_wake',wake)
    try:
        await tool(c,action='discover_components',session_ref=s.session_ref)
        await request_source(c,s)
        await deliver(c,envelope(s,{'grant':s.request['source']['nonce']}))
        await asyncio.sleep(0)
        assert len(wakes)==1 and 'composition_available' in wakes[0]
        assert not any(token in wakes[0] for token in ['PRIVATE','nonce','sg_','cs_','Synthetic notebook'])
    finally: await c._close(IDENT)

@pytest.mark.asyncio
@pytest.mark.parametrize('failure',['publish_failure','cancel_publish','cancel_accept'])
async def test_publication_and_queued_cancel_do_not_grant(tmp_path,monkeypatch,failure):
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    entered=asyncio.Event();proceed=asyncio.Event()
    try:
        await tool(c,action='discover_components',session_ref=s.session_ref)
        found=await tool(c,action='discover_catalog_sources',session_ref=s.session_ref)
        ref=found['refs'][0]['catalog_ref']
        if failure=='publish_failure':
            async def send(*a,**kw): return False
            monkeypatch.setattr(c,'_send',send)
            result=await tool(c,action='request_source_approval',session_ref=s.session_ref,catalog_ref=ref)
            assert result['status']=='publication_failed'
        else:
            original=c._check_source_candidate
            async def check(*a):
                await original(*a)
                if failure=='cancel_accept' or s.status=='waiting_for_source_approval':
                    entered.set();await proceed.wait()
            if failure=='cancel_accept':
                await tool(c,action='request_source_approval',session_ref=s.session_ref,catalog_ref=ref)
                raw=envelope(s,{'grant':s.request['source']['nonce']})
                monkeypatch.setattr(c,'_check_source_candidate',check)
                pending=asyncio.create_task(deliver(c,raw))
            else:
                monkeypatch.setattr(c,'_check_source_candidate',check)
                pending=asyncio.create_task(tool(c,action='request_source_approval',session_ref=s.session_ref,catalog_ref=ref))
            await asyncio.wait_for(entered.wait(),5)
            event=update('');event.effective_chat.id=7
            cancel=asyncio.create_task(c.cancel_from_update(event))
            await asyncio.sleep(0);proceed.set()
            await asyncio.gather(pending,cancel)
            assert s.status=='cancelled'
        assert not s.catalog_grants and not s.catalog_candidates and s.source_entry is None
        assert s.key is None and s.purchase_factory is None
    finally:
        proceed.set()
        await c._close(IDENT)
        await c._dispose(s)
