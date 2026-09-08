"""Disposable browser tool route. No prepared registry/factory or source selectors.

The trusted host explicitly authorizes a synthetic nonpersonal catalog document;
this is a provenance grant, not a model 'public' assertion.
"""
import asyncio
import json
from types import SimpleNamespace
import pytest
from telegram.ext import ApplicationHandlerStop
from test_checkout_flow import disposable_controller, Bot, update
from test_observed_purchase_integration import miniapp

IDENT = (7, 7, 42)

async def tool(c, **args):
    return json.loads(await asyncio.to_thread(c.tool, args))

async def deliver(c, raw):
    event = update(raw)
    event.effective_chat.id = 7
    with pytest.raises(ApplicationHandlerStop):
        await c._web_data(event, SimpleNamespace(bot=c.bot))

async def pages(c, layout):
    catalog = await c._context.new_page()
    await catalog.route('**/*', lambda r: r.fulfill(body='<main itemscope itemtype="https://schema.org/Product"><h1 itemprop="name">Synthetic notebook</h1></main>', content_type='text/html'))
    await catalog.goto('https://catalog.example/product')
    page = await c._context.new_page()
    rows = '<tr><th>Total</th><td>USD 12.34</td></tr><tr><th>Tax</th><td>USD 1.20</td></tr>' if layout == 'table' else '<dt>Total</dt><dd>USD 12.34</dd><dt>Tax</dt><dd>USD 1.20</dd>'
    summary = '<table>'+rows+'</table>' if layout == 'table' else '<dl>'+rows+'</dl>'
    html = '<form action="/purchase" method="post"><label>PRIVATE BILLING LABEL<input required value="PRIVATE DEFAULT"></label><section itemscope itemtype="https://schema.org/Product"><p itemprop="name">Synthetic notebook</p></section>'+summary+'<button type="submit">Complete purchase</button></form><script>window.clicks=0;document.querySelector("form").onsubmit=e=>{e.preventDefault();window.clicks++}</script>'
    await page.route('**/*', lambda r: r.fulfill(body=html, content_type='text/html'))
    await page.goto('https://checkout.example/cart')
    return catalog, page

async def attached(tmp_path, monkeypatch, layout='table'):
    c = await disposable_controller(tmp_path)
    c.loop=asyncio.get_running_loop(); c.bot=Bot()
    monkeypatch.setattr(c, '_identity', lambda: IDENT)
    catalog, page = await pages(c, layout)
    result = await tool(c, action='attach', mode='compose', origin='https://checkout.example')
    assert result['status']=='attached'
    s=c.sessions[IDENT]
    return c,s,catalog,page

@pytest.mark.asyncio
@pytest.mark.parametrize('layout', ['table','definitions'])
async def test_tool_acquisition_composed_entry_encrypted_purchase(tmp_path, monkeypatch, layout):
    c,s,catalog,page=await attached(tmp_path,monkeypatch,layout)
    try:
        fields=await tool(c, action='discover_components', session_ref=s.session_ref)
        assert fields['status']=='composition_available'
        # Host-only authorization of the exact synthetic public document. The
        # production resolver, not this test, discovers and retains its nodes.
        await c.authorize_purchase_catalog(s, catalog)
        found=await tool(c, action='discover_purchase_sources', session_ref=s.session_ref)
        assert found['status']=='purchase_sources_available', found
        assert all(set(r)=={'source_ref','kind','ordinal'} for r in found['refs'])
        assert 'PRIVATE' not in json.dumps(found)
        plan=await tool(c, action='select_purchase_sources', session_ref=s.session_ref,
                        source_revision=found['source_revision'], source_refs=[r['source_ref'] for r in reversed(found['refs'])])
        assert plan['status']=='purchase_intent_armed', plan
        result=await tool(c, action='present_composition', snapshot_ref=fields['snapshot_ref'], layout='sections' if layout=='definitions' else 'stack', groups=[{'title':'payment','refs':[r['ref'] for r in fields['refs']]}])
        assert result['status']=='waiting_for_handoff'
        app=await miniapp(s,c)
        assert await app.locator('#field-f0').input_value()==''
        await app.locator('#field-f0').fill('synthetic entry')
        await app.get_by_role('button',name='Fill fields',exact=True).click()
        await app.wait_for_function('typeof window.sent === "string"')
        await deliver(c, await app.evaluate('window.sent'))
        assert s.status=='purchase_review_ready', s.status
        assert await page.evaluate('window.clicks')==0
        await app.close()
        review=await tool(c, action='inspect_purchase',session_ref=s.session_ref)
        assert review['status']=='ready'
        assert 'PRIVATE' not in json.dumps(review)
        result=await tool(c, action='compose_purchase',session_ref=s.session_ref,revision=review['revision'],fact_refs=[r['ref'] for r in review['facts']],action_ref=review['actions'][0]['ref'])
        assert result['status']=='waiting_for_confirmation',result
        app=await miniapp(s,c)
        await app.locator('#purchase-acknowledgment').check()
        await app.get_by_role('button',name='Complete purchase',exact=True).click()
        await app.wait_for_function('typeof window.sent === "string"')
        raw=await app.evaluate('window.sent')
        await deliver(c,raw)
        assert s.status=='purchase_submitted'
        await deliver(c,raw)
        assert await page.evaluate('window.clicks')==1
        await app.close()
    finally:
        await c._close(IDENT)


@pytest.mark.asyncio
@pytest.mark.parametrize('change', [
    "document.querySelector('form').insertAdjacentHTML('beforeend','<p>PRIVATE echoed billing</p>')",
    "document.querySelector('th').textContent='Estimated total'",
    "document.querySelector('table').insertAdjacentHTML('beforeend','<tr><th>Fee</th><td>USD 2.00 plus fees</td></tr>')",
    "document.querySelector('table').insertAdjacentHTML('beforeend','<tr><th>Total</th><td>USD 2.00</td></tr>')",
    "document.querySelector('button').textContent='Submit'",
    "document.querySelector('form').insertAdjacentHTML('beforeend','<p>Renews monthly</p>')",
    "document.body.insertAdjacentHTML('afterbegin','<p>Additional USD 5.00 due now</p>')",
    "document.querySelector('label').insertAdjacentText('afterbegin','Renews monthly. ')",
    "document.querySelector('table').insertAdjacentHTML('beforeend','<tr><th>Subtotal</th><td>USD 30.00</td></tr>')",
])
async def test_private_echo_and_unsupported_obligations_block_before_projection(tmp_path,monkeypatch,change):
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    try:
        await page.evaluate('()=>{'+change+'}')
        await tool(c,action='discover_components',session_ref=s.session_ref)
        await c.authorize_purchase_catalog(s,catalog)
        result=await tool(c,action='discover_purchase_sources',session_ref=s.session_ref)
        assert result=={'status':'blocked','reason':'source_binding_unsupported'}
        assert s.purchase_sources is None and s.purchase_factory is None
        assert await page.evaluate('window.clicks')==0
    finally: await c._close(IDENT)


@pytest.mark.asyncio
async def test_catalog_like_text_is_not_public_authorization(tmp_path,monkeypatch):
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    try:
        await catalog.evaluate("document.querySelector('h1').textContent='PRIVATE purchase or billing echo'")
        await tool(c,action='discover_components',session_ref=s.session_ref)
        result=await tool(c,action='discover_purchase_sources',session_ref=s.session_ref)
        assert result=={'status':'blocked','reason':'public_source_authorization_required'}
        for extras in [{'public':True},{'selector':'h1'},{'text':'PRIVATE'},{'role':'displayed_total'},{'currency':'USD'}]:
            assert (await tool(c,action='discover_purchase_sources',session_ref=s.session_ref,**extras))['status']=='invalid'
        assert not c.bot.sent
    finally: await c._close(IDENT)


async def arm_and_present(c,s,catalog):
    fields=await tool(c,action='discover_components',session_ref=s.session_ref)
    await c.authorize_purchase_catalog(s,catalog)
    found=await tool(c,action='discover_purchase_sources',session_ref=s.session_ref)
    result=await tool(c,action='select_purchase_sources',session_ref=s.session_ref,
                     source_revision=found['source_revision'],source_refs=[r['source_ref'] for r in found['refs']])
    assert result['status']=='purchase_intent_armed'
    result=await tool(c,action='present_composition',snapshot_ref=fields['snapshot_ref'],layout='stack',
                     groups=[{'title':'details','refs':[r['ref'] for r in fields['refs']]}])
    assert result['status']=='waiting_for_handoff'


@pytest.mark.asyncio
async def test_outside_scope_obligation_invalidates_final_synchronous_commit(tmp_path,monkeypatch):
    from test_checkout_flow import envelope
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    try:
        await arm_and_present(c,s,catalog)
        await deliver(c,envelope(s,{'values':{'f0':'synthetic entry'}}))
        review=await tool(c,action='inspect_purchase',session_ref=s.session_ref)
        result=await tool(c,action='compose_purchase',session_ref=s.session_ref,revision=review['revision'],
                          fact_refs=[r['ref'] for r in review['facts']],action_ref=review['actions'][0]['ref'])
        assert result['status']=='waiting_for_confirmation'
        with pytest.raises(Exception):
            await s.commit_guard.evaluate("(g,d)=>{document.body.insertAdjacentHTML('afterbegin','<p>Additional fee</p>');return g.commit({deadline:d})}",s.request['expiresAt'])
        assert await page.evaluate('window.clicks')==0
    finally: await c._close(IDENT)


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['catalog_close','catalog_navigation','replace_action','foreign_ref','old_revision','expired','foreign_owner','foreign_task'])
async def test_source_refs_are_owner_task_document_and_time_bound(tmp_path,monkeypatch,change):
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    try:
        await tool(c,action='discover_components',session_ref=s.session_ref)
        await c.authorize_purchase_catalog(s,catalog)
        found=await tool(c,action='discover_purchase_sources',session_ref=s.session_ref)
        payload={'action':'select_purchase_sources','session_ref':s.session_ref,'source_revision':found['source_revision'],'source_refs':[r['source_ref'] for r in found['refs']]}
        lease=s.purchase_sources
        if change=='catalog_close': await catalog.close()
        if change=='catalog_navigation': await catalog.goto('https://catalog.example/other')
        if change=='replace_action': await page.evaluate("let e=document.querySelector('button');e.replaceWith(e.cloneNode(true))")
        if change=='foreign_ref': payload['source_refs'][0]='sr_'+'A'*32
        if change=='old_revision': await tool(c,action='discover_purchase_sources',session_ref=s.session_ref)
        if change=='expired': lease.deadline=0
        if change=='foreign_owner': monkeypatch.setattr(c,'_identity',lambda:(9,9,42))
        if change=='foreign_task':
            await tool(c,action='attach',mode='compose',origin='https://checkout.example')
            new=c.sessions[IDENT]
            await tool(c,action='discover_components',session_ref=new.session_ref)
            payload['session_ref']=new.session_ref
        assert (await tool(c,**payload))['status'] in {'blocked','rejected'}
        assert s.purchase_factory is None
        assert await page.evaluate('window.clicks')==0
    finally: await c._close(IDENT)
