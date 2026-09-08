"""Real registry/controller/crypto; disposable browser, synthetic facts only."""
import asyncio
import json
import pytest
from test_purchase_approval import checkout, fill, deliver
from test_checkout_flow import envelope
from plugin.purchase_facts import PurchaseFactRegistry

IDENT = (7, 8, 42)

async def registry_for(s):
    registry = await PurchaseFactRegistry.create(owner=(s.user,s.chat,s.thread), session=s, page=s.page, scope=s.scope)
    source = await s.page.query_selector('#catalog')
    observation = await registry.capture_public_product(source)
    await registry.bind_product(observation, await s.page.query_selector('#item'))
    await registry.capture_money(await s.page.query_selector('#total'), role='displayed_total', currency='USD')
    await registry.capture_action(s.refs['submit'])
    return registry

async def setup(c,s):
    # Rebind the existing synthetic session to a different, non-template checkout.
    c._scrub_binding(s)
    await s.page.set_content('<p id="catalog">Example product quantity 1</p><main><form action="/purchase" method="post">'
        '<input autocomplete="cc-number" aria-label="Card number">'
        '<p id="item">Example product quantity 1</p><p id="total">USD 12.34</p>'
        '<button type="submit">Complete purchase</button></form></main>'
        '<script>window.clicks=0;document.querySelector("form").onsubmit=e=>{e.preventDefault();window.clicks++}</script>')
    s.status='open'
    assert (await c._snapshot(s))['status']=='waiting_for_handoff'

@pytest.mark.asyncio
async def test_fresh_registry_public_tools_exact_encrypted_approval(tmp_path, monkeypatch):
    async with checkout(tmp_path) as (c,s):
        await setup(c,s)
        old=s.request['id']; old_key=s.key
        # Trusted integration hook, not a model tool or raw selector API.
        await c.arm_purchase_review(s, registry_for)
        await fill(c,s)
        assert s.status=='purchase_review_ready'
        assert s.key is None and s.request['id'] == old
        found=await c.inspect_purchase({'action':'inspect_purchase','session_ref':s.session_ref}, IDENT)
        assert found['status']=='ready'
        payload={'action':'compose_purchase','session_ref':s.session_ref,'revision':found['revision'],
                 'fact_refs':[f['ref'] for f in found['facts']], 'action_ref':found['actions'][0]['ref']}
        result=await c.compose_purchase(payload,IDENT)
        assert result['status']=='waiting_for_confirmation'
        assert s.request['id']!=old and s.key is not old_key
        assert s.request['transaction']['contract']=='observed_action_v1'
        assert 'synthetic-only' not in json.dumps(c.bot.sent,default=str)
        raw=envelope(s,{'approve':s.request['transaction']['id']})
        await deliver(c,s,raw=raw)
        assert s.status=='purchase_submitted'
        assert await s.page.evaluate('window.clicks')==1
        await deliver(c,s,raw=raw)
        assert await s.page.evaluate('window.clicks')==1


@pytest.mark.asyncio
async def test_bidi_item_rejected_before_controller_publication(tmp_path):
    async with checkout(tmp_path) as (c, s):
        await setup(c, s)
        await s.page.evaluate("t=>{for(const id of ['catalog','item']) document.getElementById(id).textContent=t}",
                              'Example \u202e123 product')
        # Rebind before fill so rejection is display validation, not mutation age.
        c._scrub_binding(s)
        s.status = 'open'
        assert (await c._snapshot(s))['status'] == 'waiting_for_handoff'
        async def factory(bound):
            registry = await PurchaseFactRegistry.create(owner=IDENT, session=bound, page=bound.page, scope=bound.scope)
            try:
                obs = await registry.capture_public_product(await bound.page.query_selector('#catalog'))
                await registry.bind_product(obs, await bound.page.query_selector('#item'))
                await registry.capture_money(await bound.page.query_selector('#total'), role='displayed_total', currency='USD')
                await registry.capture_action(bound.refs['submit'])
                return registry
            except BaseException:
                await registry.close()
                raise
        await c.arm_purchase_review(s, factory)
        assert c.bot is not None
        prior_messages = len(c.bot.sent)  # Initial encrypted-entry keyboard is allowed.
        await fill(c, s)
        assert s.status == 'rejected'
        assert s.purchase_registry is None
        assert all(not message.get('reply_markup') for message in c.bot.sent[prior_messages:])
        assert await s.page.evaluate('window.clicks') == 0


async def miniapp(s,c):
    from pathlib import Path
    app=await s.context.new_page()
    root=Path(__file__).resolve().parents[1]/'web'
    async def route(r):
        url=r.request.url
        if 'telegram.org/' in url:
            return await r.fulfill(content_type='application/javascript',body="window.Telegram={WebApp:{platform:'ios',initData:'',ready(){},close(){},sendData(v){window.sent=v}}}")
        name=url.split('/')[-1].split('#')[0] or 'index.html'
        if name=='app': name='index.html'
        if name not in {'index.html','app.js','styles.css'}: return await r.abort()
        await r.fulfill(content_type='application/javascript' if name.endswith('.js') else 'text/css' if name.endswith('.css') else 'text/html',body=(root/name).read_text())
    await app.route('**/*',route)
    launch=c.bot.sent[-1]['reply_markup'].keyboard[0][0].web_app.url
    await app.goto(launch)
    await app.wait_for_function("document.querySelector('.app-card').dataset.state !== 'loading'")
    return app

@pytest.mark.asyncio
async def test_real_tool_handler_to_frontend_encrypted_approval(tmp_path,monkeypatch):
    from plugin.secure_handoff import SCHEMA, decrypt_submission
    async with checkout(tmp_path) as (c,s):
        await setup(c,s)
        await c.arm_purchase_review(s,registry_for)
        await fill(c,s)
        # Tool owner boundary requires a private owner chat, use its real gate.
        # Recreate the registry after changing synthetic owner scope.
        await s.purchase_registry.close()
        s.purchase_registry=None
        c.sessions.pop(IDENT); s.chat=7
        ident=(7,7,42); c.sessions[ident]=s
        await c.prepare_purchase(s,await registry_for(s))
        monkeypatch.setattr(c,'_identity',lambda:ident)
        monkeypatch.setattr(c,'_owners',lambda:{7})
        found=json.loads(await asyncio.to_thread(c.tool,{'action':'inspect_purchase','session_ref':s.session_ref}))
        assert found['status']=='ready'
        payload={'action':'compose_purchase','session_ref':s.session_ref,'revision':found['revision'],
                 'fact_refs':[f['ref'] for f in found['facts']], 'action_ref':found['actions'][0]['ref']}
        assert {'inspect_purchase','compose_purchase'}<=set(SCHEMA['parameters']['properties']['action']['enum'])
        assert json.loads(await asyncio.to_thread(c.tool,payload))['status']=='waiting_for_confirmation'
        app=await miniapp(s,c)
        assert await app.locator('.app-card').get_attribute('data-state')=='secureReady'
        text=await app.locator('#transaction-summary').inner_text()
        assert 'USD 12.34' in text and 'Not established' in text
        assert 'guarantee' in await app.locator('body').inner_text()
        ack=app.locator('#purchase-acknowledgment')
        assert not await ack.is_checked()
        button=app.get_by_role('button',name='Complete purchase',exact=True)
        assert not await button.is_enabled()
        await ack.check()
        await button.click()
        await app.wait_for_function('typeof window.sent === "string"')
        raw=await app.evaluate('window.sent')
        assert decrypt_submission(raw,s.request,s.key)=={'approve':s.request['transaction']['id']}
        from test_checkout_flow import update
        from telegram.ext import ApplicationHandlerStop
        from types import SimpleNamespace
        event=update(raw); event.effective_chat.id=7
        with pytest.raises(ApplicationHandlerStop):
            await c._web_data(event,SimpleNamespace(bot=c.bot))
        assert s.status=='purchase_submitted' and await s.page.evaluate('window.clicks')==1
        await app.close()


async def approved(c,s):
    await setup(c,s)
    await c.arm_purchase_review(s,registry_for)
    await fill(c,s)
    found=await c.inspect_purchase({'action':'inspect_purchase','session_ref':s.session_ref},IDENT)
    payload={'action':'compose_purchase','session_ref':s.session_ref,'revision':found['revision'],
             'fact_refs':[f['ref'] for f in found['facts']], 'action_ref':found['actions'][0]['ref']}
    assert (await c.compose_purchase(payload,IDENT))['status']=='waiting_for_confirmation'
    return envelope(s,{'approve':s.request['transaction']['id']})

@pytest.mark.asyncio
@pytest.mark.parametrize('change',[
    "document.querySelector('#total').textContent='USD 99.00'",
    "let e=document.querySelector('#total'),t=e.textContent;e.textContent='USD 99.00';e.textContent=t",
    "let e=document.querySelector('#item');e.replaceWith(e.cloneNode(true))",
    "let e=document.querySelector('button');e.replaceWith(e.cloneNode(true))",
    "let e=document.querySelector('form');e.replaceWith(e.cloneNode(true))",
    "document.querySelector('form').insertAdjacentHTML('beforeend','<p>Extra obligation</p>')",
    "document.querySelector('input').value='changed private state'",
    "let e=document.querySelector('input'),v=e.value;e.value='other';e.dispatchEvent(new Event('input'));e.value=v",
    "document.querySelector('form').action='/other'",
])
async def test_changed_source_cannot_click_or_replay(tmp_path,change):
    async with checkout(tmp_path) as (c,s):
        raw=await approved(c,s)
        await s.page.evaluate('()=>{'+change+'}')
        await deliver(c,s,raw=raw)
        assert s.status=='rejected'
        await deliver(c,s,raw=raw)
        assert await s.page.evaluate('window.clicks')==0
        assert s.purchase_registry is None and s.purchase_selection is None

@pytest.mark.asyncio
async def test_cancel_queued_dispatch_and_replay(tmp_path):
    from test_checkout_flow import update
    async with checkout(tmp_path) as (c,s):
        raw=await approved(c,s)
        guard=s.commit_guard
        await s.lock.acquire()
        submit=asyncio.create_task(deliver(c,s,raw=raw))
        cancel=asyncio.create_task(c.cancel_from_update(update(raw)))
        await asyncio.sleep(0)
        s.lock.release()
        await asyncio.gather(submit,cancel)
        assert s.status=='cancelled'
        await deliver(c,s,raw=raw)
        assert await s.page.evaluate('window.clicks')==0

@pytest.mark.asyncio
async def test_no_model_source_or_prefill_registry(tmp_path):
    from plugin.purchase_facts import FactRejected
    async with checkout(tmp_path) as (c,s):
        await setup(c,s)
        with pytest.raises(FactRejected): await c.prepare_purchase(s,{'public':True})
        pre=await registry_for(s)
        async def wrong_factory(_): return pre
        await c.arm_purchase_review(s,wrong_factory)
        await fill(c,s)
        assert s.status=='rejected' and s.purchase_registry is None
        assert await s.page.evaluate('window.clicks')==0

@pytest.mark.asyncio
async def test_publication_failure_releases_approval(tmp_path,monkeypatch):
    async with checkout(tmp_path) as (c,s):
        await setup(c,s); await c.arm_purchase_review(s,registry_for); await fill(c,s)
        found=await c.inspect_purchase({'action':'inspect_purchase','session_ref':s.session_ref},IDENT)
        async def failed(*a,**k): return False
        monkeypatch.setattr(c,'_send',failed)
        payload={'action':'compose_purchase','session_ref':s.session_ref,'revision':found['revision'],
            'fact_refs':[f['ref'] for f in found['facts']], 'action_ref':found['actions'][0]['ref']}
        assert (await c.compose_purchase(payload,IDENT))['status']=='publication_failed'
        assert s.key is None and s.request is None and s.purchase_registry is None
        assert await s.page.evaluate('window.clicks')==0

def test_standalone_loader_observed_post_fill(tmp_path):
    import subprocess, sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    script = '''
import asyncio, sys
from pathlib import Path
sys.path[:0] = [str(Path.cwd() / 'plugin'), str(Path.cwd() / 'tests')]
import secure_handoff
import purchase_facts
import test_checkout_flow
import test_observed_purchase_integration as integration
test_checkout_flow.SecureHandoffController = secure_handoff.SecureHandoffController
integration.PurchaseFactRegistry = purchase_facts.PurchaseFactRegistry
assert secure_handoff.__package__ == ''
async def run():
    async with integration.checkout(Path(sys.argv[1])) as (c, s):
        await integration.setup(c, s)
        await c.arm_purchase_review(s, integration.registry_for)
        await integration.fill(c, s)
        assert s.status == 'purchase_review_ready', s.status
        found = await c.inspect_purchase({'action':'inspect_purchase','session_ref':s.session_ref}, integration.IDENT)
        assert found['status'] == 'ready'
        result = await c.compose_purchase({'action':'compose_purchase','session_ref':s.session_ref,
            'revision':found['revision'],'fact_refs':[f['ref'] for f in found['facts']],
            'action_ref':found['actions'][0]['ref']}, integration.IDENT)
        assert result['status'] == 'waiting_for_confirmation', result
        assert await s.page.evaluate('window.clicks') == 0
asyncio.run(run())
'''
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path)], cwd=root,
                            capture_output=True, timeout=90)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.asyncio
async def test_changed_public_projection_is_not_authority(tmp_path):
    async with checkout(tmp_path) as (c,s):
        raw=await approved(c,s)
        s.request['transaction']['facts'][0]['value']='Forged replacement product'
        await deliver(c,s,raw=raw)
        assert s.status=='rejected'
        assert await s.page.evaluate('window.clicks')==0

@pytest.mark.asyncio
@pytest.mark.parametrize('change',[
    "const n=document.querySelector('#total'),t=n.textContent;n.textContent='USD 99.00';n.textContent=t",
    "const n=document.querySelector('input'),v=n.value;n.value='other';n.dispatchEvent(new Event('change'));n.value=v",
    "const n=document.createElement('p');document.querySelector('form').append(n);n.remove()",
    "document.querySelector('input').value='other'",
])
async def test_final_synchronous_guard_no_async_gap(tmp_path,change):
    async with checkout(tmp_path) as (c,s):
        await approved(c,s)
        with pytest.raises(Exception):
            await s.commit_guard.evaluate('(g,d)=>{'+change+';return g.commit({deadline:d})}',s.request['expiresAt'])
        assert await s.page.evaluate('window.clicks')==0

@pytest.mark.asyncio
async def test_inspection_changed_revision_omission_and_arbitrary_model_input(tmp_path):
    async with checkout(tmp_path) as (c,s):
        await setup(c,s); await c.arm_purchase_review(s,registry_for); await fill(c,s)
        found=await c.inspect_purchase({'action':'inspect_purchase','session_ref':s.session_ref},IDENT)
        assert (await c.inspect_purchase({'action':'inspect_purchase','session_ref':s.session_ref,'public':True},IDENT))['status']=='invalid'
        assert (await c.inspect_purchase({'action':'inspect_purchase','session_ref':s.session_ref},(9,9,None)))['status']=='rejected'
        for addition in [{'text':'untrusted'},{'selector':'button'},{'approve':True}]:
            args={'action':'compose_purchase','session_ref':s.session_ref,'revision':found['revision'],'fact_refs':[f['ref'] for f in found['facts']],'action_ref':found['actions'][0]['ref'],**addition}
            assert (await c.compose_purchase(args,IDENT))['status']=='invalid'
        await s.page.evaluate("document.querySelector('#total').textContent='USD 99.00'")
        result=await c.inspect_purchase({'action':'inspect_purchase','session_ref':s.session_ref},IDENT)
        assert result['status']=='rejected' and '99.00' not in json.dumps(result)


@pytest.mark.asyncio
async def test_present_does_not_destroy_pending_review(tmp_path):
    async with checkout(tmp_path) as (c,s):
        await setup(c,s); await c.arm_purchase_review(s,registry_for); await fill(c,s)
        registry=s.purchase_registry
        result=await c._run('present',{'action':'present'},IDENT)
        assert result['status']=='purchase_review_ready'
        assert s.purchase_registry is registry and s.key is None


@pytest.mark.asyncio
@pytest.mark.parametrize('layout', ['table','sections'])
async def test_layout_neutral_postfill_tax_rows_and_omission(tmp_path,layout):
    async with checkout(tmp_path) as (c,s):
        await setup(c,s)
        # Structural changes occur before the post-fill registry exists.
        await s.page.evaluate("""layout=>{
            const form=document.querySelector('form');
            const holder=document.createElement(layout==='table'?'table':'section');
            if(layout==='table') holder.innerHTML='<tbody><tr><td id="tax">USD 1.20</td></tr></tbody>';
            else holder.innerHTML='<div><p id="tax">USD 1.20</p></div>';
            form.insertBefore(holder,form.querySelector('button'));
        }""",layout)
        async def factory(s):
            r=await registry_for(s)
            await r.capture_money(await s.page.query_selector('#tax'),role='tax',currency='USD')
            return r
        await c.arm_purchase_review(s,factory)
        await fill(c,s)
        found=await c.inspect_purchase({'action':'inspect_purchase','session_ref':s.session_ref},IDENT)
        assert found['status']=='ready'
        tax=next(f for f in found['facts'] if f['role']=='tax')
        assert tax['amount']=='1.20'
        # Direct registry refusal proves registered rows cannot be hidden by ordering.
        from plugin.purchase_facts import FactRejected
        with pytest.raises(FactRejected,match='required_fact_omitted'):
            await s.purchase_registry.compose({'revision':found['revision'],
                'fact_refs':[f['ref'] for f in found['facts'] if f['role']!='tax'],
                'action_ref':found['actions'][0]['ref']},owner=IDENT,session=s)
        result=await c.compose_purchase({'action':'compose_purchase','session_ref':s.session_ref,
            'revision':found['revision'],'fact_refs':[f['ref'] for f in reversed(found['facts'])],
            'action_ref':found['actions'][0]['ref']},IDENT)
        assert result['status']=='waiting_for_confirmation'
        app=await miniapp(s,c)
        assert 'USD 1.20' in await app.locator('#transaction-summary').inner_text()
        await app.set_viewport_size({'width':375,'height':812})
        assert await app.evaluate('document.documentElement.scrollWidth<=innerWidth')
        await app.close()
        await deliver(c,s,{'approve':s.request['transaction']['id']})
        assert s.status=='purchase_submitted' and await s.page.evaluate('window.clicks')==1

@pytest.mark.asyncio
async def test_expired_browser_lease_rejects_exact_encrypted_approval(tmp_path):
    async with checkout(tmp_path) as (c,s):
        raw=await approved(c,s)
        await s.commit_guard.evaluate('g=>g.deadline=Date.now()-1')
        await deliver(c,s,raw=raw)
        assert s.status=='rejected' and await s.page.evaluate('window.clicks')==0

@pytest.mark.asyncio
async def test_wrong_capability_is_terminal_without_click(tmp_path):
    async with checkout(tmp_path) as (c,s):
        raw=await approved(c,s)
        await deliver(c,s,{'approve':'tx_'+'A'*32})
        await deliver(c,s,raw=raw)
        assert s.status=='rejected' and await s.page.evaluate('window.clicks')==0
