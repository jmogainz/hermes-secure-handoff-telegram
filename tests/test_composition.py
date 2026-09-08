"""Offline composition → actual Mini App crypto → private native browser apply."""
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from telegram.ext import ApplicationHandlerStop
from test_general_forms import form_controller
from test_checkout_flow import update

IDENT = (7, 8, 42)
HTML = '''<form><label>PRIVATE LABEL<input required name="first" value="PRIVATE CURRENT"></label>
<label>PRIVATE OPTIONAL<textarea name="second">PRIVATE DEFAULT</textarea></label>
<select name="third"><option value="private-a">PRIVATE OPTION A</option><option value="private-b">PRIVATE OPTION B</option></select>
<button>Pay</button></form><script>window.order=[];window.clicks=0;
document.querySelectorAll('input,textarea,select').forEach((e,i)=>e.addEventListener('input',()=>window.order.push(i)));
document.querySelector('button').onclick=e=>{e.preventDefault();window.clicks++}</script>'''

async def discover(c, s):
    s.requested_mode = 'compose'
    s.session_ref = 'ss_fixture'
    return await c._run('discover_components', {'action':'discover_components', 'session_ref':s.session_ref}, IDENT)

@pytest.mark.asyncio
@pytest.mark.parametrize('layout,optional', [('stack',1),('sections',2)])
async def test_composed_browser_crypto_roundtrip(form_controller, layout, optional):
    c,s = form_controller
    await s.page.set_content(HTML)
    found = await discover(c,s)
    assert found['status'] == 'composition_available'
    assert 'PRIVATE' not in json.dumps(found)
    refs = found['refs']
    assert [r['required'] for r in refs] == [True,False,False]
    payload = {'action':'present_composition','snapshot_ref':found['snapshot_ref'], 'layout':layout,
               'groups':[{'title':'details','refs':[refs[optional]['ref']]}, {'title':'other','refs':[refs[0]['ref']]}]}
    result = await c._run('present_composition',payload,IDENT)
    assert result['status'] == 'waiting_for_handoff'
    assert 'PRIVATE' not in json.dumps(c.bot.sent, default=str)
    from plugin.secure_handoff import _unb64
    launch=c.bot.sent[-1]['reply_markup'].keyboard[0][0].web_app.url
    manifest=json.loads(_unb64(launch.split('#request=')[1]))
    assert manifest==s.request
    assert 'PRIVATE' not in json.dumps(manifest) and 'private-a' not in json.dumps(manifest)
    assert all(set(f)<= {'id','type','required','label','options'} for f in manifest['fields'])
    assert [f['id'] for f in s.request['fields']] == ['f0', f'f{optional}']
    app = await s.context.new_page()
    root = Path(__file__).resolve().parents[1] / 'web'
    async def route(r):
        url=r.request.url
        if 'telegram.org/' in url:
            return await r.fulfill(content_type='application/javascript', body="window.Telegram={WebApp:{platform:'ios',initData:'',ready(){},close(){},sendData(v){window.sent=v}}}")
        name=url.split('/')[-1].split('#')[0] or 'index.html'
        if name == 'app': name='index.html'
        if name not in {'index.html','app.js','styles.css'}: return await r.abort()
        await r.fulfill(content_type='application/javascript' if name.endswith('.js') else 'text/css' if name.endswith('.css') else 'text/html',body=(root/name).read_text())
    await app.route('**/*',route)
    await app.goto(launch)
    await app.wait_for_function("document.querySelector('.app-card').dataset.state !== 'loading'")
    assert await app.locator('.app-card').get_attribute('data-state') == 'secureReady'
    assert await app.locator('.composition-group').count() == 2
    assert await app.locator('[data-composition-layout]').get_attribute('data-composition-layout') == layout
    assert await app.locator('.composition-group').first.evaluate('(e)=>getComputedStyle(e).borderTopStyle') == ('solid' if layout == 'sections' else 'none')
    assert await app.locator('.field-row input,.field-row textarea,.field-row select').evaluate_all('(es)=>es.map(e=>e.id)') == [f'field-f{optional}','field-f0']
    assert await app.locator('.field-row input,.field-row textarea,.field-row select').evaluate_all('(es)=>es.every(e=>e.value === "")')
    await app.locator('#field-f0').fill('synthetic entry')
    if optional == 1: await app.locator('#field-f1').fill('synthetic notes')
    else: await app.locator('#field-f2').select_option('o1')
    await app.get_by_role('button',name='Fill fields',exact=True).click()
    await app.wait_for_function('typeof window.sent === "string"')
    raw=await app.evaluate('window.sent')
    assert 'synthetic entry' not in raw
    with pytest.raises(ApplicationHandlerStop):
        await c._web_data(update(raw),SimpleNamespace(bot=c.bot))
    assert s.status == 'filled'
    assert await s.page.evaluate('window.order') == [0,optional]
    assert await s.page.evaluate('window.clicks') == 0
    assert await s.page.locator('input').input_value() == 'synthetic entry'
    assert await s.page.locator('textarea').input_value() == ('synthetic notes' if optional == 1 else 'PRIVATE DEFAULT')
    assert await s.page.locator('select').input_value() == ('private-b' if optional == 2 else 'private-a')
    status=await c._run('composition_status', {'action':'composition_status','component_ref':result['component_ref']}, IDENT)
    assert status == {'status':'filled','component_ref':result['component_ref']}
    with pytest.raises(ApplicationHandlerStop):
        await c._web_data(update(raw),SimpleNamespace(bot=c.bot))
    assert await s.page.evaluate('window.order') == [0,optional]
    await app.close()


@pytest.mark.asyncio
async def test_model_schema_and_real_tool_dispatch(form_controller, monkeypatch):
    from plugin.secure_handoff import SCHEMA
    from plugin import composition
    import asyncio
    c,s=form_controller
    props=SCHEMA['parameters']['properties']
    assert composition.ACTIONS <= set(props['action']['enum'])
    assert 'compose' in props['mode']['enum']
    # Exercise trusted owner scope at the real synchronous handler boundary.
    c.sessions.clear(); s.user=s.chat=7; s.thread=None
    ident=(7,7,None); c.sessions[ident]=s
    monkeypatch.setattr(c,'_identity',lambda:ident)
    c.loop=asyncio.get_running_loop()
    await s.page.set_content(HTML)
    async def attach(*args,**kwargs): return s
    monkeypatch.setattr(c,'_attach_session',attach)
    attached=json.loads(await asyncio.to_thread(c.tool, {'action':'attach','mode':'compose','origin':'https://fixture.example'}))
    assert attached['status']=='attached'
    assert not c.bot.sent
    discovered=json.loads(await asyncio.to_thread(c.tool,{'action':'discover_components','session_ref':attached['session_ref']}))
    assert discovered['status']=='composition_available'
    composed={'action':'present_composition','snapshot_ref':discovered['snapshot_ref'],'layout':'stack',
              'groups':[{'title':'contact','refs':[discovered['refs'][0]['ref']]}]}
    branch=next(b for b in SCHEMA['parameters']['oneOf'] if b['properties']['action'].get('const')=='present_composition')
    assert set(branch['required'])==set(composed)
    assert branch['additionalProperties'] is False
    result=json.loads(await asyncio.to_thread(c.tool,composed))
    assert result['status']=='waiting_for_handoff'
    status=json.loads(await asyncio.to_thread(c.tool,{'action':'composition_status','component_ref':result['component_ref']}))
    assert status==result
    cancelled=json.loads(await asyncio.to_thread(c.tool,{'action':'cancel_composition','component_ref':result['component_ref']}))
    assert cancelled['status']=='cancelled'
    for payload in [ {'action':[]}, {'action':'present_composition','groups':[]},
                     {'action':'discover_components','session_ref':attached['session_ref'],'value':'forbidden'},
                     {'action':'discover_components','session_ref':3} ]:
        assert json.loads(await asyncio.to_thread(c.tool,payload))['status']=='invalid'

@pytest.mark.asyncio
async def test_cancel_status_and_expiry_status(form_controller):
    c,s=form_controller
    await s.page.set_content(HTML)
    found=await discover(c,s)
    result=await c._run('present_composition', {'action':'present_composition','snapshot_ref':found['snapshot_ref'],
                  'layout':'stack','groups':[{'title':'details','refs':[found['refs'][0]['ref']]}]},IDENT)
    payload={'action':'cancel_composition','component_ref':result['component_ref']}
    assert (await c._run('cancel_composition',payload,IDENT))['status']=='cancelled'
    payload['action']='composition_status'
    assert (await c._run('composition_status',payload,IDENT))['status']=='cancelled'
    assert s.request is None and s.key is None and not s.composition_refs and not s.composition_options
