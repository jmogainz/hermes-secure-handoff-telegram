"""Adversarial bounded-composition coverage; disposable browser and fake publisher."""
import asyncio
import copy
import json
import time
from types import SimpleNamespace
import pytest
from telegram.ext import ApplicationHandlerStop
from test_general_forms import form_controller
from test_composition import discover, HTML, IDENT
from test_checkout_flow import envelope, update
from plugin.secure_handoff import Session


def present(found):
    return {'action':'present_composition','snapshot_ref':found['snapshot_ref'],'layout':'sections',
            'groups':[{'title':'details','refs':[r['ref'] for r in found['refs']]}]}

@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['omit','duplicate','foreign','title','layout','html','value','huge','nested','empty'])
async def test_invalid_composition_is_not_published(form_controller, change):
    c,s=form_controller
    await s.page.set_content(HTML)
    found=await discover(c,s); args=present(found)
    if change=='omit': args['groups'][0]['refs'].pop(0)
    if change=='duplicate': args['groups'][0]['refs'].append(found['refs'][0]['ref'])
    if change=='foreign': args['groups'][0]['refs'][0]='fr_'+'a'*32
    if change=='title': args['groups'][0]['title']='<script>evil</script>'
    if change=='layout': args['layout']='hidden'
    if change=='html': args['html']='<input>'
    if change=='value': args['groups'][0]['value']='forbidden'
    if change=='huge': args['groups']*=9
    if change=='nested': args['groups'][0]['refs']=[args['groups'][0]]
    if change=='empty': args['groups']=[]
    assert (await c._run('present_composition',args,IDENT))['status'] in {'invalid','rejected'}
    assert not c.bot.sent
    assert await s.page.evaluate('window.order')==[]

@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', [
    "document.querySelector('input').outerHTML='<input required name=first>'",
    "document.querySelector('form').outerHTML=document.querySelector('form').outerHTML",
    "document.querySelector('input').required=false",
    "document.querySelector('textarea').required=true",
    "document.querySelector('option').textContent='changed'",
    "document.querySelector('option').value='changed'",
    "document.querySelector('input').style.opacity=0",
    "document.querySelector('form').insertAdjacentHTML('beforeend','<input required>')",
    'navigate', 'expire',
])
async def test_stale_discovery_cannot_publish(form_controller, mutation):
    c,s=form_controller; await s.page.set_content(HTML)
    found=await discover(c,s)
    if mutation=='navigate': await s.page.goto('https://fixture.example/replaced'); await s.page.set_content(HTML)
    elif mutation=='expire': s.request['expiresAt']=int(time.time()*1000)-1
    else: await s.page.evaluate(mutation)
    result=await c._run('present_composition',present(found),IDENT)
    assert result['status'] in {'publication_failed','rejected'}
    assert not c.bot.sent and s.key is None

@pytest.mark.asyncio
async def test_scope_supersession_replay_and_foreign_snapshot(form_controller):
    c,s=form_controller; await s.page.set_content(HTML)
    first=await discover(c,s)
    second=await discover(c,s)
    assert (await c._run('present_composition',present(first),IDENT))['status']=='rejected'
    forged=present(second); forged['groups'][0]['refs'][0]=first['refs'][0]['ref']
    assert (await c._run('present_composition',forged,IDENT))['status']=='rejected'
    for ident in [(9,9,None),(7,8,None),(7,7,42)]:
        c.sessions[ident]=Session(*ident,page=s.page,context=s.context,requested_mode='compose')
        assert (await c._run('present_composition',present(second),ident))['status']=='rejected'
    result=await c._run('present_composition',present(second),IDENT)
    assert result['status']=='waiting_for_handoff'
    count=len(c.bot.sent)
    assert (await c._run('present_composition',present(second),IDENT))['status']=='rejected'
    assert len(c.bot.sent)==count
    args={'action':'composition_status','component_ref':result['component_ref']}
    assert (await c._run('composition_status',args,(9,9,None)))['status']=='rejected'
    for action in ['present','click','type']:
        assert (await c._run(action,{},IDENT))['status']=='forbidden'
    s.request['expiresAt']=int(time.time()*1000)-1
    assert (await c._run('composition_status',args,IDENT))['status']=='expired'

@pytest.mark.asyncio
async def test_publication_failure_revokes_request(form_controller):
    c,s=form_controller; await s.page.set_content(HTML)
    found=await discover(c,s)
    async def fail(**kwargs): raise RuntimeError('synthetic failure')
    c.bot.send_message=fail
    assert (await c._run('present_composition',present(found),IDENT))['status']=='publication_failed'
    assert s.key is None and s.request is None and not s.refs and not s.composition_options
    assert (await c._run('present_composition',present(found),IDENT))['status']=='rejected'

@pytest.mark.asyncio
async def test_cancel_queued_apply_rejects_before_decrypt(form_controller,monkeypatch):
    c,s=form_controller; await s.page.set_content(HTML)
    found=await discover(c,s); result=await c._run('present_composition',present(found),IDENT)
    raw=envelope(s,{'values':{'f0':'synthetic','f1':'notes','f2':'o0'}})
    decrypts=[]
    monkeypatch.setattr('plugin.secure_handoff.decrypt_submission',lambda *a:decrypts.append(True))
    await s.lock.acquire()
    apply=asyncio.create_task(c._web_data(update(raw),SimpleNamespace(bot=c.bot)))
    cancel=asyncio.create_task(c._run('cancel_composition',{'action':'cancel_composition','component_ref':result['component_ref']},IDENT))
    await asyncio.sleep(0)
    s.lock.release()
    with pytest.raises(ApplicationHandlerStop): await apply
    assert (await cancel)['status']=='cancelled'
    assert not decrypts and await s.page.evaluate('window.order')==[]

@pytest.mark.asyncio
@pytest.mark.parametrize('extra', ['<input type=checkbox required>','<input type=color>','<input type=range>',
                                  '<input type=file>','<select multiple><option>A</option></select>'])
async def test_unsupported_nonempty_native_defaults_fail_closed(form_controller, extra):
    c,s=form_controller; await s.page.set_content('<form><input required>'+extra+'</form>')
    assert (await discover(c,s))['status']=='rejected'
    assert not c.bot.sent


@pytest.mark.asyncio
async def test_native_cancel_scrubs_composition_private_maps(form_controller):
    c,s=form_controller; await s.page.set_content(HTML)
    found=await discover(c,s)
    await c._run('present_composition',present(found),IDENT)
    assert s.composition_options
    assert await c.cancel_from_update(update(''))
    assert not s.composition_options and not s.composition_fields and not s.composition_refs


@pytest.mark.asyncio
async def test_compose_mode_cannot_enter_legacy_presentation(form_controller):
    c,s=form_controller; await s.page.set_content(HTML)
    assert (await c._run('present',{'mode':'compose'},IDENT))['status']=='invalid'
    assert not c.bot.sent

@pytest.mark.asyncio
@pytest.mark.parametrize('bad', ['missing','unknown','changed','wrong_owner'])
async def test_composition_submit_rejects_invalid_or_stale_payload(form_controller,bad,monkeypatch):
    c,s=form_controller; await s.page.set_content(HTML)
    found=await discover(c,s); await c._run('present_composition',present(found),IDENT)
    values={'f0':'synthetic','f1':'notes','f2':'o1'}
    if bad=='missing': values.pop('f0')
    if bad=='unknown': values['f9']='synthetic'
    raw=envelope(s,{'values':values})
    u=update(raw)
    if bad=='wrong_owner': u.effective_user.id=9
    if bad=='changed':
        await s.page.evaluate("document.querySelector('textarea').required=true")
        monkeypatch.setattr('plugin.secure_handoff.decrypt_submission',lambda *a:pytest.fail('decrypted stale fields'))
    with pytest.raises(ApplicationHandlerStop): await c._web_data(u,SimpleNamespace(bot=c.bot))
    assert await s.page.evaluate('window.order')==[]
    assert await s.page.evaluate('window.clicks')==0
