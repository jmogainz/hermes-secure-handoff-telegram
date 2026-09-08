"""Negative lifecycle gates through the production acquisition route."""
import asyncio
from pathlib import Path
import subprocess
import sys
import pytest
from test_purchase_acquisition import attached, tool, deliver, arm_and_present, IDENT
from test_checkout_flow import envelope, update
from plugin.purchase_facts import PurchaseFactRegistry

@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['partial_factory','cancel_during_factory','source_closed_after_entry'])
async def test_postfill_acquisition_failure_scrubs_partial_registry(tmp_path,monkeypatch,failure):
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    allocated=[]; entered=asyncio.Event(); proceed=asyncio.Event()
    original=PurchaseFactRegistry.capture_money
    async def capture(registry,*args,**kwargs):
        allocated.append(registry)
        await original(registry,*args,**kwargs)
        if failure=='partial_factory': raise ValueError('synthetic capture failure')
        entered.set(); await proceed.wait()
    try:
        await arm_and_present(c,s,catalog)
        lease=s.purchase_sources; grant=s.catalog_grants[0]
        if failure=='source_closed_after_entry': await catalog.close()
        else: monkeypatch.setattr(PurchaseFactRegistry,'capture_money',capture)
        raw=envelope(s,{'values':{'f0':'synthetic entry'}})
        if failure=='cancel_during_factory':
            pending=asyncio.create_task(deliver(c,raw))
            await asyncio.wait_for(entered.wait(),5)
            event=update(raw); event.effective_chat.id=7
            cancel=asyncio.create_task(c.cancel_from_update(event))
            await asyncio.sleep(0)
            proceed.set()
            await asyncio.gather(pending,cancel)
            assert s.status=='cancelled'
        else:
            await deliver(c,raw)
            assert s.status=='rejected'
        await asyncio.sleep(0)
        assert s.purchase_registry is None and s.purchase_sources is None
        assert s.purchase_factory is None and not s.catalog_grants
        assert lease.closed and grant.closed
        assert all(r._closed and not r._facts and not r._observations for r in allocated)
        assert await page.evaluate('window.clicks')==0
    finally:
        await c._close(IDENT)
        # cancel_from_update intentionally releases the session without closing
        # owner tabs. This disposable fixture still owns its browser transport.
        await c._dispose(s)

@pytest.mark.asyncio
async def test_no_entry_purchase_is_not_fabricated_as_filled(tmp_path,monkeypatch):
    c,s,catalog,page=await attached(tmp_path,monkeypatch)
    try:
        await page.evaluate("document.querySelector('label').remove()")
        assert (await tool(c,action='discover_components',session_ref=s.session_ref))['status']=='rejected'
        assert (await tool(c,action='discover_purchase_sources',session_ref=s.session_ref))['status']=='rejected'
        assert not s.checkout_filled and s.purchase_factory is None
        assert await page.evaluate('window.clicks')==0
    finally:
        await c._close(IDENT)
        # cancel_from_update intentionally releases the session without closing
        # owner tabs. This disposable fixture still owns its browser transport.
        await c._dispose(s)


def test_directory_loader_actual_acquisition_execution(tmp_path):
    root=Path(__file__).resolve().parents[1]
    script='''
import sys,asyncio
from pathlib import Path
sys.path[:0]=[str(Path.cwd()/'plugin'),str(Path.cwd()/'tests')]
import secure_handoff,test_checkout_flow,test_purchase_acquisition,pytest
 test_placeholder
'''.replace(' test_placeholder', '''test_checkout_flow.SecureHandoffController=secure_handoff.SecureHandoffController
assert secure_handoff.__package__==''
async def run():
    with pytest.MonkeyPatch.context() as patch:
        await test_purchase_acquisition.test_tool_acquisition_composed_entry_encrypted_purchase(Path(sys.argv[1]),patch,'definitions')
asyncio.run(run())''')
    result=subprocess.run([sys.executable,'-c',script,str(tmp_path)],cwd=root,capture_output=True,timeout=60)
    assert result.returncode==0,result.stderr.decode()
