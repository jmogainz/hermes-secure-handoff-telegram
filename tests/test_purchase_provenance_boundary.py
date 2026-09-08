"""Even perfect-looking checkout text cannot mint public fact provenance."""
import asyncio
import json
from types import SimpleNamespace

import pytest
from plugin import purchase_approval
from test_purchase_approval import checkout, fill
from test_purchase_discovery import table_summary, row_summary
from test_purchase_review_regressions import assert_no_public_summary


@pytest.mark.asyncio
@pytest.mark.parametrize('layout', ['dl', 'table', 'rows', 'nested_dl'])
async def test_matching_synthetic_dom_without_source_stays_closed(tmp_path, layout):
    # Intentionally no reviewed=True: semantic equality is NOT provenance.
    async with checkout(tmp_path) as (controller, s):
        if layout != 'dl':
            markup = table_summary() if layout == 'table' else row_summary(layout)
            await s.page.locator('dl').evaluate('(e, html) => e.outerHTML=html', markup)
        await fill(controller, s)
        assert s.status == 'human_action_required'
        assert s.request is None and s.key is None
        assert s.commit_guard is None
        assert_no_public_summary(controller)
        assert await s.page.evaluate('window.clicks') == 0
        # Re-reading cannot mint new authority or replay the private entry.
        result = await controller._run('read', {}, (7, 8, 42))
        assert result['status'] == 'human_action_required'
        assert result['reason'] == 'public_fact_source_unavailable'
        assert_no_public_summary(controller)

@pytest.mark.asyncio
async def test_unreviewed_source_rejects_before_any_dom_read():
    class NoBrowserReads:
        url = 'https://unreviewed.example/checkout'

        def __getattr__(self, name):
            pytest.fail(f'Unreviewed source attempted browser access: {name}')

    assert purchase_approval._REVIEWED_SOURCES == {}

    with pytest.raises(ValueError, match='reviewed purchase source required'):
        await purchase_approval.pin_purchase(SimpleNamespace(page=NoBrowserReads()))


@pytest.mark.asyncio
@pytest.mark.parametrize('reviewed', [False, True])
async def test_real_tool_read_reports_only_bounded_blocker(tmp_path, monkeypatch, reviewed):
    async with checkout(tmp_path, reviewed=reviewed) as (controller, s):
        if reviewed:
            await s.page.locator('dd').first.evaluate("e => e.textContent='SYNTHETIC PRIVATE BILLING TEXT'")
        await fill(controller, s)
        assert s.status == 'human_action_required'
        original = (s.user, s.chat, s.thread)
        ident = (7, 7, None)
        controller.sessions.clear()
        s.user, s.chat, s.thread = ident
        controller.sessions[ident] = s
        monkeypatch.setattr(controller, '_identity', lambda: ident)
        try:
            result = json.loads(await asyncio.to_thread(controller.tool, {'action':'read'}))
            expected = 'purchase_binding_unsupported' if reviewed else 'public_fact_source_unavailable'
            assert result == {'status':'human_action_required', 'url':controller._safe_origin(s), 'reason':expected}
            assert 'PRIVATE' not in json.dumps(result)
            assert_no_public_summary(controller)
        finally:
            controller.sessions.clear()
            s.user, s.chat, s.thread = original
            controller.sessions[original] = s
