"""Disposable, intercepted HTTPS pages only; never attach to a live browser."""
import json
from contextlib import asynccontextmanager

import pytest
from playwright.async_api import async_playwright

from plugin import purchase_facts as facts


@asynccontextmanager
async def fixture():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context()
        await context.route('**/*', lambda route: route.fulfill(body='<html></html>', content_type='text/html'))
        page = await context.new_page()
        await page.goto('https://shop.example/checkout')
        await page.set_content('<section id="checkout"><span id="item">Example plan</span>'
                               '<span id="total">USD 12.34</span><span id="tax">USD 1.00</span>'
                               '<input value="SYNTHETIC PRIVATE"><button id="pay">PRIVATE ACTION</button></section>')
        source = await context.new_page()
        await source.goto('https://catalog.example/product?private-query=not-for-wire')
        await source.set_content('<h1>Example plan</h1>')
        clock = [10.0]
        registry = await facts.PurchaseFactRegistry.create(owner=(7, 8), session=object(), page=page,
                    scope=await page.query_selector('#checkout'), ttl=30, clock=lambda: clock[0])
        try:
            yield registry, page, source, clock
        finally:
            await registry.close()
            await browser.close()


@pytest.mark.asyncio
async def test_purchase_display_rules_before_fact_publication():
    from pathlib import Path
    cases = json.loads(Path(__file__).with_name('purchase_display_cases.json').read_text())
    async with fixture() as (r, page, source, _):
        node = await source.query_selector('h1')
        checkout_node = await page.query_selector('#item')
        assert node is not None and checkout_node is not None
        for codepoint in cases['rejectedCodePoints']:
            text = 'Example ' + chr(codepoint) + '123 product'
            await node.evaluate('(e,t)=>e.textContent=t', text)
            await checkout_node.evaluate('(e,t)=>e.textContent=t', text)
            with pytest.raises(facts.FactRejected, match='ineligible_leaf'):
                await r.capture_public_product(node)
            # Same leaf policy applies to checkout snapshots and final guards.
            with pytest.raises(facts.FactRejected, match='ineligible_leaf'):
                await r._leaf(checkout_node)
            assert not r._observations and not r._facts
        for text in cases['acceptedItems']:
            await node.evaluate('(e,t)=>e.textContent=t', text)
            observation = await r.capture_public_product(node)
            assert r._observations[observation].value == text  # No normalization.


async def populate(registry, page, source):
    observation = await registry.capture_public_product(await source.query_selector('h1'))
    item = await registry.bind_product(observation, await page.query_selector('#item'))
    total = await registry.capture_money(await page.query_selector('#total'), role='displayed_total', currency='USD')
    action = await registry.capture_action(await page.query_selector('#pay'))
    return observation, item, total, action


@pytest.mark.asyncio
async def test_public_capture_live_match_and_ref_only_composition():
    async with fixture() as (r, page, source, _):
        _, item, total, action = await populate(r, page, source)
        discovery = await r.discover(owner=r.owner, session=r.session)
        assert discovery['status'] == 'ready'
        payload = {'revision': discovery['revision'], 'fact_refs': [total, item], 'action_ref': action}
        selection = await r.compose(payload, owner=r.owner, session=r.session)
        wire = selection.projection()
        assert wire['facts'][0]['amount'] == '12.34'
        assert wire['facts'][1]['value'] == 'Example plan'
        assert wire['action']['label'] == 'Bound purchase action'
        assert all(text not in json.dumps(wire) for text in ('PRIVATE', 'private-query', 'selector', 'handle'))
        wire['facts'][1]['value'] = 'injected'
        assert selection.projection()['facts'][1]['value'] == 'Example plan'
        assert await r.validate(selection, owner=r.owner, session=r.session) is True
        with pytest.raises((AttributeError, TypeError)):
            setattr(selection, '_wire', '{}')


@pytest.mark.asyncio
async def test_source_history_not_recaptured_and_forged_provenance_rejected():
    async with fixture() as (r, page, source, _):
        obs = await r.capture_public_product(await source.query_selector('h1'))
        await source.locator('h1').evaluate("e=>e.textContent='SYNTHETIC PRIVATE CHANGED'")
        for forged in ({'public': True, 'complete': True}, facts.PublicProductObservation(), None):
            with pytest.raises(facts.FactRejected, match='missing_provenance'):
                await r.bind_product(forged, await page.query_selector('#item'))
        await r.bind_product(obs, await page.query_selector('#item'))
        wire = await r.discover(owner=r.owner, session=r.session)
        assert wire['facts'][0]['value'] == 'Example plan'
        assert 'CHANGED' not in json.dumps(wire)
        assert wire['reasons'] == ['missing_total', 'missing_action']


@pytest.mark.asyncio
@pytest.mark.parametrize('markup', [
    '<span>Example plan<span>SYNTHETIC PRIVATE</span></span>',
    '<input value="SYNTHETIC PRIVATE">',
    '<span contenteditable>Example plan</span>',
    '<span hidden>Example plan</span>',
    '<form><span>Example plan</span></form>',
])
async def test_public_structurally_mixed_or_private_regions_rejected(markup):
    async with fixture() as (r, page, source, _):
        await source.set_content(markup)
        node = await source.query_selector('body > *')
        with pytest.raises(facts.FactRejected, match='ineligible_leaf'):
            await r.capture_public_product(node)
        assert (await r.discover(owner=r.owner, session=r.session))['facts'] == []


@pytest.mark.asyncio
@pytest.mark.parametrize('text,currency,role,reason', [
    ('USD 12.34 plus tax', 'USD', 'displayed_total', 'invalid_money_leaf'),
    ('SYNTHETIC PRIVATE USD 12.34', 'USD', 'tax', 'invalid_money_leaf'),
    ('12.34', 'USD', 'tax', 'invalid_money_leaf'),
    ('$12.34', 'USD', 'tax', 'invalid_money_leaf'),
    ('EUR 12.34', 'USD', 'tax', 'invalid_money_leaf'),
    ('USD 12.3', 'USD', 'tax', 'invalid_money_leaf'),
    ('USD 012.34', 'USD', 'tax', 'invalid_money_leaf'),
    ('USD 12.34', None, 'tax', 'ambiguous_currency'),
    ('USD 12.34', 'USD', None, 'ambiguous_role'),
    ('USD 12.34', 'USD', 'card_number', 'ambiguous_role'),
])
async def test_complete_money_token_with_explicit_role_currency(text, currency, role, reason):
    async with fixture() as (r, page, source, _):
        # A new registry is needed after a checkout mutation, as in post-fill integration.
        await r.close()
        await page.locator('#total').evaluate('(e,t)=>e.textContent=t', text)
        other = await facts.PurchaseFactRegistry.create(owner=r.owner, session=r.session, page=page,
                    scope=await page.query_selector('#checkout'))
        try:
            with pytest.raises(facts.FactRejected, match=reason):
                await other.capture_money(await page.query_selector('#total'), role=role, currency=currency)
        finally:
            await other.close()


@pytest.mark.asyncio
async def test_money_leaf_cannot_be_mixed_or_control():
    async with fixture() as (r, page, source, _):
        for selector in ('#checkout', 'input'):
            with pytest.raises(facts.FactRejected, match='ineligible_leaf'):
                await r.capture_money(await page.query_selector(selector), role='tax', currency='USD')
        with pytest.raises(facts.FactRejected, match='invalid_binding'):
            await r.capture_money('#total', role='tax', currency='USD')


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', [
    "document.querySelector('#item').textContent='SYNTHETIC PRIVATE'",
    "document.querySelector('#total').textContent='USD 99.00'",
    "document.querySelector('#pay').outerHTML='<button id=pay>PRIVATE ACTION</button>'",
    "document.querySelector('#checkout').outerHTML=document.querySelector('#checkout').outerHTML",
    "let n=document.querySelector('#total');n.textContent='USD 99.00';n.textContent='USD 12.34'",
    "document.querySelector('input').dispatchEvent(new Event('input',{bubbles:true}))",
    "document.querySelector('#checkout').appendChild(document.createElement('span'))",
])
async def test_changed_original_nodes_and_epoch_invalidate_sealed_selection(mutation):
    async with fixture() as (r, page, source, _):
        _, item, total, action = await populate(r, page, source)
        selected = await r.compose({'revision': r.revision, 'fact_refs': [item, total], 'action_ref': action}, owner=r.owner, session=r.session)
        before = selected.projection()
        await page.evaluate('()=>{' + mutation + '}')
        with pytest.raises(facts.FactRejected, match='changed_binding'):
            await r.validate(selected, owner=r.owner, session=r.session)
        with pytest.raises(facts.FactRejected, match='changed_binding'):
            await r.discover(owner=r.owner, session=r.session)
        assert selected.projection() == before
        assert 'SYNTHETIC PRIVATE' not in json.dumps(before)


@pytest.mark.asyncio
async def test_foreign_owner_session_document_refs_and_expiry():
    async with fixture() as (r, page, source, clock):
        obs, item, total, action = await populate(r, page, source)
        payload = {'revision': r.revision, 'fact_refs': [item, total], 'action_ref': action}
        for owner, session in (((99, 8), r.session), (r.owner, object())):
            with pytest.raises(facts.FactRejected, match='foreign_scope'):
                await r.compose(payload, owner=owner, session=session)
        with pytest.raises(facts.FactRejected, match='changed_binding'):
            await r.bind_product(obs, await source.query_selector('h1'))
        with pytest.raises(facts.FactRejected, match='foreign_ref'):
            await r.compose({**payload, 'action_ref': 'pa_forged'}, owner=r.owner, session=r.session)
        clock[0] = 40.0
        with pytest.raises(facts.FactRejected, match='expired_revision'):
            await r.compose(payload, owner=r.owner, session=r.session)


@pytest.mark.asyncio
async def test_navigation_same_url_invalidates_original_document():
    async with fixture() as (r, page, source, _):
        await populate(r, page, source)
        await page.reload()
        with pytest.raises(facts.FactRejected, match='changed_binding'):
            await r.discover(owner=r.owner, session=r.session)


@pytest.mark.asyncio
async def test_all_registered_facts_required_and_payload_cannot_inject_text():
    async with fixture() as (r, page, source, _):
        _, item, total, action = await populate(r, page, source)
        tax = await r.capture_money(await page.query_selector('#tax'), role='tax', currency='USD')
        payload = {'revision': r.revision, 'fact_refs': [item, total], 'action_ref': action}
        with pytest.raises(facts.FactRejected, match='required_fact_omitted'):
            await r.compose(payload, owner=r.owner, session=r.session)
        for patch in ({'amount': '0.01'}, {'text': 'arbitrary'}, {'revision': 'pr_foreign'}, {'fact_refs': [item, item]}):
            with pytest.raises(facts.FactRejected, match='invalid_composition'):
                await r.compose({**payload, **patch}, owner=r.owner, session=r.session)
        selected = await r.compose({**payload, 'fact_refs': [item, total, tax]}, owner=r.owner, session=r.session)
        assert selected.projection()['facts'][2]['role'] == 'tax'
        with pytest.raises(facts.FactRejected, match='foreign_selection'):
            await r.validate(facts.PurchaseSelection(json.dumps(selected.projection())), owner=r.owner, session=r.session)


@pytest.mark.asyncio
async def test_ambiguous_totals_and_bounded_registry():
    async with fixture() as (r, page, source, _):
        await populate(r, page, source)
        await r.capture_money(await page.query_selector('#tax'), role='displayed_total', currency='USD')
        assert (await r.discover(owner=r.owner, session=r.session))['reasons'] == ['ambiguous_total']
        for _ in range(r.MAX_FACTS - 4):
            await r.capture_money(await page.query_selector('#tax'), role='displayed_total', currency='USD')
        with pytest.raises(facts.FactRejected, match='registry_full'):
            await r.capture_action(await page.query_selector('#pay'))
        await r.close()
        with pytest.raises(facts.FactRejected, match='expired_revision'):
            await r.discover(owner=r.owner, session=r.session)


@pytest.mark.asyncio
async def test_same_node_cannot_be_reclassified_as_different_fact_role():
    async with fixture() as (r, page, source, _):
        await r.capture_money(await page.query_selector('#total'), role='displayed_total', currency='USD')
        with pytest.raises(facts.FactRejected, match='ambiguous_provenance'):
            await r.capture_money(await page.query_selector('#total'), role='tax', currency='USD')


@pytest.mark.asyncio
async def test_public_observation_exact_comparison_and_foreign_issuer():
    async with fixture() as (r, page, source, _):
        await source.locator('h1').evaluate("e=>e.textContent='Other plan'")
        obs = await r.capture_public_product(await source.query_selector('h1'))
        with pytest.raises(facts.FactRejected, match='product_mismatch'):
            await r.bind_product(obs, await page.query_selector('#item'))
        other = await facts.PurchaseFactRegistry.create(owner=r.owner, session=r.session, page=page,
                    scope=await page.query_selector('#checkout'))
        try:
            with pytest.raises(facts.FactRejected, match='missing_provenance'):
                await other.bind_product(obs, await page.query_selector('#item'))
        finally:
            await other.close()


@pytest.mark.asyncio
async def test_concurrent_roles_cannot_race_provenance_check():
    import asyncio
    async with fixture() as (r, page, source, _):
        node = await page.query_selector('#total')
        outcomes = await asyncio.gather(
            r.capture_money(node, role='displayed_total', currency='USD'),
            r.capture_money(node, role='tax', currency='USD'), return_exceptions=True)
        assert sum(isinstance(x, facts.FactRejected) for x in outcomes) == 1
        assert len((await r.discover(owner=r.owner, session=r.session))['facts']) == 1
