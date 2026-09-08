"""Security-review reproductions: disposable Chromium, synthetic data only."""
import base64
import json
import copy
from urllib.parse import urlsplit
from test_purchase_approval import checkout, fill, deliver
from test_checkout_flow import envelope
import pytest
from plugin import purchase_approval as purchase


def contract():
    # Public catalog constants from a synthetic reviewed adapter, NOT DOM text.
    return {'version': 1, 'item': 'Example subscription', 'merchant': 'Example merchant',
            'currency': 'USD', 'price': {'subtotal': 1000, 'tax': 100, 'fees': 134, 'total': 1234},
            'refund': 'non_refundable',
            'recurrence': {'kind': 'recurring', 'first_start': '2026-09-08',
                           'first_end': '2027-09-08', 'renewal_start': '2027-09-08',
                           'cadence': 'annually', 'price': {'subtotal': 1800, 'tax': 200, 'fees': 0, 'total': 2000}}}


def test_typed_recurring_summary_includes_first_term_and_transition():
    summary = purchase.validate_source_contract(contract())
    assert '2026-09-08' in summary['item']
    assert '2027-09-08' in summary['item']
    assert '2027-09-08' in summary['terms']
    assert summary['totalIncludingTax'] == '12.34'
    assert summary['renewal'] == 'Renews annually at USD 20.00 including tax; cancel before renewal.'


@pytest.mark.parametrize('change', ['missing_start', 'missing_end', 'missing_transition',
                                   'mismatch_transition', 'reversed_term', 'tax_unknown',
                                   'total_mismatch', 'renewal_tax_unknown', 'extra_prose'])
def test_typed_contract_rejects_incomplete_or_contradictory_semantics(change):
    value = copy.deepcopy(contract())
    if change.startswith('missing_'):
        key = {'missing_start': 'first_start', 'missing_end': 'first_end', 'missing_transition': 'renewal_start'}[change]
        del value['recurrence'][key]
    elif change == 'mismatch_transition':
        value['recurrence']['renewal_start'] = '2028-09-08'
    elif change == 'reversed_term':
        value['recurrence']['first_end'] = '2025-09-08'
    elif change == 'tax_unknown':
        value['price']['tax'] = None
    elif change == 'total_mismatch':
        value['price']['tax'] = 500
    elif change == 'renewal_tax_unknown':
        value['recurrence']['price']['tax'] = None
    else:
        value['terms'] = 'Tax of USD 5.00 is due at checkout.'
    with pytest.raises(ValueError):
        purchase.validate_source_contract(value)


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', [None, 'after_approval', 'formatted_echo', 'contradictory_tax'])
async def test_reviewed_typed_source_keeps_one_shot_engine(tmp_path, monkeypatch, mutation):
    async with checkout(tmp_path) as (controller, session):
        summary = purchase.validate_source_contract(contract())
        await session.page.locator('dd').evaluate_all('(nodes, texts) => nodes.forEach((n,i) => n.textContent=texts[i])', list(summary.values()))
        async def reviewed_source(bound_session):
            assert bound_session is session
            return contract()
        url = urlsplit(session.page.url)
        monkeypatch.setitem(purchase._REVIEWED_SOURCES, f'{url.scheme}://{url.netloc}', reviewed_source)
        if mutation == 'formatted_echo':
            await session.page.evaluate("""() => document.querySelector('input').addEventListener('input', e => {
                document.querySelector('dd').textContent += e.target.value.replaceAll('-', ' ');
            })""")
        elif mutation == 'contradictory_tax':
            await session.page.locator('dd').nth(5).evaluate("e => e.textContent='Tax of USD 5.00 is due at checkout.'")
        await fill(controller, session)
        if mutation in ('formatted_echo', 'contradictory_tax'):
            assert session.status == 'human_action_required'
            assert await session.page.evaluate('window.clicks') == 0
            assert_no_public_summary(controller)
            return
        assert session.status == 'waiting_for_confirmation'
        assert session.request is not None
        assert session.request['transaction']['summary'] == summary
        raw = envelope(session, {'approve': session.request['transaction']['id']})
        if mutation == 'after_approval':
            await session.page.locator('dd').nth(3).evaluate("e => e.textContent='99.99'")
        await deliver(controller, session, raw=raw)
        if mutation == 'after_approval':
            assert session.status != 'purchase_submitted'
            assert await session.page.evaluate('window.clicks') == 0
        else:
            assert session.status == 'purchase_submitted'
            assert await session.page.evaluate('window.clicks') == 1
            await deliver(controller, session, raw=raw)
            assert await session.page.evaluate('window.clicks') == 1


def assert_no_public_summary(controller):
    for message in controller.bot.sent:
        markup = message.get('reply_markup')
        if not markup:
            continue
        for row in markup.keyboard:
            for button in row:
                if not button.web_app:
                    continue
                encoded = button.web_app.url.split('#request=')[1]
                manifest = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
                assert manifest.get('mode') != 'purchase_approval'
                assert 'transaction' not in manifest



@pytest.mark.asyncio
@pytest.mark.parametrize('case', ['formatted_echo', 'fragmented_echo', 'static_billing',
                                 'incomplete_subscription', 'contradictory_tax'])
async def test_unreviewed_dom_never_publishes_purchase_summary(tmp_path, case):
    async with checkout(tmp_path) as (controller, session):
        if case == 'formatted_echo':
            await session.page.evaluate("""() => document.querySelector('input').addEventListener('input', e => {
                document.querySelector('dd').textContent='Example product; billing: '+e.target.value.replaceAll('-', ' ');
            })""")
        elif case == 'fragmented_echo':
            await session.page.evaluate("""() => document.querySelector('input').addEventListener('input', e => {
                document.querySelector('dd').textContent='Example product; billing: '+e.target.value.split('').join(' ');
            })""")
        else:
            index, text = {'static_billing': (0, 'Example product; billing: Synthetic Person'),
                           'incomplete_subscription': (0, 'Example subscription'),
                           'contradictory_tax': (5, 'No additional fees. Tax of USD 5.00 is due at checkout.')}[case]
            await session.page.locator('dd').nth(index).evaluate('(e, text) => e.textContent=text', text)
        await fill(controller, session)
        assert session.status == 'human_action_required'
        assert not session.request or session.request.get('mode') != 'purchase_approval'
        assert_no_public_summary(controller)
        assert await session.page.evaluate('window.clicks') == 0
