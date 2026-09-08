"""Synthetic disposable Chromium checkout discovery; never attaches to live Chrome."""
import html

import pytest

from test_purchase_approval import SUMMARY, LABELS, checkout, fill, deliver


def table_summary():
    rows = ''.join(f'<tr><th scope="row">{html.escape(label)}</th><td>{html.escape(value)}</td></tr>'
                   for label, value in zip(LABELS, SUMMARY.values()))
    return '<table><caption>Order summary</caption><tbody>' + rows + '</tbody></table>'


def row_summary(layout='rows'):
    aliases = ['Product', 'Seller', 'Currency', 'Total including tax and fees', 'Billing frequency', 'Purchase terms']
    pairs = list(zip(aliases, SUMMARY.values()))[::-1]
    if layout == 'nested_dl':
        body = '<dl>' + ''.join(f'<dt>{label}</dt><dd>{value}</dd>' for label, value in pairs) + '</dl>'
    else:
        body = ''.join(f'<div><strong>{label}</strong><span>{value}</span></div>' for label, value in pairs)
    return '<section><h2>Checkout summary</h2>' + body + '</section>'


@pytest.mark.asyncio
@pytest.mark.parametrize('layout', ['rows', 'nested_dl'])
async def test_heading_scoped_semantic_rows_with_aliases_and_reordered_fields(tmp_path, layout):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        await s.page.locator('dl').evaluate('(e,text)=>e.outerHTML=text', row_summary(layout))
        await fill(controller, s)
        assert s.status == 'waiting_for_confirmation'
        assert s.request['transaction']['summary'] == SUMMARY
        await deliver(controller, s, {'approve': s.request['transaction']['id']})
        assert s.status == 'purchase_submitted'
        assert await s.page.evaluate('window.clicks') == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', [
    "document.querySelectorAll('td')[3].innerHTML='12.34<span hidden>99.99</span>'",
    "document.querySelectorAll('td')[3].innerHTML='<s>12.34</s>'",
    "document.querySelector('table').insertAdjacentHTML('beforeend','<tfoot><tr><td colspan=2>Tax unknown</td></tr></tfoot>')",
    "document.querySelector('table').insertAdjacentHTML('beforeend','<caption>Fees unknown</caption>')",
    "document.querySelectorAll('td')[5].textContent='No additional fees. Tax unknown.'",
    "document.querySelectorAll('td')[5].textContent='No additional fees. Shipping calculated later.'",
    "document.querySelectorAll('td')[5].textContent='No additional fees. Plus service charge.'",
    "document.querySelectorAll('td')[5].textContent='No additional fees. Fees may apply.'",
    "document.querySelectorAll('td')[5].textContent='No additional fees. Taxes payable later.'",
    "document.querySelectorAll('td')[5].textContent='No additional fees. Additional charges apply.'",
    "document.querySelectorAll('td')[5].textContent='No additional fees. Service charge: USD 5.00.'",
    "document.querySelectorAll('td')[5].textContent='Registration is non-refundable.'",
    "document.querySelectorAll('td')[2].textContent='XYZ'",
    "document.querySelectorAll('td')[4].textContent='No renewal information available'",
    "document.querySelectorAll('th')[0].textContent='Seller'",
    "document.querySelector('table').insertAdjacentHTML('afterend',document.querySelector('table').outerHTML)",
    "document.querySelectorAll('td')[5].innerHTML='<input value=synthetic-only>'",
    "document.querySelectorAll('td')[5].textContent='synthetic-only'",
    "document.querySelectorAll('td')[5].insertAdjacentHTML('beforeend','<style>td::after {content: \"plus tax\"}</style>')",
])
@pytest.mark.parametrize('reviewed', [False, True])
async def test_unsafe_or_incomplete_candidate_never_publishes(tmp_path, mutation, reviewed):
    async with checkout(tmp_path, reviewed=reviewed) as (controller, s):
        await s.page.locator('dl').evaluate('(e,text)=>e.outerHTML=text', table_summary())
        await s.page.evaluate(mutation)
        await fill(controller, s)
        assert s.status in {'human_action_required', 'rejected'}
        assert s.request is None
        assert 'synthetic-only' not in str(controller.bot.sent)
        assert await s.page.evaluate('window.clicks') == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('layout', ['table', 'rows', 'nested_dl'])
@pytest.mark.parametrize('change', ['replace_value', 'replace_root', 'restore_text', 'duplicate', 'private_value'])
async def test_original_source_and_transaction_checked_in_same_call_as_click(tmp_path, layout, change):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        markup = table_summary() if layout == 'table' else row_summary(layout)
        await s.page.locator('dl').evaluate('(e,text)=>e.outerHTML=text', markup)
        await fill(controller, s)
        assert s.status == 'waiting_for_confirmation'
        guard = s.commit_guard
        # Mutation and attempted commit share one synchronous browser invocation;
        # there is no Python preflight or observer-callback turn to rescue it.
        with pytest.raises(Exception, match='changed|billing'):
            await guard.evaluate('''(g, {change, deadline}) => {
                const root=document.querySelector('table,section');
                const value=root.querySelector('td,dd,span');
                if(change==='replace_value') value.replaceWith(value.cloneNode(true));
                if(change==='replace_root') root.replaceWith(root.cloneNode(true));
                if(change==='restore_text') { const t=value.textContent; value.textContent='different'; value.textContent=t; }
                if(change==='duplicate') root.after(root.cloneNode(true));
                if(change==='private_value') document.querySelector('input').value='synthetic-changed';
                return g.commit({deadline});
            }''', {'change': change, 'deadline': s.request['expiresAt']})
        assert await s.page.evaluate('window.clicks') == 0


@pytest.mark.asyncio
async def test_hidden_duplicate_is_not_a_visible_price_source(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        markup = table_summary() + table_summary().replace('<table>', '<table hidden>').replace('12.34', '0.01')
        await s.page.locator('dl').evaluate('(e,text)=>e.outerHTML=text', markup)
        await fill(controller, s)
        assert s.status == 'waiting_for_confirmation'
        assert s.request['transaction']['summary'] == SUMMARY
        await deliver(controller, s, {'approve': s.request['transaction']['id']})
        assert await s.page.evaluate('window.clicks') == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('layout', ['wrapped_dl', 'list_rows', 'implicit_row_header'])
async def test_additional_native_label_value_structures(tmp_path, layout):
    if layout == 'wrapped_dl':
        pairs = ''.join(f'<div><dt>{label}</dt><dd>{value}</dd></div>' for label, value in zip(LABELS, SUMMARY.values()))
        markup = '<dl aria-label="Order summary">' + pairs + '</dl>'
    elif layout == 'list_rows':
        pairs = ''.join(f'<li><span>{label}</span><strong>{value}</strong></li>' for label, value in zip(LABELS, SUMMARY.values()))
        markup = '<div role="region" aria-label="Purchase summary"><ul>' + pairs + '</ul></div>'
    else:
        markup = table_summary().replace(' scope="row"', '')
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        await s.page.locator('dl').evaluate('(e,text)=>e.outerHTML=text', markup)
        await fill(controller, s)
        assert s.status == 'waiting_for_confirmation'
        assert s.request['transaction']['summary'] == SUMMARY
        await deliver(controller, s, {'approve': s.request['transaction']['id']})
        assert await s.page.evaluate('window.clicks') == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('terms', ['?', 'N/A', 'None', 'Unavailable', 'Not provided'])
@pytest.mark.parametrize('reviewed', [False, True])
async def test_placeholder_terms_are_not_complete_even_with_explicit_final_fees(tmp_path, terms, reviewed):
    markup = row_summary().replace(SUMMARY['terms'], terms)
    async with checkout(tmp_path, reviewed=reviewed) as (controller, s):
        await s.page.locator('dl').evaluate('(e,text)=>e.outerHTML=text', markup)
        await fill(controller, s)
        assert s.status == 'human_action_required'
        assert s.request is None
        assert await s.page.evaluate('window.clicks') == 0


@pytest.mark.asyncio
async def test_native_captioned_table_can_authorize_once(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        await s.page.locator('dl').evaluate('(e,text)=>e.outerHTML=text', table_summary())
        await fill(controller, s)
        assert s.status == 'waiting_for_confirmation'
        assert s.request['transaction']['summary'] == SUMMARY
        await deliver(controller, s, {'approve': s.request['transaction']['id']})
        assert s.status == 'purchase_submitted'
        assert await s.page.evaluate('window.clicks') == 1
