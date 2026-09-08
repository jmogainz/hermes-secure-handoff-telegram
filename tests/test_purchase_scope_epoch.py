"""Private action guard regressions; reviewed synthetic source, no live browser."""
import pytest
from test_purchase_approval import checkout, fill, deliver


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['insert_row', 'restore_row', 'input_restore', 'change_restore'])
async def test_scope_or_field_epoch_blocks_same_turn_commit(tmp_path, change):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        await fill(controller, s)
        assert s.status == 'waiting_for_confirmation'
        assert s.request is not None and s.commit_guard is not None
        # Mutation and final click are attempted in the SAME JS invocation.
        # Final-state equality cannot detect value A -> B -> A or inserted rows.
        with pytest.raises(Exception, match='epoch changed'):
            await s.commit_guard.evaluate('''(g, {change, deadline}) => {
                const scope=document.querySelector('form');
                if(change==='insert_row' || change==='restore_row') {
                    const row=document.createElement('p');
                    row.textContent='Additional synthetic obligation';
                    scope.append(row);
                    if(change==='restore_row') row.remove();
                } else {
                    const field=scope.querySelector('input'), old=field.value;
                    field.value='synthetic alternative';
                    field.dispatchEvent(new Event(change==='input_restore' ? 'input':'change', {bubbles:true}));
                    field.value=old;
                }
                return g.commit({deadline});
            }''', {'change':change, 'deadline':s.request['expiresAt']})
        assert await s.page.evaluate('window.clicks') == 0


@pytest.mark.asyncio
async def test_unrelated_animation_outside_review_scope_does_not_revoke(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        await fill(controller, s)
        assert s.status == 'waiting_for_confirmation'
        await s.page.evaluate('''() => {
            const banner=document.createElement('aside');
            document.body.append(banner); banner.textContent='Synthetic animation';
            banner.textContent='Another frame';
        }''')
        assert s.request is not None
        await deliver(controller, s, {'approve':s.request['transaction']['id']})
        assert s.status == 'purchase_submitted'
        assert await s.page.evaluate('window.clicks') == 1
