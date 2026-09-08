"""Purchase lifecycle only: disposable browser and status-only fake transport."""
import asyncio
from types import SimpleNamespace

import pytest
from plugin.secure_handoff import SecureHandoffController
from test_purchase_approval import checkout, fill, deliver, envelope
from test_checkout_flow import update


@pytest.mark.asyncio
@pytest.mark.parametrize('status', ['purchase_submitted', 'outcome_unknown'])
async def test_purchase_status_wakes_exact_owner_without_transaction(status):
    controller = object.__new__(SecureHandoffController)
    controller.adapter = object()
    delivered = []

    async def receive(adapter, text, source):
        delivered.append((adapter, text, source))

    controller._deliver_wake = receive
    await controller._wake_session(status, 7, 8, 42, 'https://example.test')
    assert len(delivered) == 1
    adapter, text, source = delivered[0]
    assert adapter is controller.adapter
    assert vars(source) == {'user_id': '7', 'chat_id': '8', 'thread_id': '42'}
    assert f'Status: {status}.' in text
    assert 'Site: https://example.test.' in text
    assert 'Do not retry' in text
    assert 'not proof of payment or ownership' in text
    await controller._wake_session('untrusted_status', 7, 8, 42, 'https://example.test')
    assert len(delivered) == 1


def assert_scrubbed(s):
    assert s.request is None and s.key is None and s.deadline is None
    assert s.commit_guard is None and s.document is None
    assert s.form is None and s.scope is None and s.auth_container is None
    for name in ('refs', 'ref_meta', 'field_parts', 'field_frames', 'field_origins',
                 'field_documents', 'commit_slots', 'select_options'):
        assert getattr(s, name) == {}
    assert s.form_controls == []
    assert s.form_action == s.submit_action == ''


@pytest.mark.asyncio
@pytest.mark.parametrize('terminal', ['purchase_submitted', 'rejected', 'cancelled', 'expired', 'closed', 'publication_failed', 'outcome_unknown'])
async def test_terminal_purchase_scrubs_all_private_authority(tmp_path, terminal):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        await fill(controller, s)
        raw = envelope(s, {'approve': s.request['transaction']['id']})
        guard = s.commit_guard
        # Independent handle allows checking revocation after Python disposal.
        witness = await guard.evaluate_handle('g => g')
        released = asyncio.Event()
        release_guard = controller._release_guard

        async def release(g):
            try:
                await release_guard(g)
            finally:
                released.set()

        controller._release_guard = release
        if terminal == 'rejected':
            await s.page.evaluate("document.querySelector('#buy').disabled=true")
        elif terminal == 'outcome_unknown':
            class CancelAfterClick:
                async def evaluate(self, expression, arg=None):
                    result = await guard.evaluate(expression, arg)
                    if 'g.commit' in expression:
                        raise asyncio.CancelledError
                    return result

                async def dispose(self):
                    await guard.dispose()

            s.commit_guard = CancelAfterClick()
        if terminal == 'cancelled':
            assert await controller.cancel_from_update(update(raw)) is True
        elif terminal == 'closed':
            await controller._close((7, 8, 42))
        elif terminal == 'expired':
            await controller._deadline_expired(s, s.request['id'])
        elif terminal == 'publication_failed':
            async def fail(*args, **kwargs):
                return False
            controller._send = fail
            await controller._present(s, SimpleNamespace(bot=controller.bot))
        elif terminal == 'outcome_unknown':
            with pytest.raises(asyncio.CancelledError):
                await controller._web_data(update(raw), SimpleNamespace(bot=controller.bot))
        else:
            await deliver(controller, s, raw=raw)
        assert s.status == ('cancelled' if terminal == 'closed' else terminal)
        assert_scrubbed(s)
        await asyncio.wait_for(released.wait(), 2)
        if terminal == 'closed':
            # Owned disposable context is torn down, unlike attached live tabs.
            assert s.page.is_closed()
        else:
            assert await witness.evaluate('g => g.revoked') is True
            await witness.dispose()
            assert await s.page.evaluate('window.clicks') == (1 if terminal in {'purchase_submitted', 'outcome_unknown'} else 0)
        await deliver(controller, s, raw=raw)
        assert (await controller._run('present', {}, (7, 8, 42)))['status'] != 'waiting_for_confirmation'


@pytest.mark.asyncio
async def test_cancelled_summary_read_releases_unpublished_purchase_lease(tmp_path, monkeypatch):
    from plugin import purchase_approval
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        pin = purchase_approval.pin_purchase
        released = asyncio.Event()
        witnesses = []

        async def pin_then_cancel(session):
            guard = await pin(session)
            witnesses.append(await guard.evaluate_handle('g => g'))

            class CancelSummary:
                async def evaluate(self, expression, arg=None):
                    if expression == 'g => g.summary':
                        raise asyncio.CancelledError
                    return await guard.evaluate(expression, arg)

                async def dispose(self):
                    await guard.dispose()
                    released.set()

            return CancelSummary()

        monkeypatch.setattr(purchase_approval, 'pin_purchase', pin_then_cancel)
        raw = envelope(s, {'values': {'f0': 'synthetic-only'}})
        with pytest.raises(asyncio.CancelledError):
            await controller._web_data(update(raw), SimpleNamespace(bot=controller.bot))
        assert_scrubbed(s)
        await asyncio.wait_for(released.wait(), 2)
        assert await witnesses[0].evaluate('g => g.revoked') is True
        await witnesses[0].dispose()
        assert await s.page.evaluate('window.clicks') == 0


@pytest.mark.asyncio
async def test_cancelled_ambiguity_probe_scrubs_without_retry(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        await fill(controller, s)
        raw = envelope(s, {'approve': s.request['transaction']['id']})
        guard = s.commit_guard

        class CancelProbe:
            async def evaluate(self, expression, arg=None):
                if expression == 'g => g.consumed':
                    raise asyncio.CancelledError
                result = await guard.evaluate(expression, arg)
                if 'g.commit' in expression:
                    raise ConnectionError('synthetic acknowledgement loss')
                return result

            async def dispose(self):
                await guard.dispose()

        s.commit_guard = CancelProbe()
        with pytest.raises(asyncio.CancelledError):
            await controller._web_data(update(raw), SimpleNamespace(bot=controller.bot))
        assert s.status == 'outcome_unknown'
        assert_scrubbed(s)
        await deliver(controller, s, raw=raw)
        assert await s.page.evaluate('window.clicks') == 1


@pytest.mark.asyncio
async def test_cancelled_resend_revokes_delivered_approval(tmp_path):
    async with checkout(tmp_path, reviewed=True) as (controller, s):
        await fill(controller, s)
        raw = envelope(s, {'approve': s.request['transaction']['id']})
        original = controller._send

        async def cancel_after_send(*args, **kwargs):
            await original(*args, **kwargs)
            raise asyncio.CancelledError

        controller._send = cancel_after_send
        with pytest.raises(asyncio.CancelledError):
            await controller._present(s, SimpleNamespace(bot=controller.bot))
        assert s.status == 'publication_failed'
        assert_scrubbed(s)
        await deliver(controller, s, raw=raw)
        assert await s.page.evaluate('window.clicks') == 0
