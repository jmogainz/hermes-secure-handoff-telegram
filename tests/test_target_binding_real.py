"""Real CDP target identity tests; synthetic pages only, no live profile."""
import os

import pytest
from playwright.async_api import async_playwright

from plugin.secure_handoff import SecureHandoffController


class Ctx:
    def get_config(self, key):
        return {"allowed_user_ids": [7], "mini_app_url": "https://mini.example/app",
                "browser_cdp_url": "http://127.0.0.1:9222"}[key]


@pytest.mark.asyncio
async def test_real_cdp_exact_target_disambiguates_and_never_navigates():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(channel=os.environ.get("PLAYWRIGHT_CHANNEL", "chromium"))
        context = await browser.new_context()
        try:
            await context.route("https://fixture.example/**", lambda route: route.fulfill(
                content_type="text/html", body="<main>Synthetic target fixture</main>"))
            first = await context.new_page()
            second = await context.new_page()
            await first.goto("https://fixture.example/first")
            await second.goto("https://fixture.example/second")
            controller = SecureHandoffController(Ctx())
            target = await controller._page_target_id(second)
            assert len(target) == 32
            with pytest.raises(ValueError):
                await controller._existing_page(context, "https://fixture.example")
            assert await controller._existing_page(context, "https://fixture.example", target) is second
            with pytest.raises(ValueError):
                await controller._existing_page(context, "https://other.example", target)
            with pytest.raises(ValueError):
                await controller._existing_page(context, "https://fixture.example", "0" * 32)
            assert first.url == "https://fixture.example/first"
            assert second.url == "https://fixture.example/second"
            await second.close()
            with pytest.raises(ValueError):
                await controller._existing_page(context, "https://fixture.example", target)
            assert not first.is_closed()
        finally:
            await browser.close()
