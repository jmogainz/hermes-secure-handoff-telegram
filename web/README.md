# Telegram Mini App

The static client supports two bounded protocols:

- v1 encrypted connection diagnostic;
- v4 transport-only encrypted entry and one-shot action approval.

The page starts without credential controls. After validating the fragment request it creates only the agent-composed fields, encrypts the submission in-browser, calls `Telegram.WebApp.sendData`, clears local plaintext, and waits for the plugin acknowledgement/wakeup path.

It contains no provider, authentication-stage, checkout, purchase, route, or webpage-success logic. It makes no network calls beyond loading the official Telegram Web App SDK and uses no cookies or browser storage.

Deploy the `web/` directory as a static site with the headers in `vercel.json`.
