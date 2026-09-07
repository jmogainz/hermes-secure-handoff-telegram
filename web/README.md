# Telegram Mini App hosting

## Hosting model

You can publish this frontend once and let every operator configure the same
stable HTTPS URL. The frontend is static and has no shared backend, bot token,
account, or database. Each operator's Hermes instance creates a fresh request
key and sends the completed payload back through that operator's Telegram bot.

There are two valid deployment choices:

- **Official shared deployment:** easiest for users. They trust the project-owned
  domain and receive frontend updates from that deployment.
- **Self-hosted deployment:** strongest isolation. Each operator owns the host,
  release files, and update process.

A shared deployment is not a shared Telegram installation. Every operator must
still configure their own bot, gateway, Telegram owner ID, and dedicated Chrome
profile. The host must serve `index.html`, `app.js`, and `styles.css` without
rewriting the request fragment.

The domain owner is a trusted code publisher. The page can read user input before
it encrypts the submission for Hermes, so users should use a self-hosted copy if
they do not want to trust the official shared host.

## Vercel

From the repository root, use a local Vercel login or load only the deployment
credential into the process. Never source the complete Hermes environment:

```bash
VERCEL_TOKEN="$VERCEL_TOKEN" vercel link --yes --project <your-project-name>
VERCEL_TOKEN="$VERCEL_TOKEN" vercel deploy ./web --prod
```

Use the official shared URL `https://hermes-remote-web-login-telegram.vercel.app` in the setup wizard, or pass a self-hosted URL with `--mini-app-url`. The URL must not include a query string or fragment.

## Security boundary

- The frontend has no server routes, API keys, cookies, analytics calls, or
  credential storage. A shared official host is technically supported, but its
  domain owner is trusted to publish the frontend code users execute.
- The Telegram request is carried in the URL fragment and is encrypted again
  before `Telegram.WebApp.sendData()` sends anything back to the bot.
- The static host does not need access to the Hermes machine or Telegram bot
  token.
