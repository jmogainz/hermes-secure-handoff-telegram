# Telegram Mini App hosting

This directory is a static, secret-free Telegram Mini App. Host it at an HTTPS
origin controlled by the same operator as the Telegram bot; do not reuse a
shared/test deployment for real credentials. The host must serve `index.html`,
`app.js`, and `styles.css` without rewriting the request fragment.

## Vercel

From the repository root, use a local Vercel login or load only the deployment
credential into the process. Never source the complete Hermes environment:

```bash
VERCEL_TOKEN="$VERCEL_TOKEN" vercel link --yes --project <your-project-name>
VERCEL_TOKEN="$VERCEL_TOKEN" vercel deploy ./web --prod
```

Use the resulting HTTPS origin as `mini_app_url` in the plugin setup wizard.
The URL must not include a query string or fragment. A custom domain is fine.

## Security boundary

- There are no server routes, API keys, cookies, analytics calls, or credential
  storage in this frontend.
- The Telegram request is carried in the URL fragment and is encrypted again
  before `Telegram.WebApp.sendData()` sends anything back to the bot.
- The static host does not need access to the Hermes machine or Telegram bot
  token.
