# Order Webhook Processor

A Node.js webhook receiver that checks HMAC-SHA256 against the raw request bytes before JSON parsing. It deduplicates event IDs, queues accepted events, retries processing with exponential backoff, and moves exhausted events to a dead-letter list. State is persisted as a local JSON file for a single-process deployment.

```sh
WEBHOOK_SECRET=development-secret node webhook.js serve
node webhook.js list
node webhook.js replay
node --test
```

Send a POST to `/webhook` with an `X-Signature` header containing the lowercase hex HMAC of the exact body bytes. Accepted events need an `id`, `type`, and `order_id`. `GET /health` returns worker counts. The built-in handler records a processed event; replace `handleEvent()` to integrate an order system. Use a durable shared queue when scaling beyond one process.

