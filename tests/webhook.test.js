const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { Store, server, verify } = require('../webhook');

test('raw-body HMAC and duplicate HTTP delivery', async () => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'webhooks-'));
  const store = new Store(path.join(folder, 'state.json'));
  const app = server(store, 'secret').listen(0, '127.0.0.1');
  await new Promise(resolve => app.once('listening', resolve));
  try {
    const raw = JSON.stringify({ id: 'evt1', type: 'paid', order_id: 'order1' });
    const signature = crypto.createHmac('sha256', 'secret').update(raw).digest('hex');
    assert.equal(verify(Buffer.from(raw), signature, 'secret'), true);
    const url = `http://127.0.0.1:${app.address().port}/webhook`;
    const options = { method: 'POST', body: raw, headers: { 'X-Signature': signature } };
    assert.equal((await fetch(url, options)).status, 202);
    assert.equal((await fetch(url, options)).status, 200);
    assert.equal((await fetch(url, { ...options, headers: { 'X-Signature': '0'.repeat(64) } })).status, 401);
    assert.equal(store.data.queue.length, 1);
  } finally { app.close(); fs.rmSync(folder, { recursive: true, force: true }); }
});

test('failure retries then dead letter and replay', async () => {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'webhooks-'));
  try {
    const store = new Store(path.join(folder, 'state.json'));
    store.accept({ id: 'e', type: 'paid', order_id: 'o' });
    const base = Date.now() + 100000;
    for (let i = 0; i < 5; i++) await store.work(() => { throw Error('down'); }, base + i * 20000);
    assert.equal(store.data.dead.length, 1);
    store.replay();
    assert.equal(await store.work(() => {}, Date.now() + 100000), 'done');
    assert.equal(new Store(store.file).data.processed[0], 'e');
  } finally { fs.rmSync(folder, { recursive: true, force: true }); }
});

