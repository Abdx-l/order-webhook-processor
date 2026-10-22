const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');

function verify(raw, signature, secret) {
  if (!signature || !secret || !/^[a-f0-9]{64}$/.test(signature)) return false;
  const expected = crypto.createHmac('sha256', secret).update(raw).digest();
  return crypto.timingSafeEqual(expected, Buffer.from(signature, 'hex'));
}

class Store {
  constructor(file) {
    this.file = file;
    this.data = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : { seen: {}, queue: [], dead: [], processed: [] };
  }
  save() {
    const temp = this.file + '.tmp';
    fs.writeFileSync(temp, JSON.stringify(this.data, null, 2));
    fs.renameSync(temp, this.file);
  }
  accept(event) {
    if (!event || typeof event.id !== 'string' || !event.id || !event.type || !event.order_id) throw new Error('id, type and order_id required');
    if (this.data.seen[event.id]) return false;
    this.data.seen[event.id] = true;
    this.data.queue.push({ event, attempts: 0, available: Date.now() });
    this.save();
    return true;
  }
  async work(handler = handleEvent, now = Date.now()) {
    const index = this.data.queue.findIndex(job => job.available <= now);
    if (index < 0) return null;
    const job = this.data.queue.splice(index, 1)[0];
    try {
      await handler(job.event);
      this.data.processed.push(job.event.id);
      this.save();
      return 'done';
    } catch (error) {
      job.attempts += 1;
      job.error = String(error);
      if (job.attempts >= 5) this.data.dead.push(job);
      else { job.available = now + 1000 * 2 ** (job.attempts - 1); this.data.queue.push(job); }
      this.save();
      return job.attempts >= 5 ? 'dead' : 'retry';
    }
  }
  replay() {
    for (const job of this.data.dead.splice(0)) { job.attempts = 0; job.available = Date.now(); this.data.queue.push(job); }
    this.save();
  }
}

async function handleEvent(event) { return event.id; }

function server(store, secret) {
  return http.createServer((request, response) => {
    if (request.method === 'GET' && request.url === '/health') {
      response.setHeader('content-type', 'application/json');
      return response.end(JSON.stringify({ queued: store.data.queue.length, dead: store.data.dead.length, processed: store.data.processed.length }));
    }
    if (request.method !== 'POST' || request.url !== '/webhook') { response.writeHead(404); return response.end(); }
    const chunks = [];
    let size = 0;
    request.on('data', chunk => { size += chunk.length; if (size > 1024 * 1024) request.destroy(); else chunks.push(chunk); });
    request.on('end', () => {
      const raw = Buffer.concat(chunks);
      if (!verify(raw, request.headers['x-signature'], secret)) { response.writeHead(401); return response.end('invalid signature'); }
      try {
        const accepted = store.accept(JSON.parse(raw.toString('utf8')));
        response.writeHead(accepted ? 202 : 200);
        response.end(accepted ? 'queued' : 'duplicate');
      } catch (error) { response.writeHead(400); response.end(String(error)); }
    });
  });
}

if (require.main === module) {
  const store = new Store(process.env.WEBHOOK_DB || 'webhooks.json');
  const command = process.argv[2];
  if (command === 'serve') {
    if (!process.env.WEBHOOK_SECRET) throw new Error('WEBHOOK_SECRET is required');
    server(store, process.env.WEBHOOK_SECRET).listen(Number(process.env.PORT || 8080), '127.0.0.1');
    setInterval(() => store.work().catch(console.error), 250);
  } else if (command === 'replay') store.replay();
  else if (command === 'list') console.log(JSON.stringify(store.data, null, 2));
  else throw new Error('Choose serve, list or replay');
}

module.exports = { verify, Store, server };

