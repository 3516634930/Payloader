import assert from 'node:assert/strict';
import test from 'node:test';

import { createPublicDataResponder } from '../server/public-data-response.mjs';

test('public data responder reuses snapshots by object identity and invalidates on replacement', async () => {
  let data = { payloads: [{ id: 'one' }], tools: [] };
  const responder = createPublicDataResponder({
    loadData: async () => data,
    responseHeaders: {},
  });

  const first = await responder.prepare();
  const second = await responder.prepare();
  assert.equal(second, first);

  data = { payloads: [{ id: 'two' }], tools: [] };
  const replaced = await responder.prepare();
  assert.notEqual(replaced, first);
  assert.notEqual(replaced.etag, first.etag);
});

test('public data responder honors disabled compression encodings', async () => {
  const responder = createPublicDataResponder({
    loadData: async () => ({ payloads: [], tools: [] }),
    responseHeaders: {},
  });
  const written = {};
  const response = {
    writeHead(status, headers) {
      written.status = status;
      written.headers = headers;
    },
    end(body) {
      written.body = body;
    },
  };

  await responder.respond({ headers: { 'accept-encoding': 'br;q=0, gzip;q=0' } }, response);

  assert.equal(written.status, 200);
  assert.equal(written.headers['content-encoding'], undefined);
  assert.equal(Number(written.headers['content-length']), written.body.length);
});
