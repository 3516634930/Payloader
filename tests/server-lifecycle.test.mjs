import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import test from 'node:test';

import { closeHttpServer, createShutdownController } from '../server/server-lifecycle.mjs';

test('closeHttpServer stops an active server and is idempotent', async () => {
  const server = createServer((_request, response) => response.end('ok'));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  await closeHttpServer(server, { timeoutMs: 1_000 });
  await closeHttpServer(server, { timeoutMs: 1_000 });

  assert.equal(server.listening, false);
});

test('shutdown controller closes the server and resources once', async () => {
  const server = createServer((_request, response) => response.end('ok'));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  let resourceCloses = 0;
  const controller = createShutdownController({
    server,
    closeResources: async () => { resourceCloses += 1; },
    timeoutMs: 1_000,
  });

  await Promise.all([controller.shutdown('test'), controller.shutdown('test-again')]);

  assert.equal(server.listening, false);
  assert.equal(resourceCloses, 1);
});
