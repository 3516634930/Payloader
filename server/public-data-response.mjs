import { createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { brotliCompress, constants, gzip } from 'node:zlib';

const compressBrotli = promisify(brotliCompress);
const compressGzip = promisify(gzip);

const cacheControl = 'public, max-age=0, must-revalidate';

const acceptsEncoding = (header, encoding) => String(header || '')
  .split(',')
  .map(value => value.trim().toLowerCase().split(';').map(part => part.trim()))
  .some(([name, ...parameters]) => {
    if (name !== encoding) return false;
    const quality = parameters.find(parameter => parameter.startsWith('q='));
    return quality ? Number(quality.slice(2)) > 0 : true;
  });

const selectRepresentation = (request, snapshot) => {
  const acceptEncoding = request.headers['accept-encoding'];
  if (acceptsEncoding(acceptEncoding, 'br')) return { body: snapshot.brotli, encoding: 'br' };
  if (acceptsEncoding(acceptEncoding, 'gzip')) return { body: snapshot.gzip, encoding: 'gzip' };
  return { body: snapshot.identity, encoding: '' };
};

const matchesEtag = (request, etag) => String(request.headers['if-none-match'] || '')
  .split(',')
  .map(value => value.trim())
  .includes(etag);

export const createPublicDataResponder = ({ loadData, responseHeaders }) => {
  let cachedData;
  let cachedSnapshotPromise;

  const snapshotFor = data => {
    if (data === cachedData && cachedSnapshotPromise) return cachedSnapshotPromise;
    cachedData = data;
    cachedSnapshotPromise = (async () => {
      const identity = Buffer.from(JSON.stringify(data));
      const etag = `W/"${createHash('sha256').update(identity).digest('hex')}"`;
      const [brotli, gzipBody] = await Promise.all([
        compressBrotli(identity, {
          params: { [constants.BROTLI_PARAM_QUALITY]: 4 },
        }),
        compressGzip(identity, { level: 6 }),
      ]);
      return { identity, brotli, gzip: gzipBody, etag };
    })();
    return cachedSnapshotPromise;
  };

  const respond = async (request, response) => {
    const data = await loadData();
    const snapshot = await snapshotFor(data);
    const headers = {
      ...responseHeaders,
      'content-type': 'application/json; charset=utf-8',
      'cache-control': cacheControl,
      etag: snapshot.etag,
      vary: 'Accept-Encoding',
    };
    if (matchesEtag(request, snapshot.etag)) {
      response.writeHead(304, headers);
      response.end();
      return;
    }

    const representation = selectRepresentation(request, snapshot);
    if (representation.encoding) headers['content-encoding'] = representation.encoding;
    headers['content-length'] = String(representation.body.length);
    response.writeHead(200, headers);
    response.end(representation.body);
  };

  const prepare = async () => snapshotFor(await loadData());

  return Object.freeze({ prepare, respond, snapshotFor });
};
