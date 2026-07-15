const { createDecipheriv, createHash, timingSafeEqual } = require('node:crypto');

const encryptedTarget = 'PoexbFmTpqzLjv3OZNvRhN6MPzoLC0z2HeK1HGuIevo+SL8XdROL';
const initializationVector = 'siqZIpSvbVbduMpo';
const authenticationTag = 'TGbBhX8/4ANPeKcQRzN4ag==';
const derivationSalt = 'XbIwN1jVd9C52lvnffmd0Wtk8+kWRSOw';
const expectedDigest = '81ea9805f81db752f393d34fb1e82de2cd1c864efe6295f575ec87357ed7db0a';
const authenticatedContext = Buffer.from('Payloader:project-attribution:v1', 'utf8');
const storedShardOrder = Object.freeze([2, 0, 3, 1]);
const keyShards = Object.freeze([
  Object.freeze([60, 46, 86, 18, 80, 49, 253, 203, 211, 207, 108, 24]),
  Object.freeze([243, 126, 45, 209, 202, 163, 11, 140, 5, 92, 35, 159]),
  Object.freeze([243, 126, 89, 175, 24, 104, 131, 238, 80, 207, 175, 198]),
  Object.freeze([47, 212, 94, 29, 30, 86, 170, 173, 23, 40, 251, 28]),
]);

const integrityError = () => new Error('Payloader project attribution integrity check failed.');
const shardMask = (shardIndex, byteIndex) => (0x5a + shardIndex * 29 + byteIndex * 17) & 0xff;

const deriveKey = () => {
  const restoredShards = new Array(keyShards.length);
  for (let storedIndex = 0; storedIndex < keyShards.length; storedIndex += 1) {
    const shardIndex = storedShardOrder[storedIndex];
    const stored = keyShards[storedIndex];
    restoredShards[shardIndex] = Buffer.from(
      [...stored].reverse().map((value, byteIndex) => value ^ shardMask(shardIndex, byteIndex)),
    );
  }
  return createHash('sha256')
    .update(Buffer.concat(restoredShards))
    .update(Buffer.from(derivationSalt, 'base64'))
    .digest();
};

const resolveProjectAttribution = () => {
  try {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      deriveKey(),
      Buffer.from(initializationVector, 'base64'),
    );
    decipher.setAAD(authenticatedContext);
    decipher.setAuthTag(Buffer.from(authenticationTag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(encryptedTarget, 'base64')),
      decipher.final(),
    ]).toString('utf8');
    const actualDigest = createHash('sha256').update(plaintext).digest();
    const requiredDigest = Buffer.from(expectedDigest, 'hex');
    if (actualDigest.length !== requiredDigest.length || !timingSafeEqual(actualDigest, requiredDigest)) {
      throw integrityError();
    }
    const parsed = new URL(plaintext);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw integrityError();
    }
    return plaintext;
  } catch (error) {
    if (error instanceof Error && error.message === integrityError().message) throw error;
    throw integrityError();
  }
};

const officialProjectUrl = resolveProjectAttribution();
const publicProjectRoute = '/api/r/p';
const clientProjectRoute = 'payloader://project';

module.exports = Object.freeze({
  clientProjectRoute,
  officialProjectUrl,
  publicProjectRoute,
  resolveProjectAttribution,
});
