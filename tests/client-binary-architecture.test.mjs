import assert from 'node:assert/strict';
import test from 'node:test';

import {
  inspectClientBinaryArchitecture,
  validateClientBinaryArchitecture,
} from '../scripts/client-binary-architecture.mjs';

const peHeader = machine => {
  const bytes = Buffer.alloc(128);
  bytes.write('MZ', 0, 'ascii');
  bytes.writeUInt32LE(64, 0x3c);
  bytes.write('PE\0\0', 64, 'binary');
  bytes.writeUInt16LE(machine, 68);
  return bytes;
};

const elfHeader = machine => {
  const bytes = Buffer.alloc(64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1], 0);
  bytes.writeUInt16LE(machine, 18);
  return bytes;
};

const universalMachOHeader = () => {
  const bytes = Buffer.alloc(48);
  bytes.writeUInt32BE(0xcafebabe, 0);
  bytes.writeUInt32BE(2, 4);
  bytes.writeUInt32BE(0x01000007, 8);
  bytes.writeUInt32BE(0x0100000c, 28);
  return bytes;
};

const thinMachOHeader = cpu => {
  const bytes = Buffer.alloc(32);
  bytes.writeUInt32LE(0xfeedfacf, 0);
  bytes.writeUInt32LE(cpu, 4);
  return bytes;
};

test('client binary inspection recognizes PE, ELF, and universal Mach-O architectures', () => {
  assert.deepEqual(inspectClientBinaryArchitecture(peHeader(0x8664)), { format: 'pe', architectures: ['x64'] });
  assert.deepEqual(inspectClientBinaryArchitecture(peHeader(0xaa64)), { format: 'pe', architectures: ['arm64'] });
  assert.deepEqual(inspectClientBinaryArchitecture(peHeader(0x014c)), { format: 'pe', architectures: ['ia32'] });
  assert.deepEqual(inspectClientBinaryArchitecture(elfHeader(62)), { format: 'elf', architectures: ['x64'] });
  assert.deepEqual(inspectClientBinaryArchitecture(elfHeader(183)), { format: 'elf', architectures: ['arm64'] });
  assert.deepEqual(inspectClientBinaryArchitecture(elfHeader(40)), { format: 'elf', architectures: ['armv7l'] });
  assert.deepEqual(inspectClientBinaryArchitecture(thinMachOHeader(0x01000007)), {
    format: 'macho',
    architectures: ['x64'],
  });
  assert.deepEqual(inspectClientBinaryArchitecture(thinMachOHeader(0x0100000c)), {
    format: 'macho',
    architectures: ['arm64'],
  });
  assert.deepEqual(inspectClientBinaryArchitecture(universalMachOHeader()), {
    format: 'macho',
    architectures: ['x64', 'arm64'],
  });
});

test('client binary validation rejects mislabeled and incomplete target architectures', () => {
  assert.deepEqual(validateClientBinaryArchitecture(peHeader(0x8664), 'win-x64-nsis'), {
    format: 'pe',
    architectures: ['x64'],
  });
  assert.throws(
    () => validateClientBinaryArchitecture(peHeader(0x8664), 'win-arm64-nsis'),
    /does not match win-arm64-nsis/,
  );
  assert.throws(
    () => validateClientBinaryArchitecture(Buffer.from('not-a-binary'), 'linux-x64-appimage'),
    /Unsupported client executable format/,
  );
  assert.throws(
    () => validateClientBinaryArchitecture(Buffer.from([0xfe, 0xed, 0xfa, 0xcf, 0x01, 0, 0, 7]), 'mac-universal-dmg'),
    /does not match mac-universal-dmg/,
  );
});
