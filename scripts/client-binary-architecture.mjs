import { open } from 'node:fs/promises';

const targetArchitectures = Object.freeze({
  'win-x64-nsis': Object.freeze({ format: 'pe', architectures: ['x64'] }),
  'win-arm64-nsis': Object.freeze({ format: 'pe', architectures: ['arm64'] }),
  'win-ia32-nsis': Object.freeze({ format: 'pe', architectures: ['ia32'] }),
  'linux-x64-appimage': Object.freeze({ format: 'elf', architectures: ['x64'] }),
  'linux-arm64-appimage': Object.freeze({ format: 'elf', architectures: ['arm64'] }),
  'linux-armv7l-appimage': Object.freeze({ format: 'elf', architectures: ['armv7l'] }),
  'mac-x64-dmg': Object.freeze({ format: 'macho', architectures: ['x64'] }),
  'mac-arm64-dmg': Object.freeze({ format: 'macho', architectures: ['arm64'] }),
  'mac-universal-dmg': Object.freeze({ format: 'macho', architectures: ['x64', 'arm64'] }),
});

const peArchitectures = new Map([
  [0x014c, 'ia32'],
  [0x8664, 'x64'],
  [0xaa64, 'arm64'],
]);
const elfArchitectures = new Map([
  [40, 'armv7l'],
  [62, 'x64'],
  [183, 'arm64'],
]);
const machArchitectures = new Map([
  [0x01000007, 'x64'],
  [0x0100000c, 'arm64'],
]);

const requireBytes = (buffer, count, label) => {
  if (!Buffer.isBuffer(buffer) || buffer.length < count) throw new Error(`Invalid ${label} executable header.`);
};

const architectureResult = (format, architectures, label) => {
  const normalized = [...new Set(architectures)];
  if (!normalized.length || normalized.some(value => !value)) {
    throw new Error(`Unsupported ${label} executable architecture.`);
  }
  return { format, architectures: normalized };
};

const inspectPe = buffer => {
  requireBytes(buffer, 64, 'PE');
  const headerOffset = buffer.readUInt32LE(0x3c);
  requireBytes(buffer, headerOffset + 6, 'PE');
  if (buffer.toString('binary', headerOffset, headerOffset + 4) !== 'PE\0\0') {
    throw new Error('Invalid PE executable header.');
  }
  return architectureResult('pe', [peArchitectures.get(buffer.readUInt16LE(headerOffset + 4))], 'PE');
};

const inspectElf = buffer => {
  requireBytes(buffer, 20, 'ELF');
  const endian = buffer[5];
  if (endian !== 1 && endian !== 2) throw new Error('Invalid ELF executable header.');
  const machine = endian === 1 ? buffer.readUInt16LE(18) : buffer.readUInt16BE(18);
  return architectureResult('elf', [elfArchitectures.get(machine)], 'ELF');
};

const readMachCpu = (buffer, offset, littleEndian) => (
  littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset)
);

const inspectMachO = (buffer, magic) => {
  const thin = new Map([
    [0xfeedface, false],
    [0xfeedfacf, false],
    [0xcefaedfe, true],
    [0xcffaedfe, true],
  ]);
  if (thin.has(magic)) {
    requireBytes(buffer, 8, 'Mach-O');
    return architectureResult('macho', [machArchitectures.get(readMachCpu(buffer, 4, thin.get(magic)))], 'Mach-O');
  }

  const fat = new Map([
    [0xcafebabe, { littleEndian: false, entrySize: 20 }],
    [0xbebafeca, { littleEndian: true, entrySize: 20 }],
    [0xcafebabf, { littleEndian: false, entrySize: 32 }],
    [0xbfbafeca, { littleEndian: true, entrySize: 32 }],
  ]);
  const format = fat.get(magic);
  if (!format) return null;
  requireBytes(buffer, 8, 'Mach-O');
  const count = readMachCpu(buffer, 4, format.littleEndian);
  if (!Number.isSafeInteger(count) || count < 1 || count > 16) throw new Error('Invalid Mach-O architecture table.');
  requireBytes(buffer, 8 + count * format.entrySize, 'Mach-O');
  const architectures = [];
  for (let index = 0; index < count; index += 1) {
    const cpu = readMachCpu(buffer, 8 + index * format.entrySize, format.littleEndian);
    architectures.push(machArchitectures.get(cpu));
  }
  return architectureResult('macho', architectures, 'Mach-O');
};

export const inspectClientBinaryArchitecture = buffer => {
  requireBytes(buffer, 4, 'client');
  if (buffer[0] === 0x4d && buffer[1] === 0x5a) return inspectPe(buffer);
  if (buffer[0] === 0x7f && buffer.toString('ascii', 1, 4) === 'ELF') return inspectElf(buffer);
  const mach = inspectMachO(buffer, buffer.readUInt32BE(0));
  if (mach) return mach;
  throw new Error('Unsupported client executable format.');
};

export const validateClientBinaryArchitecture = (buffer, targetId) => {
  const expected = targetArchitectures[targetId];
  if (!expected) throw new Error(`Unknown client binary target: ${targetId}`);
  const actual = inspectClientBinaryArchitecture(buffer);
  const matches = actual.format === expected.format
    && expected.architectures.every(architecture => actual.architectures.includes(architecture))
    && actual.architectures.every(architecture => expected.architectures.includes(architecture));
  if (!matches) {
    throw new Error(
      `Client executable architecture ${actual.format}/${actual.architectures.join('+')} does not match ${targetId}.`,
    );
  }
  return actual;
};

export const verifyClientExecutableArchitecture = async (filePath, targetId) => {
  const handle = await open(filePath, 'r');
  try {
    const header = Buffer.alloc(4096);
    const { bytesRead } = await handle.read(header, 0, header.length, 0);
    return validateClientBinaryArchitecture(header.subarray(0, bytesRead), targetId);
  } finally {
    await handle.close();
  }
};
