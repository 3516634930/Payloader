declare module 'whirlpool-js' {
  const whirlpool: {
    encSync(value: string): string;
  };

  export default whirlpool;
}

declare module 'sm-crypto' {
  type Sm4Options = {
    mode?: 'cbc' | 'ecb';
    iv?: string;
    inputEncoding?: 'utf8' | 'hex' | 'array';
    outputEncoding?: 'hex' | 'array';
  };

  const smCrypto: {
    sm3(value: string | Uint8Array): string;
    sm4: {
      encrypt(value: string | number[], key: string, options?: Sm4Options): string;
      decrypt(value: string | number[], key: string, options?: Sm4Options): string;
    };
  };

  export default smCrypto;
}

declare module 'xxhashjs' {
  type XXHashResult = {
    toString(radix?: number): string;
  };

  const xxhash: {
    h32(value: string | Uint8Array, seed?: number): XXHashResult;
    h64(value: string | Uint8Array, seed?: number): XXHashResult;
  };

  export const h32: typeof xxhash.h32;
  export const h64: typeof xxhash.h64;
  export default xxhash;
}
