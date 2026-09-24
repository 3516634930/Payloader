import type { Dispatch, SetStateAction } from 'react';
import {
  cryptoJsBlockCipherOperationIds,
  isCryptoJsCipherOperation,
  isNobleAesOperation,
  isNobleNonceOperation,
  isOtpOperation,
  label,
} from '../../utils/codec';
import type { Operation, ParamKey } from '../../utils/codec';
import { parityVariantOptions } from './variantOptions';

interface OperationParamsPanelProps {
  operation: Operation;
  language: 'zh' | 'en';
  showOptions: boolean;
  setShowOptions: Dispatch<SetStateAction<boolean>>;
  params: Record<ParamKey, string>;
  setParams: Dispatch<SetStateAction<Record<ParamKey, string>>>;
  // 归一化后的下拉显示值（rabbit/hexagram/parity 表越界回落），由宿主经 workbenchActions 计算。
  variantValue: string;
  hashAlgorithmValue: string;
}

// 操作摘要 + 参数面板（原 CodecWorkbench 内联整块受控组件化迁出）：状态与回调全部经 props 传入，回调签名不变。
function OperationParamsPanel({ operation, language, showOptions, setShowOptions, params, setParams, variantValue, hashAlgorithmValue }: OperationParamsPanelProps) {
  return (
    <>
      <div className="operation-summary">
        <div>
          <strong>{label(operation.name, language)}</strong>
          <span>{label(operation.summary, language)}</span>
        </div>
        {operation.params?.length ? (
          <button type="button" className="options-toggle" onClick={() => setShowOptions(value => !value)}>
            {showOptions ? (language === 'zh' ? '收起参数' : 'Hide options') : (language === 'zh' ? '展开参数' : 'Show options')}
          </button>
        ) : null}
      </div>

      {operation.params?.length ? (
        <div className={`codec-options ${showOptions ? 'open' : ''}`}>
          {operation.params.includes('variant') && (
            <label>
              <span>{language === 'zh' ? '输出 / 算法变体' : 'Variant'}</span>
              <select value={variantValue} onChange={event => setParams({ ...params, variant: event.target.value })}>
                {(operation.id === 'html-entity' || operation.id === 'xml-entity') && (
                  <>
                    <option value="special">{language === 'zh' ? '命名实体' : 'Named entities'}</option>
                    <option value="decimal">{language === 'zh' ? '十进制实体' : 'Decimal entities'}</option>
                    <option value="hex">{language === 'zh' ? '十六进制实体' : 'Hex entities'}</option>
                  </>
                )}
                {operation.id === 'unicode-escape' && (
                  <>
                    <option value="special">{language === 'zh' ? '\\uXXXX' : '\\uXXXX'}</option>
                    <option value="hex">{language === 'zh' ? '\\xHH' : '\\xHH'}</option>
                    <option value="brace">{language === 'zh' ? '\\u{...} 格式' : '\\u{...} format'}</option>
                  </>
                )}
                {operation.id === 'base32' && (
                  <>
                    <option value="special">RFC 4648 Base32</option>
                    <option value="hex">Base32hex</option>
                    <option value="decimal">Crockford Base32</option>
                  </>
                )}
                {parityVariantOptions[operation.id]?.map(option => (
                  <option key={option.value} value={option.value}>{language === 'zh' ? option.zh : option.en}</option>
                ))}
                {operation.id === 'bech32' && (
                  <>
                    <option value="special">Bech32</option>
                    <option value="hex">Bech32m</option>
                  </>
                )}
                {operation.id === 'bacon' && (
                  <>
                    <option value="special">{language === 'zh' ? '24 字母（I/J、U/V 合并）' : '24-letter (I/J, U/V merged)'}</option>
                    <option value="decimal">{language === 'zh' ? '26 字母全表' : 'Full 26-letter'}</option>
                  </>
                )}
                {operation.id === 'hexagram' && (
                  <>
                    <option value="names">{language === 'zh' ? '卦名（坤剥比观…）' : 'Names (坤剥比观…)'}</option>
                    <option value="symbols">{language === 'zh' ? '卦符（䷀-䷿）' : 'Symbols (䷀-䷿)'}</option>
                  </>
                )}
                {operation.id === 'otpauth-uri' && (
                  <>
                    <option value="special">TOTP</option>
                    <option value="hex">HOTP</option>
                  </>
                )}
                {isCryptoJsCipherOperation(operation.id) && (
                  <>
                    <option value="special">{operation.id === 'rabbit' ? 'Raw key + IV' : 'CBC raw key + IV'}</option>
                    {cryptoJsBlockCipherOperationIds.has(operation.id) && <option value="hex">ECB raw key</option>}
                    <option value="decimal">OpenSSL Salted__ passphrase</option>
                  </>
                )}
                {(operation.id === 'aes-ecb' || operation.id === 'aes-cbc-raw') && (
                  <>
                    <option value="special">PKCS#7 padding</option>
                    <option value="hex">No padding exact block</option>
                  </>
                )}
                {operation.id === 'sm4' && (
                  <>
                    <option value="special">CBC raw key + IV</option>
                    <option value="hex">ECB raw key</option>
                  </>
                )}
                {operation.id === 'ascii85' && (
                  <>
                    <option value="special">ASCII85 / Adobe</option>
                    <option value="hex">Z85</option>
                  </>
                )}
                {operation.id === 'hex' && (
                  <>
                    <option value="special">{language === 'zh' ? '纯 Hex' : 'Plain hex'}</option>
                    <option value="decimal">{language === 'zh' ? '0x 前缀' : '0x prefix'}</option>
                    <option value="hex">{language === 'zh' ? '\\x 前缀' : '\\x prefix'}</option>
                  </>
                )}
                {operation.id === 'rot' && (
                  <>
                    <option value="special">ROT13 / Caesar</option>
                    <option value="hex">ROT47</option>
                  </>
                )}
                {operation.id === 'utf16-bytes' && (
                  <>
                    <option value="special">UTF-16 LE</option>
                    <option value="hex">UTF-16 BE</option>
                  </>
                )}
                {operation.id === 'dna-code' && (
                  <>
                    <option value="special">00=A 01=C 10=G 11=T</option>
                    <option value="decimal">00=A 01=G 10=C 11=T</option>
                    <option value="hex">00=C 01=A 10=T 11=G</option>
                  </>
                )}
                {operation.id === 'keyboard-shift' && (
                  <>
                    <option value="special">{language === 'zh' ? '向右还原' : 'Shift right'}</option>
                    <option value="hex">{language === 'zh' ? '向左还原' : 'Shift left'}</option>
                  </>
                )}
                {operation.id === 'albam' && (
                  <>
                    <option value="special">{language === 'zh' ? 'A↔N 半表互换（+13 对合）' : 'A↔N half-table swap (+13)'}</option>
                    <option value="shift11">CacheSleuth +11</option>
                  </>
                )}
              </select>
            </label>
          )}
          {operation.params.includes('hashAlgorithm') && (
            <label>
              <span>{language === 'zh' ? '摘要算法' : 'Digest algorithm'}</span>
              <select value={hashAlgorithmValue} onChange={event => setParams({ ...params, hashAlgorithm: event.target.value })}>
                {isOtpOperation(operation.id) ? (
                  <>
                    <option value="sha1">SHA-1</option>
                    <option value="sha256">SHA-256</option>
                    <option value="sha512">SHA-512</option>
                  </>
                ) : operation.id === 'jwt-hmac' ? (
                  <>
                    <option value="sha256">SHA-256 / HS256</option>
                    <option value="sha384">SHA-384 / HS384</option>
                    <option value="sha512">SHA-512 / HS512</option>
                  </>
                ) : (
                  <>
                    {operation.id !== 'hmac' && <option value="md5">MD5</option>}
                    <option value="sha1">SHA-1</option>
                    <option value="sha256">SHA-256</option>
                    <option value="sha384">SHA-384</option>
                    <option value="sha512">SHA-512</option>
                    {operation.id !== 'hmac' && <option value="sha3-224">SHA3-224</option>}
                    {operation.id !== 'hmac' && <option value="sha3-256">SHA3-256</option>}
                    {operation.id !== 'hmac' && <option value="sha3-384">SHA3-384</option>}
                    {operation.id !== 'hmac' && <option value="sha3-512">SHA3-512</option>}
                    {operation.id !== 'hmac' && <option value="keccak-256">Keccak-256</option>}
                    {operation.id !== 'hmac' && <option value="keccak-512">Keccak-512</option>}
                    {operation.id !== 'hmac' && <option value="md4">MD4</option>}
                    {operation.id !== 'hmac' && <option value="ntlm">NTLM</option>}
                    {operation.id !== 'hmac' && <option value="ripemd160">RIPEMD-160</option>}
                    {operation.id !== 'hmac' && <option value="blake2b-256">BLAKE2b-256</option>}
                    {operation.id !== 'hmac' && <option value="blake2b-512">BLAKE2b-512</option>}
                    {operation.id !== 'hmac' && <option value="blake2s-256">BLAKE2s-256</option>}
                    {operation.id !== 'hmac' && <option value="blake3">BLAKE3</option>}
                    {operation.id !== 'hmac' && <option value="sm3">SM3</option>}
                    {operation.id !== 'hmac' && <option value="whirlpool">Whirlpool</option>}
                    {operation.id !== 'hmac' && <option value="xxhash32">xxHash32</option>}
                    {operation.id !== 'hmac' && <option value="xxhash64">xxHash64</option>}
                    {operation.id !== 'hmac' && <option value="crc16">CRC16</option>}
                    {operation.id !== 'hmac' && <option value="crc32">CRC32</option>}
                    {operation.id !== 'hmac' && <option value="adler32">Adler32</option>}
                  </>
                )}
              </select>
            </label>
          )}
          {operation.params.includes('secret') && (
            <label className={operation.id === 'jwt-public' ? 'wide-option' : undefined}>
              <span>{operation.id === 'brainfuck'
                ? (language === 'zh' ? 'Brainfuck 输入' : 'Brainfuck stdin')
                : operation.id === 'lcg-helper'
                  ? (language === 'zh' ? '可选 modulus' : 'Optional modulus')
                  : operation.id === 'hash-length-extension-helper'
                    ? (language === 'zh' ? '追加数据' : 'Append data')
                  : isCryptoJsCipherOperation(operation.id)
                    ? (variantValue === 'decimal' ? 'Passphrase' : 'Key')
                  : operation.id === 'openssl-aes-256-cbc'
                    ? 'OpenSSL passphrase'
                  : isNobleNonceOperation(operation.id) || isNobleAesOperation(operation.id) || operation.id === 'sm4'
                    ? 'Key'
                  : isOtpOperation(operation.id)
                    ? 'Base32 secret'
                  : operation.id === 'enigma'
                    ? 'Enigma settings'
                  : operation.id === 'jwt-hmac'
                    ? 'JWT HMAC secret'
                  : operation.id === 'jwt-public'
                    ? 'Public key material'
                  : operation.id === 'fernet'
                    ? 'Fernet key'
                  : (language === 'zh' ? '密钥 / 口令' : 'Secret / password')}</span>
              {operation.id === 'jwt-public' ? (
                <textarea
                  value={params.secret}
                  onChange={event => setParams({ ...params, secret: event.target.value })}
                  rows={6}
                  spellCheck={false}
                  placeholder={'-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n\nor paste JWK / JWKS JSON'}
                />
              ) : (
                <input value={params.secret} onChange={event => setParams({ ...params, secret: event.target.value })} placeholder={operation.id === 'lcg-helper' ? 'm=2^31 / m=2147483648' : operation.id === 'hash-length-extension-helper' ? 'admin=true' : isCryptoJsCipherOperation(operation.id) ? (params.variant === 'decimal' ? 'OpenSSL passphrase' : 'hex key or UTF-8 key') : operation.id === 'openssl-aes-256-cbc' ? 'OpenSSL passphrase' : isNobleNonceOperation(operation.id) || isNobleAesOperation(operation.id) || operation.id === 'sm4' ? 'hex key or UTF-8 key' : isOtpOperation(operation.id) ? 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' : operation.id === 'enigma' ? 'rotors=I II III; reflector=B; rings=AAA; positions=AAA; plugboard=AV BS' : operation.id === 'jwt-hmac' ? 'secret' : operation.id === 'fernet' ? 'URL-safe Base64 32-byte key' : (language === 'zh' ? '仅在本地浏览器使用' : 'Used locally in this browser')} />
              )}
            </label>
          )}
          {operation.params.includes('iv') && (!operation.params.includes('variant') || operation.id === 'aes-cbc-raw' || (variantValue !== 'hex' && variantValue !== 'decimal')) && (
            <label>
              <span>{isNobleNonceOperation(operation.id) ? 'Nonce' : operation.id === 'rabbit' ? 'IV / nonce' : 'IV'}</span>
              <input value={params.iv} onChange={event => setParams({ ...params, iv: event.target.value })} placeholder={isNobleNonceOperation(operation.id) ? 'hex nonce or UTF-8 nonce' : operation.id === 'rabbit' ? 'optional hex or UTF-8 IV' : 'hex IV or UTF-8 IV'} />
            </label>
          )}
          {operation.params.includes('hrp') && (
            <label>
              <span>{language === 'zh' ? 'HRP 前缀' : 'HRP prefix'}</span>
              <input value={params.hrp} onChange={event => setParams({ ...params, hrp: event.target.value })} placeholder="bc / tb / lnbc" />
            </label>
          )}
          {operation.params.includes('versionHex') && (
            <label>
              <span>{language === 'zh' ? '版本字节 Hex' : 'Version bytes hex'}</span>
              <input value={params.versionHex} onChange={event => setParams({ ...params, versionHex: event.target.value })} placeholder="00 / 05 / 80" />
            </label>
          )}
          {operation.params.includes('digits') && (
            <label>
              <span>{language === 'zh' ? 'OTP 位数' : 'OTP digits'}</span>
              <input type="number" min="4" max="10" step="1" value={params.digits} onChange={event => setParams({ ...params, digits: event.target.value })} />
            </label>
          )}
          {operation.params.includes('counter') && (operation.id !== 'otpauth-uri' || params.variant === 'hex') && (
            <label>
              <span>{language === 'zh' ? 'HOTP counter' : 'HOTP counter'}</span>
              <input type="number" min="0" step="1" value={params.counter} onChange={event => setParams({ ...params, counter: event.target.value })} />
            </label>
          )}
          {operation.params.includes('timeStep') && (operation.id !== 'otpauth-uri' || params.variant !== 'hex') && (
            <label>
              <span>{language === 'zh' ? 'TOTP 步长秒数' : 'TOTP time step'}</span>
              <input type="number" min="1" step="1" value={params.timeStep} onChange={event => setParams({ ...params, timeStep: event.target.value })} />
            </label>
          )}
          {operation.params.includes('otpTimestamp') && (
            <label>
              <span>{language === 'zh' ? 'Unix 秒级时间' : 'Unix timestamp seconds'}</span>
              <input inputMode="numeric" value={params.otpTimestamp} onChange={event => setParams({ ...params, otpTimestamp: event.target.value })} placeholder={language === 'zh' ? '留空表示当前时间' : 'Empty = current time'} />
            </label>
          )}
          {operation.params.includes('keyword2') && (
            <label>
              <span>{language === 'zh' ? '第二关键词' : 'Second keyword'}</span>
              <input value={params.keyword2} onChange={event => setParams({ ...params, keyword2: event.target.value })} placeholder="CIPHER / SECONDKEY" />
            </label>
          )}
          {operation.params.includes('associatedData') && (
            <label>
              <span>{language === 'zh' ? 'AAD 关联数据' : 'AAD / associated data'}</span>
              <input value={params.associatedData} onChange={event => setParams({ ...params, associatedData: event.target.value })} placeholder="optional UTF-8 or hex AAD" />
            </label>
          )}
          {operation.params.includes('period') && (
            <label>
              <span>{language === 'zh' ? '周期' : 'Period'}</span>
              <input type="number" min="1" max="64" value={params.period} onChange={event => setParams({ ...params, period: event.target.value })} />
            </label>
          )}
          {operation.params.includes('iterations') && (
            <label>
              <span>{operation.id === 'brainfuck' ? (language === 'zh' ? '最大步数' : 'Max steps') : (language === 'zh' ? 'PBKDF2 迭代次数' : 'PBKDF2 iterations')}</span>
              <input type="number" min="10000" step="1000" value={params.iterations} onChange={event => setParams({ ...params, iterations: event.target.value })} />
            </label>
          )}
          {operation.params.includes('dropBytes') && (
            <label>
              <span>{language === 'zh' ? '丢弃字节' : 'Drop bytes'}</span>
              <input type="number" min="0" max="4096" step="1" value={params.dropBytes} onChange={event => setParams({ ...params, dropBytes: event.target.value })} />
            </label>
          )}
          {operation.params.includes('shift') && (
            <label>
              <span>{language === 'zh' ? 'Caesar 位移' : 'Caesar shift'}</span>
              <input type="number" value={params.shift} onChange={event => setParams({ ...params, shift: event.target.value })} />
            </label>
          )}
          {operation.params.includes('separator') && (
            <label>
              <span>{language === 'zh' ? '分隔符' : 'Separator'}</span>
              <select value={params.separator} onChange={event => setParams({ ...params, separator: event.target.value })}>
                <option value="space">{language === 'zh' ? '空格' : 'Space'}</option>
                <option value="comma">{language === 'zh' ? '逗号' : 'Comma'}</option>
                <option value="newline">{language === 'zh' ? '换行' : 'New line'}</option>
              </select>
            </label>
          )}
          {operation.params.includes('affineA') && (
            <label>
              <span>{language === 'zh' ? 'Affine a' : 'Affine a'}</span>
              <input type="number" value={params.affineA} onChange={event => setParams({ ...params, affineA: event.target.value })} />
            </label>
          )}
          {operation.params.includes('affineB') && (
            <label>
              <span>{language === 'zh' ? 'Affine b' : 'Affine b'}</span>
              <input type="number" value={params.affineB} onChange={event => setParams({ ...params, affineB: event.target.value })} />
            </label>
          )}
          {operation.params.includes('rails') && (
            <label>
              <span>{language === 'zh' ? '轨道数' : 'Rails'}</span>
              <input type="number" min="2" max="32" value={params.rails} onChange={event => setParams({ ...params, rails: event.target.value })} />
            </label>
          )}
          {operation.params.includes('knownPlaintext') && (
            <label>
              <span>{language === 'zh' ? '已知明文' : 'Known plaintext'}</span>
              <input value={params.knownPlaintext} onChange={event => setParams({ ...params, knownPlaintext: event.target.value })} placeholder="flag{ / PNG header / PK" />
            </label>
          )}
          {operation.params.includes('mimeType') && (
            <label>
              <span>MIME</span>
              <input value={params.mimeType} onChange={event => setParams({ ...params, mimeType: event.target.value })} />
            </label>
          )}
          {operation.params.includes('blockLabel') && (
            <label>
              <span>{language === 'zh' ? 'PEM 块类型' : 'PEM block label'}</span>
              <input value={params.blockLabel} onChange={event => setParams({ ...params, blockLabel: event.target.value })} placeholder="PUBLIC KEY / CERTIFICATE / PRIVATE KEY" />
            </label>
          )}
        </div>
      ) : null}
    </>
  );
}

export { OperationParamsPanel };
