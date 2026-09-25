// RAR 爆破测试向量（tests/helpers/rar-test-vectors.mjs）：
// —— 真实工具产物向量：libarchive 测试集两个加密 RAR3 归档（BSD-2-Clause 许可，uuencode
//    原文以 JSON 行数组离线内嵌——由脚本从原始 .uu 文件机械生成，杜绝手抄笔误），测试侧
//    自带 uudecode 解码，不依赖系统工具/网络：
//    1) test_read_format_rar_encryption_data.rar（WinRAR 产物，185 字节）：foo.txt/bar.txt
//       均以口令 "12345678" 加密——口令出处 libarchive/test/test_read_format_rar_encryption_data.c
//       注释 Password is "12345678"；探测实测：两文件头 method=0x33/UNP_VER=29/pack=32/
//       unp=16/共享 salt 4f03bcd9d6164cdf，FILE_CRC foo=0xa6ad865c / bar=0xcd90e2be。
//    2) test_read_format_rar4_encrypted.rar（311 字节）：a.txt/c.txt 明文存储，b.txt 口令
//       "password"、d.txt 口令 "password2"——口令出处 libarchive/test/test_read_format_rar_encryption.c
//       头部注释；b.txt 探测实测：method=0x33/UNP_VER=29/pack=32/unp=18/salt be021b9a792a8a55。
// —— uudecode：经典 uu 格式（begin MODE NAME 头行；行首长度字节 = 数据字节数 + 32，
//    解码按 (c-32)&63；每 4 字符 6bit×4 → 3 字节，行尾冗余位丢弃；` 空行 / end 结束）。

// uuencode 文本 → 字节（测试向量解码专用，不进 src 产物）
export const uudecode = (text) => {
  const lines = text.split(/\r?\n/);
  if (lines.length === 0 || !lines[0].startsWith('begin ')) {
    throw new Error('uudecode 输入必须以 begin MODE NAME 行开头');
  }
  const out = [];
  for (let i = 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line === 'end') break;
    if (line === '`' || line.length === 0) continue;
    const count = (line.charCodeAt(0) - 32) & 63;
    if (count === 0) continue;
    const bytes = [];
    for (let j = 1; j < line.length; j += 4) {
      const chars = [0, 1, 2, 3].map((k) => (j + k < line.length ? (line.charCodeAt(j + k) - 32) & 63 : 0));
      const packed = (chars[0] << 18) | (chars[1] << 12) | (chars[2] << 6) | chars[3];
      bytes.push((packed >> 16) & 255, (packed >> 8) & 255, packed & 255);
    }
    for (let b = 0; b < count; b += 1) out.push(bytes[b]);
  }
  return Uint8Array.from(out);
};

const joinUu = (lines) => lines.join('\n');

const ENCRYPTION_DATA_UU_LINES = ["begin 664 test_read_format_rar_encryption_data.rar","M4F%R(1H'`,^0<P``#0````````!=_'0DA\"\\`(````!`````#7(:MIJ5,,4,=","M,P<`M($``&9O;RYT>'1/`[S9UA9,WT5`&I*2B-\\5*XZ>SW\"Y0.C)1^;.UK]$","MXK@UJ)SH93<!!T5T)(0O`\"`````0`````[[BD,VF3#%#'3,'`+2!``!B87(N","M='AT3P.\\V=863-]P='I(B8@/9EM]Y0:Y<AZH)57XRC<!H^WT\\13S(V31H<0]","%>P!`!P``","`","end"];

const RAR4_ENCRYPTED_UU_LINES = ["begin 0744 test_read_format_rar4_encrypted.rar","M4F%R(1H'`,^0<P``#0`````````J8W0@D\"H`$@```!(````\"56Y:[F17=E@=","M,`4`(````&$N='AT`/#\\3!M4:&ES(&ES(&9R;VT@82YT>'1?CG0DE#(`(```","M`!(````\"A13ZJ6=7=E@=,P4`(````&(N='ATO@(;FGDJBE4`L'*@-,GY]@T0","M?ZC1UGSKU*2VR-1K@HH>GZZP#?C:ML=$\"NKDN\\=T()`J`!(````2`````C4]","MFI1N5W98'3`%`\"````!C+G1X=`\"P/D@M5&AI<R!I<R!F<F]M(&,N='AT[<IT","M))0R`\"`````2`````B7ANB9-9'98'3,%`\"````!D+G1X=*_B?1/SI5-2`/#[","I88]V^#_)1V@;4\"TVC,!XR=.I1:KVB0/<OAC@C&97VP3UZ<0]>P!`!P``","`","end"];

// 真实工具产物向量一：全条目加密（口令 "12345678"）
export const encryptionDataRar = () => uudecode(joinUu(ENCRYPTION_DATA_UU_LINES));

// 真实工具产物向量二：部分条目加密（b.txt 口令 "password"，d.txt 口令 "password2"）
export const rar4EncryptedRar = () => uudecode(joinUu(RAR4_ENCRYPTED_UU_LINES));
