// UPX NRV2B 对拍 driver：原版 UCL n2b_d.c + getbit.h（存档 output/ucl-*.c），
// gcc 编译后解压 sample-upx.elf 的首个 b_info 块，输出解压字节 + ilen 终值。
// 用法：gcc -O2 -o upx-nrv-driver scripts/upx-nrv-driver.c && ./upx-nrv-driver tests/fixtures/sample-upx.elf
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char ucl_byte;
typedef unsigned int ucl_uint;
typedef unsigned int ucl_uintp[1];
#define ucl_voidp void*
#define ACC_UNUSED(x) ((void)x)
#define UCL_UINT32_C(c) c ## U
#define UA_GET4(p) (*(const unsigned int *)(const void *)(p))
#define UCL_E_OK 0
#define UCL_E_INPUT_OVERRUN (-201)
#define UCL_E_OUTPUT_OVERRUN (-202)
#define UCL_E_LOOKBEHIND_OVERRUN (-203)
#define fail(x, r) if (x) { *dst_len = olen; return r; }

// ---- 原版 getbit_le32（getbit.h 逐字）----
#define getbit_le32(bb, bc, src, ilen) \
    (bc > 0 ? ((bb >> --bc) & 1) : (bc = 31, \
    bb = UA_GET4((src) + ilen), ilen += 4, (bb >> 31) & 1))

// ---- 原版 n2b_d.c 主循环（SAFE 关闭版逐字）----
static int nrv2b_decompress_le32(const ucl_byte *src, ucl_uint src_len,
    ucl_byte *dst, ucl_uint *dst_len, ucl_voidp wrkmem)
{
    unsigned int bb = 0;
    ucl_uint ilen = 0, olen = 0, last_m_off = 1;
    ucl_uint bc = 0;
    const ucl_uint oend = *dst_len;
    ACC_UNUSED(wrkmem);
    (void)bc;
    {
        unsigned int bbb = 0; ucl_uint bcc = 0;
        // 复制宏内的 bb/bc 用局部（getbit_le32 带独立 bc 参数版本）
        for (;;)
        {
            ucl_uint m_off, m_len;

            while (getbit_le32(bbb, bcc, src, ilen))
            {
                fail(ilen >= src_len, UCL_E_INPUT_OVERRUN);
                fail(olen >= oend, UCL_E_OUTPUT_OVERRUN);
                dst[olen++] = src[ilen++];
            }
            m_off = 1;
            do {
                m_off = m_off * 2 + getbit_le32(bbb, bcc, src, ilen);
                fail(ilen >= src_len, UCL_E_INPUT_OVERRUN);
                fail(m_off > UCL_UINT32_C(0xffffff) + 3, UCL_E_LOOKBEHIND_OVERRUN);
            } while (!getbit_le32(bbb, bcc, src, ilen));
            if (m_off == 2)
            {
                m_off = last_m_off;
            }
            else
            {
                fail(ilen >= src_len, UCL_E_INPUT_OVERRUN);
                m_off = (m_off - 3) * 256 + src[ilen++];
                if (m_off == UCL_UINT32_C(0xffffffff))
                    break;
                last_m_off = ++m_off;
            }
            m_len = getbit_le32(bbb, bcc, src, ilen);
            m_len = m_len * 2 + getbit_le32(bbb, bcc, src, ilen);
            if (m_len == 0)
            {
                m_len++;
                do {
                    m_len = m_len * 2 + getbit_le32(bbb, bcc, src, ilen);
                    fail(ilen >= src_len, UCL_E_INPUT_OVERRUN);
                    fail(m_len >= oend, UCL_E_OUTPUT_OVERRUN);
                } while (!getbit_le32(bbb, bcc, src, ilen));
                m_len += 2;
            }
            m_len += (m_off > 0xd00);
            fail(olen + m_len > oend, UCL_E_OUTPUT_OVERRUN);
            fail(m_off > olen, UCL_E_LOOKBEHIND_OVERRUN);
            {
                const ucl_byte *m_pos;
                m_pos = dst + olen - m_off;
                dst[olen++] = *m_pos++;
                do dst[olen++] = *m_pos++; while (--m_len > 0);
            }
        }
        *dst_len = olen;
        return ilen == src_len ? UCL_E_OK : (ilen < src_len ? (-204) : UCL_E_INPUT_OVERRUN);
    }
}

// main：argv[1]=upx.elf；块定位由 JS 侧约定：l_info magic "UPX!"@236 → 块数据 @268，sz_cpr=248, sz_unc=848
int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s upx.elf\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 1; }
    fseek(f, 0, SEEK_END); long size = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(size);
    if (fread(buf, 1, size, f) != (size_t)size) { perror("read"); return 1; }
    fclose(f);

    // 与 JS parseUpx 相同的定位：扫 100..0x800 找 "UPX!"（首个=头部 l_info magic@236）
    long magic = -1;
    for (long i = 100; i + 12 < size && i < 0x800; i++) {
        if (memcmp(buf + i, "UPX!", 4) == 0) { magic = i; break; }
    }
    if (magic < 0) { fprintf(stderr, "no magic\n"); return 1; }
    long blockOff = magic + 20; // l_info(12, magic@+4) + p_info(12)
    unsigned int szUnc = *(unsigned int *)(buf + blockOff);
    unsigned int szCpr = *(unsigned int *)(buf + blockOff + 4);
    unsigned char method = buf[blockOff + 8];
    fprintf(stderr, "block @%ld sz_unc=%u sz_cpr=%u method=%u data@%ld\n", blockOff, szUnc, szCpr, method, blockOff + 12);

    unsigned char *out = malloc(szUnc + 16);
    ucl_uint outLen[1] = { szUnc };
    int rc = nrv2b_decompress_le32(buf + blockOff + 12, szCpr, out, outLen, 0);
    fprintf(stderr, "rc=%d olen=%u\n", rc, outLen[0]);
    for (unsigned int i = 0; i < outLen[0] && i < 64; i++) printf("%02x ", out[i]);
    printf("\n");
    return 0;
}
