/* outguess 0.2 提取语义 C 参照 driver（批次 SI-3 对拍锚定件）：
 * 手抄自 resurrecting-open-source-projects/outguess 原版存档（output/outguess-*.c），
 * 逐行保留原语义：arc4_getbyte/getword/addrandom/initkey（arc.c 48-127 行，MD5 由调用方
 * 算好后以 32 位 hex 传入——JS 侧 codec md5Bytes 已有独立测试覆盖）、iterator 全家
 * （iterator.c 42-77 行 + iterator.h SKIPADJ）、steg_use_bit 位流收集规则（jpg.c 289-337：
 * (temp&1)==temp 跳过）、steg_retrbyte/steg_retrieve（main.c 340-414，无 ECC）与
 * decode_data 无 ECC 路径（main.c 670-676）。与 JS 实现（src/utils/ctf/outguessExtract.ts）
 * 同输入对拍：明文、seed、len、逐字节 skipmod 序列、头部 4 字节的 off 序列。
 * 编译：gcc -O2 -o outguess-ref.exe scripts/outguess-ref-driver.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

typedef uint8_t u_int8_t;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef unsigned char u_char; /* MinGW sys/types.h 不带 BSD u_char */

/* ---- arc.c 逐行手抄 ---- */
struct arc4_stream { u_int8_t s[256]; u_int8_t i, j; };

static void arc4_init(struct arc4_stream *as) {
	int n;
	for (n = 0; n < 256; n++) as->s[n] = n;
	as->i = 0; as->j = 0;
}

static u_int8_t arc4_getbyte(struct arc4_stream *as) {
	u_int8_t si, sj;
	as->i = (as->i + 1);
	si = as->s[as->i];
	as->j = (as->j + si);
	sj = as->s[as->j];
	as->s[as->i] = sj;
	as->s[as->j] = si;
	return as->s[(si + sj) & 0xff];
}

static u_int32_t arc4_getword(struct arc4_stream *as) {
	u_int32_t val;
	val = arc4_getbyte(as) << 24;
	val |= arc4_getbyte(as) << 16;
	val |= arc4_getbyte(as) << 8;
	val |= arc4_getbyte(as);
	return val;
}

static void arc4_addrandom(struct arc4_stream *as, u_char *dat, int datlen) {
	int n; u_int8_t si;
	as->i--;
	for (n = 0; n < 256; n++) {
		as->i = (as->i + 1);
		si = as->s[as->i];
		as->j = (as->j + si + dat[n % datlen]);
		as->s[as->i] = as->s[as->j];
		as->s[as->j] = si;
	}
}

/* arc4_initkey 的 MD5 前置段由调用方完成：argv 传 md5(type||key) 的 32 hex 字符 */
static void arc4_initkey_digest(struct arc4_stream *as, const char *digest_hex) {
	u_char digest[16];
	for (int n = 0; n < 16; n++) {
		unsigned v; sscanf(digest_hex + 2 * n, "%2x", &v); digest[n] = (u_char)v;
	}
	arc4_init(as);
	arc4_addrandom(as, digest, 16);
}

/* ---- iterator.c/.h 逐行手抄 ---- */
#define INIT_SKIPMOD 32
#define SKIPADJ(x,y) ((y) > (x)/32 ? 2 : 2 - ((x/32) - (y))/(float)(x/32))

typedef struct { struct arc4_stream as; int off; int skipmod; } iterator;
typedef struct { int bits; } ref_bitmap;

static void iterator_init(iterator *iter, ref_bitmap *b, struct arc4_stream *seed_as) {
	iter->skipmod = INIT_SKIPMOD;
	iter->as = *seed_as; /* JS 侧 iteratorInit 内联 arc4_initkey('Seeding')，此处由调用方传入同态流 */
	iter->off = arc4_getword(&iter->as) % iter->skipmod;
}

static int iterator_next(iterator *iter, ref_bitmap *b) {
	iter->off += (arc4_getword(&iter->as) % iter->skipmod) + 1;
	return iter->off;
}

static void iterator_seed(iterator *iter, ref_bitmap *b, u_int16_t seed) {
	u_int8_t reseed[2];
	reseed[0] = seed;
	reseed[1] = seed >> 8;
	arc4_addrandom(&iter->as, reseed, 2);
}

static void iterator_adapt(iterator *iter, ref_bitmap *b, int datalen) {
	iter->skipmod = SKIPADJ(b->bits, b->bits - iter->off) * (b->bits - iter->off) / (8 * datalen);
}

/* ---- jpg.c steg_use_bit 收集规则（(temp&1)==temp 跳过，temp=unsigned short 视图）---- */
static int collect_bit(int coeff) {
	unsigned short temp = (unsigned short)coeff;
	if ((temp & 0x1) == temp) return -1; /* 0/+1 跳过 */
	return temp & 0x1;
}

/* ---- main.c steg_retrbyte 逐行手抄（位流以数组代替 bitmap）---- */
static u_char *g_bits; /* 0/1 位流 */
static int g_total_bits;

static u_int32_t steg_retrbyte(iterator *iter) {
	u_int32_t i = iter->off;
	int where;
	u_int32_t tmp = 0;
	for (where = 0; where < 8; where++) {
		if (i >= (u_int32_t)g_total_bits) { fprintf(stderr, "ref: bitstream exhausted\n"); exit(2); }
		tmp |= (g_bits[i] ? 1 : 0) << where;
		i = iterator_next(iter, NULL);
	}
	return tmp;
}

/* decode_data 无 ECC 路径 = XOR（main.c 666-676）*/
static void xor_stream(u_char *buf, int len, struct arc4_stream *as) {
	for (int j = 0; j < len; j++) buf[j] ^= arc4_getbyte(as);
}

int main(int argc, char **argv) {
	if (argc < 6) {
		fprintf(stderr, "usage: %s <enc_md5hex(32)> <seed_md5hex(32)> <ncoeff> <seed> <plaintext_hex>\n", argv[0]);
		return 1;
	}
	const char *enc_hex = argv[1];    /* md5("Encryption"||key) */
	const char *seed_hex = argv[2];   /* md5("Seeding"||key) */
	int ncoeff = atoi(argv[3]);
	unsigned seed = (unsigned)strtoul(argv[4], NULL, 0);
	const char *plain_hex = argv[5];

	u_char plaintext[4096]; int plainlen = 0;
	for (const char *p = plain_hex; p[0] && p[1] && plainlen < 4096; p += 2) {
		unsigned v; sscanf(p, "%2x", &v); plaintext[plainlen++] = (u_char)v;
	}

	/* mock 系数 pattern 与 JS 测试一致 */
	static const int pattern[10] = {7, -7, 2, -2, 0, 3, -1, 1, 5, -3};
	int *coeffs = malloc(sizeof(int) * ncoeff);
	int usable = 0;
	for (int i = 0; i < ncoeff; i++) coeffs[i] = pattern[i % 10];
	for (int i = 0; i < ncoeff; i++) if (collect_bit(coeffs[i]) >= 0) usable++;
	g_bits = calloc(usable, 1);
	g_total_bits = usable;

	ref_bitmap bm; bm.bits = usable;

	/* 嵌入方向（do_embed 简化主干：header XOR as，数据 XOR tas）*/
	struct arc4_stream as, tas, seed_as;
	arc4_initkey_digest(&as, enc_hex);
	tas = as;
	arc4_initkey_digest(&seed_as, seed_hex);
	iterator iter;
	iterator_init(&iter, &bm, &seed_as);

	/* 记录头部 4 字节写入期间的 off 走向（每字节首 off）*/
	int head_offs[4];
	u_char header[4] = {(u_char)(seed & 0xff), (u_char)(seed >> 8), (u_char)(plainlen & 0xff), (u_char)(plainlen >> 8)};
	u_char enc_header[4];
	for (int i = 0; i < 4; i++) enc_header[i] = header[i] ^ arc4_getbyte(&as);
	struct arc4_stream head_as_check; /* 独立流再走一遍头部 XOR 供校验 */
	(void)head_as_check;
	for (int i = 0; i < 4; i++) {
		head_offs[i] = iter.off;
		for (int where = 0; where < 8; where++) {
			g_bits[iter.off] = (enc_header[i] >> where) & 1;
			iterator_next(&iter, NULL);
		}
	}
	iterator_seed(&iter, &bm, (u_int16_t)seed);
	int skipmod_log[4096]; int slog = 0;
	u_char enc_plain[4096];
	for (int i = 0; i < plainlen; i++) enc_plain[i] = plaintext[i] ^ arc4_getbyte(&tas);
	int remaining = plainlen, n = 0;
	while (remaining > 0) {
		iterator_adapt(&iter, &bm, remaining);
		skipmod_log[slog++] = iter.skipmod;
		for (int where = 0; where < 8; where++) {
			g_bits[iter.off] = (enc_plain[n] >> where) & 1;
			iterator_next(&iter, NULL);
		}
		n++; remaining--;
	}

	/* 提取方向（steg_retrieve 逐行：fresh 流重走）*/
	struct arc4_stream x_as, x_tas, x_seed_as;
	arc4_initkey_digest(&x_as, enc_hex);
	x_tas = x_as;
	arc4_initkey_digest(&x_seed_as, seed_hex);
	iterator x_iter;
	iterator_init(&x_iter, &bm, &x_seed_as);

	u_char hbuf[4];
	for (int i = 0; i < 4; i++) hbuf[i] = (u_char)steg_retrbyte(&x_iter);
	xor_stream(hbuf, 4, &x_as);
	u_int16_t x_seed = hbuf[0] | (hbuf[1] << 8);
	int x_len = hbuf[2] | (hbuf[3] << 8);

	iterator_seed(&x_iter, &bm, x_seed);
	u_char out[4096]; int rem = x_len, m = 0;
	while (rem > 0) {
		iterator_adapt(&x_iter, &bm, rem);
		out[m++] = (u_char)steg_retrbyte(&x_iter);
		rem--;
	}
	xor_stream(out, x_len, &x_tas);

	/* 输出对拍面 */
	printf("usable=%d\n", usable);
	printf("seed=%u len=%d\n", (unsigned)x_seed, x_len);
	printf("headoffs=%d,%d,%d,%d\n", head_offs[0], head_offs[1], head_offs[2], head_offs[3]);
	printf("skipmods=");
	for (int i = 0; i < slog; i++) printf("%d%s", skipmod_log[i], i + 1 < slog ? "," : "");
	printf("\n");
	printf("plain=");
	for (int i = 0; i < x_len; i++) printf("%02x", out[i]);
	printf("\n");
	return 0;
}
