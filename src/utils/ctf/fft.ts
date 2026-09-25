// 任意尺寸 FFT（批次 SI·C 线盲水印前置）：numpy.fft.fft2 语义复刻——行/列各自独立做 1D DFT，
// 尺寸可以是任意整数（含素数）。实现：2 的幂走迭代 radix-2；其余尺寸走 Bluestein 线性卷积
// （chirp-z），补零到 2 的幂做循环卷积。双精度 Float64Array，纯 JS 零依赖。
// 对拍基准：与朴素 O(n²) DFT 定义在随机向量上逐点一致（tests/blind-watermark.test.mjs 锚定）。

export interface ComplexArray {
  re: Float64Array;
  im: Float64Array;
  length: number;
}

const makeComplex = (length: number): ComplexArray => ({
  re: new Float64Array(length),
  im: new Float64Array(length),
  length,
});

const isPowerOfTwo = (n: number): boolean => n >= 1 && (n & (n - 1)) === 0;

// 朴素 DFT（对拍基准与小尺寸直接用）：正变换 e^{−2πi·kt/n}（inverse 为 +）
const dftNaive = (input: ComplexArray, inverse: boolean): ComplexArray => {
  const n = input.length;
  const out = makeComplex(n);
  const sign = inverse ? 1 : -1;
  for (let k = 0; k < n; k += 1) {
    let sumRe = 0;
    let sumIm = 0;
    for (let t = 0; t < n; t += 1) {
      const angle = (sign * 2 * Math.PI * k * t) / n;
      const cos = Math.cos(angle);
      const sin = Math.sin(angle);
      sumRe += input.re[t] * cos - input.im[t] * sin;
      sumIm += input.re[t] * sin + input.im[t] * cos;
    }
    out.re[k] = sumRe;
    out.im[k] = sumIm;
  }
  return out;
};

// 迭代 radix-2 FFT（位反转 + 蝶形）
const fftRadix2 = (input: ComplexArray, inverse: boolean): ComplexArray => {
  const n = input.length;
  const re = Float64Array.from(input.re);
  const im = Float64Array.from(input.im);
  // 位反转置换
  for (let i = 1, j = 0; i < n; i += 1) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      const tempRe = re[i];
      re[i] = re[j];
      re[j] = tempRe;
      const tempIm = im[i];
      im[i] = im[j];
      im[j] = tempIm;
    }
  }
  for (let length = 2; length <= n; length <<= 1) {
    const angle = (inverse ? 2 : -2) * Math.PI / length;
    const wRe = Math.cos(angle);
    const wIm = Math.sin(angle);
    for (let start = 0; start < n; start += length) {
      let curRe = 1;
      let curIm = 0;
      for (let offset = 0; offset < length / 2; offset += 1) {
        const evenIndex = start + offset;
        const oddIndex = evenIndex + length / 2;
        const productRe = curRe * re[oddIndex] - curIm * im[oddIndex];
        const productIm = curRe * im[oddIndex] + curIm * re[oddIndex];
        re[oddIndex] = re[evenIndex] - productRe;
        im[oddIndex] = im[evenIndex] - productIm;
        re[evenIndex] += productRe;
        im[evenIndex] += productIm;
        const nextCurRe = curRe * wRe - curIm * wIm;
        curIm = curRe * wIm + curIm * wRe;
        curRe = nextCurRe;
      }
    }
  }
  return { re, im, length: n };
};

// Bluestein（chirp-z）：X[k] = e^{−iπk²/n}·Σ_t [x[t]·e^{−iπt²/n}]·e^{+iπ(k−t)²/n}（正变换方向，
// 卷积核 b 取 a 的共轭 chirp，负下标镜像到 m−t）。sign：正变换 −1 / 逆变换 +1（手推 e₁ 单点锚定）
const fftBluestein = (input: ComplexArray, inverse: boolean): ComplexArray => {
  const n = input.length;
  const sign = inverse ? 1 : -1;
  let m = 1;
  while (m < 2 * n - 1) m <<= 1;
  const a = makeComplex(m);
  const b = makeComplex(m);
  // chirp：w[t] = exp(sign·i·π·t²/n)（t² 用 (t·t) mod 2n 归约，2n 是该 chirp 的完整周期）
  for (let t = 0; t < n; t += 1) {
    const angle = (sign * Math.PI * ((t * t) % (2 * n))) / n;
    a.re[t] = input.re[t] * Math.cos(angle) - input.im[t] * Math.sin(angle);
    a.im[t] = input.re[t] * Math.sin(angle) + input.im[t] * Math.cos(angle);
    b.re[t] = Math.cos(angle);
    b.im[t] = -Math.sin(angle);
  }
  for (let t = 1; t < n; t += 1) {
    b.re[m - t] = b.re[t];
    b.im[m - t] = b.im[t];
  }
  const fa = fftRadix2(a, false);
  const fb = fftRadix2(b, false);
  const conv = makeComplex(m);
  for (let index = 0; index < m; index += 1) {
    const productRe = fa.re[index] * fb.re[index] - fa.im[index] * fb.im[index];
    const productIm = fa.re[index] * fb.im[index] + fa.im[index] * fb.re[index];
    conv.re[index] = productRe;
    conv.im[index] = productIm;
  }
  const convTime = fftRadix2(conv, true);
  const out = makeComplex(n);
  const scale = 1 / m;
  for (let k = 0; k < n; k += 1) {
    const angle = (sign * Math.PI * ((k * k) % (2 * n))) / n;
    const chirpRe = Math.cos(angle);
    const chirpIm = Math.sin(angle);
    const valueRe = convTime.re[k] * scale;
    const valueIm = convTime.im[k] * scale;
    out.re[k] = valueRe * chirpRe - valueIm * chirpIm;
    out.im[k] = valueRe * chirpIm + valueIm * chirpRe;
  }
  return out;
};

// 任意尺寸 FFT（正变换，numpy.fft.fft 语义：exp(−2πi·kt/n)）
export const fft1d = (input: ComplexArray): ComplexArray => {
  if (input.length <= 1) return makeComplexCopy(input);
  if (input.length <= 32) return dftNaive(input, false);
  if (isPowerOfTwo(input.length)) return fftRadix2(input, false);
  return fftBluestein(input, false);
};

// 逆 FFT（numpy.fft.ifft 语义：含 1/n 归一化）
export const ifft1d = (input: ComplexArray): ComplexArray => {
  if (input.length <= 1) return makeComplexCopy(input);
  const n = input.length;
  let result: ComplexArray;
  if (n <= 32) result = dftNaive(input, true);
  else if (isPowerOfTwo(n)) result = fftRadix2(input, true);
  else result = fftBluestein(input, true);
  for (let index = 0; index < n; index += 1) {
    result.re[index] /= n;
    result.im[index] /= n;
  }
  return result;
};

const makeComplexCopy = (input: ComplexArray): ComplexArray => ({
  re: Float64Array.from(input.re),
  im: Float64Array.from(input.im),
  length: input.length,
});

// 二维 FFT（numpy.fft.fft2 语义：先对每行做 1D，再对每列做 1D；返回行主序 length=h*w）
export const fft2d = (re: Float64Array, im: Float64Array, width: number, height: number): { re: Float64Array; im: Float64Array } => {
  const row = makeComplex(width);
  for (let y = 0; y < height; y += 1) {
    row.re.set(re.subarray(y * width, y * width + width));
    row.im.set(im.subarray(y * width, y * width + width));
    const transformed = fft1d(row);
    re.set(transformed.re.subarray(0, width), y * width);
    im.set(transformed.im.subarray(0, width), y * width);
  }
  const col = makeComplex(height);
  for (let x = 0; x < width; x += 1) {
    for (let y = 0; y < height; y += 1) {
      col.re[y] = re[y * width + x];
      col.im[y] = im[y * width + x];
    }
    const transformed = fft1d(col);
    for (let y = 0; y < height; y += 1) {
      re[y * width + x] = transformed.re[y];
      im[y * width + x] = transformed.im[y];
    }
  }
  return { re, im };
};

export const ifft2d = (re: Float64Array, im: Float64Array, width: number, height: number): { re: Float64Array; im: Float64Array } => {
  // ifft2 = fft2(conj(x)) 的共轭 / (w·h)
  const n = width * height;
  const conjugated = makeComplex(n);
  for (let index = 0; index < n; index += 1) {
    conjugated.re[index] = re[index];
    conjugated.im[index] = -im[index];
  }
  const transformed = fft2d(conjugated.re, conjugated.im, width, height);
  for (let index = 0; index < n; index += 1) {
    transformed.re[index] /= n;
    transformed.im[index] = -transformed.im[index] / n;
  }
  return transformed;
};
