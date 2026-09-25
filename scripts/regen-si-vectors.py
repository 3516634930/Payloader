# 批次 SI 对拍参照向量再生（盲水印 numpy 参照 + FFT 锚点）。
# 用法：py -3.10 scripts/regen-si-vectors.py（需 numpy；在仓库根目录执行）
# 产物（output/ 供 tests/image-stego-si.test.mjs 引用，缺省时该测试显式 skip）：
#   bw-carrier.npy / bw-marked.npy / bw-decode-ref.npy —— chishaxie 原版语义 encode/decode 参照
#   fft-vec.json —— numpy.fft.fft 的 n=33 随机复向量（X[1] 锚点）
import numpy as np, random, json

random.seed(20160930)
h, w = 64, 64
hh = int(h * 0.5)
s = 42

def rnd():
    global s
    s = (s * 1103515245 + 12345) & 0x7fffffff
    return int((s / 0x7fffffff) * 256)

img = np.zeros((h, w))
for y in range(h):
    for x in range(w):
        img[y, x] = rnd()
m = list(range(hh)); n = list(range(w))
random.shuffle(m); random.shuffle(n)
hwm2 = np.zeros((hh, w))
for y in range(8, 24):
    for x in range(8, 56):
        hwm2[y, x] = 255
hwm = np.zeros((hh, w))
for i in range(hh):
    for j in range(w):
        hwm[i][j] = hwm2[m[i]][n[j]]
rwm = np.zeros((h, w))
for i in range(hh):
    for j in range(w):
        rwm[i][j] = hwm[i][j]
        rwm[h - 1 - i][w - 1 - j] = hwm[i][j]
f2 = np.fft.fft2(img) + 3.0 * rwm
img_wm = np.uint8(np.clip(np.real(np.fft.ifft2(f2)), 0, 255))
np.save('output/bw-carrier.npy', np.uint8(img))
np.save('output/bw-marked.npy', img_wm)
rwm2 = (np.fft.fft2(img_wm) - np.fft.fft2(img)) / 3.0
wm = np.zeros(rwm2.shape)
for i in range(hh):
    for j in range(w):
        wm[m[i]][n[j]] = np.uint8(np.real(rwm2[i][j]))
for i in range(hh):
    for j in range(w):
        wm[h - 1 - i][w - 1 - j] = wm[i][j]
np.save('output/bw-decode-ref.npy', np.uint8(wm))

# 整数域确定性序列（(i*37)%257）：JS/Python 无浮点乘法精度分叉，X[1] 锚点 = -1.353-0.589i
vals = [round((((i * 37) % 257) - 128) / 128, 6) for i in range(66)]
json.dump(vals, open('output/fft-vec.json', 'w'))
print('vectors regenerated: bw-carrier/bw-marked/bw-decode-ref.npy, fft-vec.json')
