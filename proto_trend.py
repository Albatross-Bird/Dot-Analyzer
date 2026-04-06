"""
Prototype: mean dot size per image, PNG output.
Same visual standards as proto_hist.py (5x7 bitmap font, pixel canvas).
Mean = dark gray (60,60,60).
Run: py proto_trend.py
"""
import csv, re, math, zlib, struct, statistics
from collections import defaultdict

# ── load data ─────────────────────────────────────────────────────────────────
images = defaultdict(list)
with open("C:/Program Files/Dot Analyzer/dot_measurements.csv") as f:
    for row in csv.DictReader(f):
        if not re.match(r'capture_\d+\.pgm', row.get('File', '')):
            continue
        try:
            images[row['File']].append(float(row['BBox_Diam_mm']))
        except:
            pass

keys       = sorted(images.keys())
n_images   = len(keys)
vals_mean  = [sum(v) / len(v) for v in [images[k] for k in keys]]
all_diams  = [d for k in keys for d in images[k]]
pop_mean   = sum(all_diams) / len(all_diams)
print(f"Images: {n_images}")
print(f"Sample mean range: {min(vals_mean):.4f} – {max(vals_mean):.4f}")
print(f"Population mean:   {pop_mean:.4f}")

# ── canvas / layout ───────────────────────────────────────────────────────────
PLOT_W, PLOT_H = 800, 480
ML, MR, MT, MB = 72, 24, 36, 52
px0, px1 = ML, PLOT_W - MR - 1
py0, py1 = MT, PLOT_H - MB - 1
pw = px1 - px0
ph = py1 - py0

# ── 5x7 bitmap font ───────────────────────────────────────────────────────────
GLYPHS = [
    [0x0E,0x11,0x13,0x15,0x19,0x11,0x0E],  # 0
    [0x04,0x0C,0x04,0x04,0x04,0x04,0x0E],  # 1
    [0x0E,0x11,0x01,0x02,0x04,0x08,0x1F],  # 2
    [0x0E,0x11,0x01,0x06,0x01,0x11,0x0E],  # 3
    [0x02,0x06,0x0A,0x12,0x1F,0x02,0x02],  # 4
    [0x1F,0x10,0x1E,0x01,0x01,0x11,0x0E],  # 5
    [0x06,0x08,0x10,0x1E,0x11,0x11,0x0E],  # 6
    [0x1F,0x01,0x02,0x04,0x08,0x08,0x08],  # 7
    [0x0E,0x11,0x11,0x0E,0x11,0x11,0x0E],  # 8
    [0x0E,0x11,0x11,0x0F,0x01,0x02,0x0C],  # 9
    [0x00,0x00,0x00,0x00,0x00,0x0C,0x0C],  # .
    [0x00,0x00,0x00,0x0E,0x00,0x00,0x00],  # -
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00],  # ' '
    [0x00,0x0C,0x0C,0x00,0x0C,0x0C,0x00],  # :
    [0x02,0x04,0x08,0x08,0x08,0x04,0x02],  # (
    [0x08,0x04,0x02,0x02,0x02,0x04,0x08],  # )
    [0x0A,0x0A,0x1F,0x0A,0x1F,0x0A,0x0A],  # #
    [0x0E,0x11,0x11,0x1F,0x11,0x11,0x11],  # A
    [0x0E,0x11,0x10,0x10,0x10,0x11,0x0E],  # C
    [0x1C,0x12,0x11,0x11,0x11,0x12,0x1C],  # D
    [0x1F,0x10,0x10,0x1E,0x10,0x10,0x1F],  # E
    [0x0E,0x11,0x10,0x0E,0x01,0x11,0x0E],  # G
    [0x11,0x11,0x11,0x1F,0x11,0x11,0x11],  # H
    [0x1F,0x04,0x04,0x04,0x04,0x04,0x1F],  # I
    [0x1F,0x08,0x08,0x08,0x08,0x09,0x06],  # J  (unused but keeping table dense)
    [0x11,0x12,0x14,0x18,0x14,0x12,0x11],  # K
    [0x10,0x10,0x10,0x10,0x10,0x10,0x1F],  # L (unused)
    [0x11,0x1B,0x15,0x15,0x11,0x11,0x11],  # M
    [0x11,0x19,0x15,0x13,0x11,0x11,0x11],  # N
    [0x0E,0x11,0x11,0x11,0x11,0x11,0x0E],  # O
    [0x1E,0x11,0x11,0x1E,0x14,0x12,0x11],  # R
    [0x0E,0x11,0x10,0x0E,0x01,0x11,0x0E],  # S
    [0x1F,0x04,0x04,0x04,0x04,0x04,0x04],  # T
    [0x11,0x11,0x11,0x11,0x11,0x11,0x0E],  # U
    [0x11,0x11,0x11,0x0A,0x0A,0x04,0x04],  # V (unused)
    [0x11,0x11,0x15,0x15,0x0A,0x0A,0x11],  # W (unused)
    [0x11,0x0A,0x04,0x04,0x04,0x0A,0x11],  # X (unused)
    [0x11,0x11,0x0A,0x04,0x04,0x04,0x04],  # Y (unused)
]
GLYPH_MAP = {str(i): i for i in range(10)}
GLYPH_MAP.update({'.':10, '-':11, ' ':12, ':':13, '(':14, ')':15, '#':16,
                  'A':17,'C':18,'D':19,'E':20,'G':21,'H':22,
                  'I':23,'M':27,'N':28,'O':29,'R':30,'S':31,'T':32,'U':33})
FW, FH = 5, 7

def glyph_idx(c):
    return GLYPH_MAP.get(c, 12)

# ── RGB canvas ────────────────────────────────────────────────────────────────
canvas = bytearray(b'\xff' * (PLOT_W * PLOT_H * 3))

def ppx(x, y, r, g, b):
    if 0 <= x < PLOT_W and 0 <= y < PLOT_H:
        i = (y * PLOT_W + x) * 3
        canvas[i], canvas[i+1], canvas[i+2] = r, g, b

def hline(x0, x1, y, r, g, b):
    for x in range(x0, x1+1): ppx(x, y, r, g, b)

def vline(x, y0, y1, r, g, b):
    for y in range(y0, y1+1): ppx(x, y, r, g, b)

def hline_dashed(x0, x1, y, r, g, b, dash=10, gap=2):
    """Horizontal dashed line, 1px thick."""
    x = x0
    while x <= x1:
        for i in range(dash):
            if x + i <= x1:
                ppx(x + i, y, r, g, b)
        x += dash + gap

def draw_line(x0, y0, x1, y1, r, g, b):
    """Bresenham line."""
    dx, dy = abs(x1-x0), abs(y1-y0)
    sx = 1 if x0 < x1 else -1
    sy = 1 if y0 < y1 else -1
    err = dx - dy
    while True:
        ppx(x0, y0, r, g, b)
        if x0 == x1 and y0 == y1: break
        e2 = 2 * err
        if e2 > -dy: err -= dy; x0 += sx
        if e2 <  dx: err += dx; y0 += sy

def draw_char(ox, oy, c, r, g, b):
    fi = glyph_idx(c)
    if fi >= len(GLYPHS): return
    for row in range(FH):
        bits = GLYPHS[fi][row]
        for col in range(FW):
            if bits & (0x10 >> col):
                ppx(ox+col, oy+row, r, g, b)

def draw_str(x, y, s, r, g, b):
    for c in s:
        draw_char(x, y, c, r, g, b)
        x += FW + 1

def str_w(s):
    return len(s) * (FW+1) - 1 if s else 0

# ── y-axis range — centred on population mean ────────────────────────────────
y_data_min, y_data_max = min(vals_mean), max(vals_mean)
y_span = y_data_max - y_data_min

# Half-span from pop_mean to furthest sample mean, plus 20% padding
half_span = max(abs(pop_mean - y_data_min), abs(pop_mean - y_data_max))
y_pad     = half_span * 0.20 if half_span > 1e-9 else 0.001
y_lo      = pop_mean - half_span - y_pad
y_hi      = pop_mean + half_span + y_pad

# Nice y-axis step
NICE_YS = [0.0001,0.0002,0.0005,0.001,0.002,0.005,0.01,0.02,0.05,0.1,0.2,0.5]
y_step = NICE_YS[-1]
for v in NICE_YS:
    if (y_hi - y_lo) / v <= 7:
        y_step = v
        break

# Snap y_lo/y_hi outward to step grid, keeping pop_mean centred
y_lo = math.floor(y_lo / y_step) * y_step
y_hi = math.ceil(y_hi  / y_step) * y_step

def data_to_py(val):
    """Map mm value to canvas y pixel."""
    frac = (val - y_lo) / (y_hi - y_lo)
    return py1 - int(frac * ph + 0.5)

def img_to_px(idx):
    """Map 0-based image index to canvas x pixel (centred in its slot)."""
    slot = pw / n_images
    return px0 + int((idx + 0.5) * slot + 0.5)

# ── grid lines ────────────────────────────────────────────────────────────────
yv = y_lo
while yv <= y_hi + 1e-9:
    py = data_to_py(yv)
    hline(px0+1, px1-1, py, 220, 220, 220)
    yv = round(yv + y_step, 9)

# ── population mean dashed line ──────────────────────────────────────────────
pop_py = data_to_py(pop_mean)
hline_dashed(px0 + 1, px1 - 1, pop_py, 200, 40, 40)

# ── plot lines ────────────────────────────────────────────────────────────────
r, g, b = 60, 60, 60
pts = [(img_to_px(i), data_to_py(v)) for i, v in enumerate(vals_mean)]
# 2px thick line: draw at y and y+1
for i in range(len(pts) - 1):
    draw_line(pts[i][0], pts[i][1],   pts[i+1][0], pts[i+1][1],   r, g, b)
    draw_line(pts[i][0], pts[i][1]+1, pts[i+1][0], pts[i+1][1]+1, r, g, b)
# 5x5 square marker at each data point
for x, y in pts:
    for dy in range(-2, 3):
        for dx in range(-2, 3):
            ppx(x+dx, y+dy, r, g, b)

# ── plot border ───────────────────────────────────────────────────────────────
hline(px0, px1, py0, 80, 80, 80)
hline(px0, px1, py1, 80, 80, 80)
vline(px0, py0, py1, 80, 80, 80)
vline(px1, py0, py1, 80, 80, 80)

# ── x-axis ticks ─────────────────────────────────────────────────────────────
# Label every Nth image so labels don't overlap; target ~8 labels
tick_every = max(1, n_images // 10)
for i in range(n_images):
    if i % tick_every != 0 and i != n_images - 1:
        continue
    tx = img_to_px(i)
    vline(tx, py1, py1+4, 80, 80, 80)
    lbl = str(i + 1)
    lw  = str_w(lbl)
    draw_str(tx - lw//2, py1+7, lbl, 60, 60, 60)

# ── y-axis ticks ─────────────────────────────────────────────────────────────
yv = y_lo
while yv <= y_hi + 1e-9:
    py = data_to_py(yv)
    hline(px0-4, px0, py, 80, 80, 80)
    lbl = f"{yv:.3f}"
    lw  = str_w(lbl)
    draw_str(px0 - 6 - lw, py - FH//2, lbl, 60, 60, 60)
    yv = round(yv + y_step, 9)

# ── axis labels ───────────────────────────────────────────────────────────────
xl = "IMAGE (#)"
draw_str((px0+px1)//2 - str_w(xl)//2, PLOT_H-14, xl, 40, 40, 40)

yl = "DIAMETER (MM)"
total_h = len(yl)*(FH+2)-2
ys = (py0+py1)//2 - total_h//2
for i, c in enumerate(yl):
    draw_str(4, ys + i*(FH+2), c, 40, 40, 40)

# ── legend (top-right) ───────────────────────────────────────────────────────
ax, ay = px1 - 2, py0 + 4
s = "POPULATION MEAN"
draw_str(ax - str_w(s), ay, s, 200, 40, 40)
ay += FH + 4
s = "SAMPLE MEAN"
draw_str(ax - str_w(s), ay, s, 60, 60, 60)

# ── write PNG ─────────────────────────────────────────────────────────────────
def write_png(path, rgb, w, h):
    def chunk(tag, data):
        c = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', c)
    raw = b''
    for y in range(h):
        raw += b'\x00' + bytes(rgb[y*w*3:(y+1)*w*3])
    sig  = b'\x89PNG\r\n\x1a\n'
    ihdr = chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
    idat = chunk(b'IDAT', zlib.compress(raw, 6))
    iend = chunk(b'IEND', b'')
    with open(path, 'wb') as f:
        f.write(sig + ihdr + idat + iend)

out = "C:/Program Files/Dot Analyzer/proto_trend.png"
write_png(out, canvas, PLOT_W, PLOT_H)
print(f"Written: {out}")
