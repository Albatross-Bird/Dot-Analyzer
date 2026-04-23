import struct, math, sys, os

def read_pgm_p5(path):
    with open(path, 'rb') as f:
        data = f.read()
    i = 0
    def skip():
        nonlocal i
        while i < len(data):
            if data[i:i+1] == b'#':
                while i < len(data) and data[i:i+1] != b'\n': i += 1
            elif data[i:i+1] in (b' ', b'\t', b'\n', b'\r'): i += 1
            else: break
    def token():
        nonlocal i; skip(); tok = b''
        while i < len(data) and data[i:i+1] not in (b' ', b'\t', b'\n', b'\r'):
            tok += data[i:i+1]; i += 1
        return tok.decode()
    magic = token(); w = int(token()); h = int(token()); maxv = int(token()); i += 1
    return w, h, list(data[i:i+w*h])

def find_blobs(w, h, pixels, thresh=100):
    visited = [False]*(w*h)
    blobs = []
    for sy in range(h):
        for sx in range(w):
            idx = sy*w+sx
            if pixels[idx] < thresh and not visited[idx]:
                stack = [idx]; visited[idx] = True; xs, ys = [], []
                while stack:
                    cur = stack.pop(); cy2, cx2 = divmod(cur, w)
                    xs.append(cx2); ys.append(cy2)
                    for dx, dy in [(-1,0),(1,0),(0,-1),(0,1)]:
                        nx, ny = cx2+dx, cy2+dy
                        if 0<=nx<w and 0<=ny<h:
                            ni = ny*w+nx
                            if not visited[ni] and pixels[ni] < thresh:
                                visited[ni] = True; stack.append(ni)
                if len(xs) >= 20:
                    blobs.append((sum(xs)/len(xs), sum(ys)/len(xs)))
    return blobs

folder = "C:/Program Files/Dot Analyzer/test images"
for name in ["capture_0002.pgm", "capture_0004.pgm", "capture_0011.pgm"]:
    path = os.path.join(folder, name)
    print(f"\n=== {name} ===")
    w, h, pixels = read_pgm_p5(path)
    blobs = find_blobs(w, h, pixels, thresh=100)
    nb = len(blobs)
    print(f"  blobs={nb}")
    cx_arr = [b[0] for b in blobs]
    cy_arr = [b[1] for b in blobs]

    mx = sum(cx_arr)/nb; my = sum(cy_arr)/nb
    cxx=cyy=cxy=0.0
    for cx,cy in zip(cx_arr,cy_arr):
        dx=cx-mx; dy=cy-my; cxx+=dx*dx; cyy+=dy*dy; cxy+=dx*dy
    tilt_rad = 0.5*math.atan2(2.0*cxy, cxx-cyy)
    print(f"  PCA tilt={math.degrees(tilt_rad):.3f}deg  cxy={cxy:.0f}  cxx={cxx:.0f}  cyy={cyy:.0f}")

    cos_t = math.cos(-tilt_rad); sin_t = math.sin(-tilt_rad)
    rx = [cx*cos_t - cy*sin_t for cx,cy in zip(cx_arr,cy_arr)]

    sorted_rx = sorted(rx)
    gaps = [sorted_rx[i+1]-sorted_rx[i] for i in range(nb-1)]
    gaps_s = sorted(gaps)

    # Print distribution of rx values (histogram of 20 bins)
    rx_min, rx_max = min(rx), max(rx)
    print(f"  rx range: {rx_min:.1f} to {rx_max:.1f}  span={rx_max-rx_min:.1f}px")
    bins = 30
    bin_size = (rx_max - rx_min) / bins
    hist = [0]*bins
    for v in rx:
        b = min(int((v-rx_min)/bin_size), bins-1)
        hist[b] += 1
    print(f"  rx histogram (each bin={bin_size:.1f}px):")
    for i,c in enumerate(hist):
        bar = '#'*min(c,50)
        print(f"    {rx_min+i*bin_size:6.1f}: {bar} ({c})")

    # Gap percentiles
    n = len(gaps_s)
    pcts = [50, 75, 90, 95, 99, 100]
    print(f"  gap percentiles: ", end="")
    for p in pcts:
        idx = min(int(n*p/100), n-1)
        print(f"p{p}={gaps_s[idx]:.2f}", end="  ")
    print()
    print(f"  max gap={gaps_s[-1]:.2f}  2nd-max={gaps_s[-2]:.2f}  3rd-max={gaps_s[-3]:.2f}")
