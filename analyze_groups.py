import struct, math, sys, os

def read_pgm_p5(path):
    with open(path, 'rb') as f:
        data = f.read()
    # Parse P5 header
    i = 0
    def skip_ws_comments():
        nonlocal i
        while i < len(data):
            if data[i:i+1] == b'#':
                while i < len(data) and data[i:i+1] != b'\n': i += 1
            elif data[i:i+1] in (b' ', b'\t', b'\n', b'\r'): i += 1
            else: break
    def read_token():
        nonlocal i
        skip_ws_comments()
        tok = b''
        while i < len(data) and data[i:i+1] not in (b' ', b'\t', b'\n', b'\r'):
            tok += data[i:i+1]; i += 1
        return tok.decode()
    magic = read_token()
    w = int(read_token()); h = int(read_token()); maxv = int(read_token())
    i += 1  # skip one whitespace after maxval
    pixels = list(data[i:i+w*h])
    return w, h, pixels

def find_blobs(w, h, pixels, thresh=100):
    # Simple flood-fill connected components on dark pixels
    visited = [False]*(w*h)
    blobs = []
    for sy in range(h):
        for sx in range(w):
            idx = sy*w+sx
            if pixels[idx] < thresh and not visited[idx]:
                # BFS
                stack = [idx]
                visited[idx] = True
                xs, ys = [], []
                while stack:
                    cur = stack.pop()
                    cy2, cx2 = divmod(cur, w)
                    xs.append(cx2); ys.append(cy2)
                    for dx, dy in [(-1,0),(1,0),(0,-1),(0,1)]:
                        nx, ny = cx2+dx, cy2+dy
                        if 0<=nx<w and 0<=ny<h:
                            ni = ny*w+nx
                            if not visited[ni] and pixels[ni] < thresh:
                                visited[ni] = True; stack.append(ni)
                area = len(xs)
                if area >= 20:  # min area filter
                    blobs.append((sum(xs)/area, sum(ys)/area, area))
    return blobs

def infer_groups_sim(blobs_cx_cy, verbose=False):
    nb = len(blobs_cx_cy)
    if nb < 2:
        return
    DA_PI = math.pi
    cx_arr = [b[0] for b in blobs_cx_cy]
    cy_arr = [b[1] for b in blobs_cx_cy]

    # Step 1: PCA
    mx = sum(cx_arr)/nb; my = sum(cy_arr)/nb
    cxx=cyy=cxy=0.0
    for cx,cy in zip(cx_arr,cy_arr):
        dx=cx-mx; dy=cy-my
        cxx+=dx*dx; cyy+=dy*dy; cxy+=dx*dy
    tilt_raw = 0.5*math.atan2(2.0*cxy, cxx-cyy)
    tilt_orig = tilt_raw
    # OLD clamp (what was there before my fix):
    tilt_clamped = max(-DA_PI/4, min(DA_PI/4, tilt_raw))
    # NEW normalize (my fix):
    tilt_norm = tilt_raw
    if tilt_norm >  DA_PI/4: tilt_norm -= DA_PI/2
    if tilt_norm < -DA_PI/4: tilt_norm += DA_PI/2

    print(f"  cxx={cxx:.0f}, cyy={cyy:.0f}, cxy={cxy:.0f}")
    print(f"  PCA raw tilt = {math.degrees(tilt_raw):.2f}°")
    print(f"  OLD clamped  = {math.degrees(tilt_clamped):.2f}°")
    print(f"  NEW norm     = {math.degrees(tilt_norm):.2f}°")

    for label, tilt_rad in [("OLD", tilt_clamped), ("NEW", tilt_norm)]:
        cos_t = math.cos(-tilt_rad); sin_t = math.sin(-tilt_rad)
        rx = [cx*cos_t - cy*sin_t for cx,cy in zip(cx_arr,cy_arr)]
        ry = [cx*sin_t + cy*cos_t for cx,cy in zip(cx_arr,cy_arr)]

        # Sort by rx, compute gaps
        sorted_rx = sorted(range(nb), key=lambda i: rx[i])
        sorted_rx_vals = [rx[i] for i in sorted_rx]
        gaps = [sorted_rx_vals[i+1]-sorted_rx_vals[i] for i in range(nb-1)]
        gaps_sorted = sorted(gaps)
        med_gap = gaps_sorted[len(gaps_sorted)//2]

        # OLD threshold
        old_thresh = max(med_gap*3.0, 2.0)

        # NEW bimodal threshold
        best_ratio = 0.0; best_k = -1
        for k in range(len(gaps_sorted)-1):
            if gaps_sorted[k] < 0.5: continue
            ratio = gaps_sorted[k+1]/gaps_sorted[k]
            if ratio > best_ratio: best_ratio=ratio; best_k=k
        if best_k >= 0 and best_ratio > 2.0:
            new_thresh = (gaps_sorted[best_k]+gaps_sorted[best_k+1])*0.5
        else:
            new_thresh = gaps_sorted[-1]*2.0

        # Count columns with new threshold
        cur_grp = 0; col_grps = [0]
        for g in gaps:
            if g > new_thresh: cur_grp += 1
            col_grps.append(cur_grp)
        n_groups_new = cur_grp+1

        cur_grp = 0; col_grps_old = [0]
        for g in gaps:
            if g > old_thresh: cur_grp += 1
            col_grps_old.append(cur_grp)
        n_groups_old = cur_grp+1

        print(f"  [{label}] med_gap={med_gap:.2f}, old_thresh={old_thresh:.2f} -> {n_groups_old} groups | "
              f"best_ratio={best_ratio:.1f}, new_thresh={new_thresh:.2f} -> {n_groups_new} groups")
        if label == "NEW":
            # Report group sizes
            from collections import Counter
            gcnt = Counter(col_grps)
            sizes = sorted(gcnt.values(), reverse=True)
            print(f"  [NEW] group sizes (top 5): {sizes[:5]}  ... total groups={n_groups_new}")

folder = "C:/Program Files/Dot Analyzer/test images"
names = sorted(os.listdir(folder))
for name in names:
    if not name.endswith('.pgm'): continue
    path = os.path.join(folder, name)
    print(f"\n=== {name} ===")
    w,h,pixels = read_pgm_p5(path)
    blobs = find_blobs(w, h, pixels, thresh=100)
    print(f"  {len(blobs)} blobs found (min_area=20)")
    if len(blobs) < 2:
        print("  too few blobs, skip")
        continue
    infer_groups_sim(blobs)
