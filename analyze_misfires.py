import math, os

def read_pgm_p5(path):
    with open(path, 'rb') as f: data = f.read()
    i = 0
    def skip():
        nonlocal i
        while i < len(data):
            if data[i:i+1] == b'#':
                while i < len(data) and data[i:i+1] != b'\n': i += 1
            elif data[i:i+1] in (b' ',b'\t',b'\n',b'\r'): i += 1
            else: break
    def token():
        nonlocal i; skip(); tok = b''
        while i < len(data) and data[i:i+1] not in (b' ',b'\t',b'\n',b'\r'):
            tok += data[i:i+1]; i += 1
        return tok.decode()
    magic=token(); w=int(token()); h=int(token()); maxv=int(token()); i+=1
    return w,h,list(data[i:i+w*h])

def find_blobs(w, h, pixels, thresh=100):
    visited = [False]*(w*h); blobs = []
    for sy in range(h):
        for sx in range(w):
            idx = sy*w+sx
            if pixels[idx] < thresh and not visited[idx]:
                stack=[idx]; visited[idx]=True; xs,ys=[],[]
                while stack:
                    cur=stack.pop(); cy2,cx2=divmod(cur,w)
                    xs.append(cx2); ys.append(cy2)
                    for dx,dy in [(-1,0),(1,0),(0,-1),(0,1)]:
                        nx,ny=cx2+dx,cy2+dy
                        if 0<=nx<w and 0<=ny<h:
                            ni=ny*w+nx
                            if not visited[ni] and pixels[ni]<thresh:
                                visited[ni]=True; stack.append(ni)
                if len(xs)>=20: blobs.append((sum(xs)/len(xs),sum(ys)/len(xs)))
    return blobs

RATIO_THRESH = 1.4

def bimodal(sorted_vals):
    sv = sorted_vals
    n = len(sv)
    gs = sorted([sv[i+1]-sv[i] for i in range(n-1)])
    best_ratio=0.0; best_k=-1
    for k in range(len(gs)-1):
        if gs[k] < 0.5: continue
        r = gs[k+1]/gs[k]
        if r > best_ratio: best_ratio=r; best_k=k
    if best_k >= 0 and best_ratio > RATIO_THRESH:
        thresh = (gs[best_k]+gs[best_k+1])*0.5
    else:
        thresh = gs[-1]*2.0
    return best_ratio, thresh

def simulate(blobs):
    nb = len(blobs)
    cx_arr = [b[0] for b in blobs]; cy_arr = [b[1] for b in blobs]
    mx=sum(cx_arr)/nb; my=sum(cy_arr)/nb
    cxx=cyy=cxy=0.0
    for cx,cy in zip(cx_arr,cy_arr):
        dx=cx-mx; dy=cy-my; cxx+=dx*dx; cyy+=dy*dy; cxy+=dx*dy
    t = 0.5*math.atan2(2.0*cxy, cxx-cyy)
    if t > math.pi/4: t -= math.pi/2
    if t < -math.pi/4: t += math.pi/2
    ct=math.cos(-t); st=math.sin(-t)
    rx=[cx*ct-cy*st for cx,cy in zip(cx_arr,cy_arr)]

    srx = sorted(range(nb), key=lambda i: rx[i])
    scx = sorted(range(nb), key=lambda i: cx_arr[i])

    rx_ratio, rx_thresh = bimodal([rx[i] for i in srx])
    cx_ratio, cx_thresh = bimodal([cx_arr[i] for i in scx])

    use_cx = cx_ratio >= rx_ratio
    sorted_winner = scx if use_cx else srx
    win_vals = [cx_arr[i] for i in sorted_winner] if use_cx else [rx[i] for i in sorted_winner]
    gap_thresh = cx_thresh if use_cx else rx_thresh
    proj = cx_arr if use_cx else rx

    # Assign column groups
    blob_grp = [0]*nb
    cur_grp = 0
    blob_grp[sorted_winner[0]] = 0
    for i in range(nb-1):
        if win_vals[i+1]-win_vals[i] > gap_thresh: cur_grp+=1
        blob_grp[sorted_winner[i+1]] = cur_grp
    n_groups_raw = cur_grp+1

    # Group centers in proj space
    grp_sum=[0.0]*n_groups_raw; grp_cnt=[0]*n_groups_raw
    for i in range(nb):
        grp_sum[blob_grp[i]] += proj[i]
        grp_cnt[blob_grp[i]] += 1
    grp_center = [grp_sum[g]/grp_cnt[g] for g in range(n_groups_raw)]

    # Column spacing
    diffs = sorted([grp_center[g+1]-grp_center[g] for g in range(n_groups_raw-1)])
    col_spacing = diffs[len(diffs)//2] if diffs else 0.0

    # Misfire check
    misfire_thresh = col_spacing * 0.4
    misfires = 0
    for i in range(nb):
        dev = abs(proj[i] - grp_center[blob_grp[i]])
        if col_spacing > 0.0 and dev > misfire_thresh:
            misfires += 1

    return math.degrees(t), use_cx, n_groups_raw, misfires, col_spacing

folder = "C:/Program Files/Dot Analyzer/test images"
broken = {4,5,7,8,9,10,11,12,13,14,15,17,18,19}
names = sorted(os.listdir(folder))
print(f"{'Img':>4}  {'Tilt':>6}  {'Proj':>3}  {'Groups':>6}  {'Blobs':>5}  {'Misfire':>7}  {'Valid%':>6}  Status")
print("-"*65)
for name in names:
    if not name.endswith('.pgm'): continue
    num = int(name.replace('capture_','').replace('.pgm',''))
    w,h,px = read_pgm_p5(os.path.join(folder,name))
    blobs = find_blobs(w,h,px,100)
    tilt, use_cx, ngrp, misfires, spacing = simulate(blobs)
    nb = len(blobs)
    valid_pct = 100.0*(nb-misfires)/nb
    proj_str = "CX" if use_cx else "RX"
    status = "BROKEN" if use_cx and num not in broken else ("fixed" if num in broken else "ok")
    print(f"  {num:3d}  {tilt:6.2f}d  {proj_str}  {ngrp:6d}  {nb:5d}  {misfires:7d}  {valid_pct:5.1f}%  [{status}]")
