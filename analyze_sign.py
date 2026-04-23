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

def count_groups(rx_vals, gap_thresh):
    sv = sorted(rx_vals)
    n = len(sv); g = 1
    for i in range(n-1):
        if sv[i+1]-sv[i] > gap_thresh: g += 1
    return g

def test_formula(blobs, sign_cy, label):
    nb = len(blobs)
    cx_arr = [b[0] for b in blobs]; cy_arr = [b[1] for b in blobs]
    mx=sum(cx_arr)/nb; my=sum(cy_arr)/nb
    cxx=cyy=cxy=0.0
    for cx,cy in zip(cx_arr,cy_arr):
        dx=cx-mx; dy=cy-my; cxx+=dx*dx; cyy+=dy*dy; cxy+=dx*dy
    t = 0.5*math.atan2(2.0*cxy, cxx-cyy)
    if t > math.pi/4: t -= math.pi/2
    if t < -math.pi/4: t += math.pi/2
    ct = math.cos(t); st = math.sin(t)
    # sign_cy: +1 for original code (rx = cx*ct + cy*st)
    #          -1 for candidate fix (rx = cx*ct - cy*st)
    rx = [cx*ct + sign_cy*cy*st for cx,cy in zip(cx_arr,cy_arr)]
    sv = sorted(rx)
    gaps = [sv[i+1]-sv[i] for i in range(nb-1)]
    gs = sorted(gaps)
    # bimodal detection
    best_ratio=0.0; best_k=-1
    for k in range(len(gs)-1):
        if gs[k]<0.5: continue
        r=gs[k+1]/gs[k]
        if r>best_ratio: best_ratio=r; best_k=k
    if best_k>=0 and best_ratio>2.0:
        thresh=(gs[best_k]+gs[best_k+1])*0.5
    else:
        thresh=gs[-1]*2.0
    ngroups=count_groups(rx, thresh)
    print(f"  {label}: tilt={math.degrees(t):.2f}d  rx_span={max(rx)-min(rx):.0f}  "
          f"max_gap={gs[-1]:.2f}  best_ratio={best_ratio:.2f}  thresh={thresh:.2f}  groups={ngroups}")
    # Print rx histogram (20 bins)
    rx_min,rx_max=min(rx),max(rx)
    bins=20; bsz=(rx_max-rx_min)/bins
    hist=[0]*bins
    for v in rx: hist[min(int((v-rx_min)/bsz),bins-1)]+=1
    sparse=[f"{rx_min+i*bsz:.0f}:{c}" for i,c in enumerate(hist) if c>0]
    print(f"    hist: {' | '.join(sparse[:12])}")

folder = "C:/Program Files/Dot Analyzer/test images"
for name in ["capture_0002.pgm","capture_0004.pgm","capture_0011.pgm","capture_0016.pgm"]:
    path=os.path.join(folder,name)
    print(f"\n=== {name} ===")
    w,h,px=read_pgm_p5(path)
    blobs=find_blobs(w,h,px,100)
    print(f"  {len(blobs)} blobs")
    test_formula(blobs, +1, "CURRENT  rx=cx*cos(t)+cy*sin(t)")
    test_formula(blobs, -1, "CANDIDATE rx=cx*cos(t)-cy*sin(t)")
