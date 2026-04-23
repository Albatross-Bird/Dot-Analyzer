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

RATIO_THRESH = 1.4   # was 2.0 — accept weaker bimodal signals

def bimodal(vals):
    sv = sorted(vals)
    n = len(sv)
    gaps = [sv[i+1]-sv[i] for i in range(n-1)]
    gs = sorted(gaps)
    best_ratio=0.0; best_k=-1
    for k in range(len(gs)-1):
        if gs[k] < 0.5: continue
        r = gs[k+1]/gs[k]
        if r > best_ratio: best_ratio=r; best_k=k
    if best_k >= 0 and best_ratio > RATIO_THRESH:
        thresh = (gs[best_k]+gs[best_k+1])*0.5
    else:
        thresh = gs[-1]*2.0   # fallback: single group
    # Count groups
    cur = 0
    for g in [sv[i+1]-sv[i] for i in range(n-1)]:
        if g > thresh: cur += 1
    return best_ratio, thresh, cur+1

def test_best_approach(blobs):
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

    cx_ratio, cx_thresh, cx_groups = bimodal(cx_arr)
    rx_ratio, rx_thresh, rx_groups = bimodal(rx)

    # Use whichever gives better bimodal signal
    if cx_ratio >= rx_ratio:
        winner, ratio, thresh, groups = "CX", cx_ratio, cx_thresh, cx_groups
    else:
        winner, ratio, thresh, groups = "RX", rx_ratio, rx_thresh, rx_groups
    return winner, math.degrees(t), ratio, thresh, groups, cx_ratio, rx_ratio, cx_groups, rx_groups

folder = "C:/Program Files/Dot Analyzer/test images"
broken = {4,5,7,8,9,10,11,12,13,14,15,17,18,19}
names = sorted(os.listdir(folder))
print(f"RATIO_THRESH={RATIO_THRESH}")
print("Image  Tilt   Winner  Ratio  Thresh  Groups  cx:(r,g)  rx:(r,g)   [Status]")
print("-"*75)
for name in names:
    if not name.endswith('.pgm'): continue
    num = int(name.replace('capture_','').replace('.pgm',''))
    path=os.path.join(folder,name)
    w,h,px=read_pgm_p5(path)
    blobs=find_blobs(w,h,px,100)
    winner, tilt, ratio, thresh, groups, cx_r, rx_r, cx_g, rx_g = test_best_approach(blobs)
    expected_broken = num in broken
    is_bad = (groups == 1 and len(blobs) > 10)
    if expected_broken and not is_bad: status = "FIXED"
    elif expected_broken and is_bad: status = "STILL_BROKEN"
    elif not expected_broken and is_bad and len(blobs) > 10: status = "NEWLY_BROKEN"
    else: status = "OK"
    print(f"  {num:3d}  {tilt:5.2f}d  {winner}  r={ratio:.2f}  t={thresh:6.2f}  g={groups:3d}  "
          f"cx:({cx_r:.2f},{cx_g:3d}) rx:({rx_r:.2f},{rx_g:3d})  [{status}]")
