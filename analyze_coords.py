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
                area=len(xs)
                if area>=20: blobs.append((sum(xs)/area,sum(ys)/area,area))
    return blobs

folder = "C:/Program Files/Dot Analyzer/test images"
for name in ["capture_0002.pgm", "capture_0004.pgm"]:
    path=os.path.join(folder,name)
    print(f"\n=== {name} ===")
    w,h,px=read_pgm_p5(path)
    blobs=find_blobs(w,h,px,100)
    nb=len(blobs)

    # Print blob area distribution
    areas=sorted(b[2] for b in blobs)
    print(f"  blobs={nb}  area: min={areas[0]}  median={areas[nb//2]}  max={areas[-1]}  p95={areas[int(nb*0.95)]}")

    # Print first 30 blobs sorted by cx, to see if columns are visible
    by_cx = sorted(blobs, key=lambda b: b[0])
    print(f"  First 30 by cx (cx, cy, area):")
    for b in by_cx[:30]:
        print(f"    cx={b[0]:.1f}  cy={b[1]:.1f}  area={b[2]}")

    # Print cx histogram with small bins to see column structure
    cx_vals = [b[0] for b in blobs]
    cx_min,cx_max=min(cx_vals),max(cx_vals)
    bins=50; bsz=(cx_max-cx_min)/bins
    hist=[0]*bins
    for v in cx_vals: hist[min(int((v-cx_min)/bsz),bins-1)]+=1
    print(f"  cx histogram ({bsz:.1f}px bins, only showing non-zero):")
    nonzero=[(cx_min+i*bsz, c) for i,c in enumerate(hist) if c>0]
    for cx_start,c in nonzero[:20]:
        bar='#'*c
        print(f"    {cx_start:6.1f}: {bar} ({c})")
