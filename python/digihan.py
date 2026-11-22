"""DigiHan ring codec, format v0.4 (the ring is unchanged since v0.3).

Layout (radii in mm, from center outward):
  [0, r_center]            free-zone center art (decoder-masked)
  (r_center, r_locator)    guard band, crossed only by 8 kissotai bridges
  [r_locator, r_loc_out]   inner locator ring (solid)
  (r_loc_out, r_band_in)   inner quiet gap
  [r_band_in, r_band_out]  data band: N concentric tracks of arc modules
  (r_band_out, r_rim_in)   outer quiet gap
  [r_rim_in, r_rim_out]    outer rim ring (solid) -- detection + scale anchor

Bit stream = 24-bit sync word || RS(n, 78) codeword bits, laid track-major
(innermost track first), ascending angle from the seal's angular origin.
"""

import numpy as np
from PIL import Image, ImageDraw, ImageFilter
from reedsolo import RSCodec, ReedSolomonError

# v0.2: 28-bit sync (0xE769C57), chosen for low cyclic autocorrelation
# (max sidelobe 4/28) and no run longer than 3 (long ink runs merge under
# blur). Width chosen so 28 + 8*(78+45) == 1012 == ring capacity exactly:
# every cell carries data, no blank arc, spare capacity spent on parity.
SYNC_BITS = np.array([1,1,1,0,0,1,1,1, 0,1,1,0,1,0,0,1,
                      1,1,0,0,0,1,0,1, 0,1,1,1], dtype=np.uint8)
PAYLOAD_BYTES = 78          # 624-bit DigiHan payload
# v0.3 (format freeze): bit 0 starts at 12 o'clock, under the key bridge, and the
# stream runs clockwise; the guard band around the center art is 1.2 mm (2 modules).
START_ANGLE = -np.pi / 2    # image angle of bit 0's cell start (y down, so clockwise)
GUARD_MM = 1.2              # center art edge -> locator ring (was 0.9 in v0.2)
NSYM_DEFAULT = 45           # RS(123,78): corrects 22 byte errors

class Geometry:
    def __init__(self, diameter_mm=40.0, n_tracks=5, module_mm=0.6,
                 r_center_frac=0.30, square=False):
        self.d = diameter_mm
        self.square = square
        self.frame_gap = 0.5      # white gap between circle rim and frame, mm
        self.frame_w = 1.1        # square frame stroke width, mm
        self.square_side = diameter_mm + 2*(self.frame_gap + self.frame_w)
        R = diameter_mm / 2.0
        self.r_rim_out  = R
        self.r_rim_in   = R - 0.9
        self.r_band_out = self.r_rim_in - 0.5
        self.n_tracks   = n_tracks
        self.module     = module_mm
        self.track_h    = module_mm * 1.15          # radial height per track
        self.r_band_in  = self.r_band_out - self.n_tracks * self.track_h
        self.r_loc_out  = self.r_band_in - 0.4
        self.r_locator  = self.r_loc_out - 0.7      # locator ring thickness 0.7
        self.r_center   = self.r_locator - GUARD_MM # guard band (v0.3: 1.2 mm)
        if self.r_center < R * 0.22:
            raise ValueError("geometry leaves too little center free-zone")
        self.track_r = [self.r_band_in + (i + 0.5) * self.track_h
                        for i in range(n_tracks)]
        self.cells = [int(np.floor(2*np.pi*r / module_mm)) for r in self.track_r]

    @property
    def capacity_bits(self):
        return sum(self.cells)

def build_stream(payload: bytes, nsym: int) -> np.ndarray:
    rs = RSCodec(nsym)
    cw = bytes(rs.encode(payload))
    bits = np.unpackbits(np.frombuffer(cw, dtype=np.uint8))
    return np.concatenate([SYNC_BITS, bits])

def parse_stream(bits: np.ndarray, nsym: int):
    body = bits[len(SYNC_BITS):]
    n = (PAYLOAD_BYTES + nsym) * 8
    body = body[:n]
    cw = np.packbits(body).tobytes()
    rs = RSCodec(nsym)
    decoded, _, errata = rs.decode(cw)
    return bytes(decoded), len(errata)

# ---------------------------------------------------------------- rendering

def render(geom: Geometry, stream: np.ndarray, dpmm=15.0,
           center_mode="dense", ink=0, paper=255, cell="arc",
           bridge="rect") -> Image.Image:
    """Rasterize the seal. dpmm = pixels per mm (15 ~= 381 dpi)."""
    ext = geom.square_side if geom.square else geom.d
    S = int(np.ceil(ext * dpmm)) + 8
    c = S / 2.0
    img = Image.new("L", (S, S), paper)
    dr = ImageDraw.Draw(img)
    mm = lambda v: v * dpmm

    def ring(r_in, r_out):
        dr.ellipse([c-mm(r_out), c-mm(r_out), c+mm(r_out), c+mm(r_out)],
                   fill=ink)
        dr.ellipse([c-mm(r_in), c-mm(r_in), c+mm(r_in), c+mm(r_in)],
                   fill=paper)

    if geom.square:
        h_out = mm(geom.square_side / 2)
        h_in = h_out - mm(geom.frame_w)
        dr.rectangle([c-h_out, c-h_out, c+h_out, c+h_out], fill=ink)
        dr.rectangle([c-h_in, c-h_in, c+h_in, c+h_in], fill=paper)
    ring(geom.r_rim_in, geom.r_rim_out)          # outer rim
    # data band: each cell is a stroked arc segment (annular sector)
    k = 0
    for t in range(geom.n_tracks):
        r_in  = geom.r_band_in + t * geom.track_h + 0.06
        r_out = r_in + geom.track_h - 0.12
        w = max(1, int(round(mm(r_out - r_in))))
        bbox = [c-mm(r_out), c-mm(r_out), c+mm(r_out), c+mm(r_out)]
        C = geom.cells[t]
        r_mid = (r_in + r_out) / 2.0
        r_dot = min(geom.module, r_out - r_in) * 0.46
        for i in range(C):
            bit = stream[k] if k < len(stream) else 0
            if bit:
                if cell == "dot":
                    a = START_ANGLE + 2*np.pi * (i + 0.43) / C
                    x = c + mm(r_mid) * np.cos(a)
                    y = c + mm(r_mid) * np.sin(a)
                    rp = mm(r_dot)
                    dr.ellipse([x-rp, y-rp, x+rp, y+rp], fill=ink)
                else:
                    a0 = np.degrees(START_ANGLE) + 360.0 * i / C
                    a1 = a0 + 360.0 * 0.86 / C      # 14% angular gap
                    dr.arc(bbox, a0, a1, fill=ink, width=w)
            k += 1
    ring(geom.r_locator, geom.r_loc_out)         # inner locator ring
    # kissotai bridges: 8 tabs across guard band, key (12 o'clock) double-wide
    for j in range(8):
        ang = np.deg2rad(90 - j * 45)            # image y-down: 12h = +90 math
        w = mm(1.6) if j == 0 else mm(0.8)
        r0, r1 = mm(geom.r_center - 0.2), mm(geom.r_locator + 0.3)
        ux, uy = np.cos(ang), -np.sin(ang)
        px, py = -uy, ux
        if bridge == "tri_in":       # base on the locator ring, point toward center
            pts = [(c + r1*ux + w*px, c + r1*uy + w*py),
                   (c + r1*ux - w*px, c + r1*uy - w*py),
                   (c + r0*ux, c + r0*uy)]
        elif bridge == "tri_out":    # base at the center edge, point toward the ring
            pts = [(c + r0*ux + w*px, c + r0*uy + w*py),
                   (c + r0*ux - w*px, c + r0*uy - w*py),
                   (c + r1*ux, c + r1*uy)]
        else:                        # "rect": the default
            pts = [(c + r0*ux + w/2*px, c + r0*uy + w/2*py),
                   (c + r1*ux + w/2*px, c + r1*uy + w/2*py),
                   (c + r1*ux - w/2*px, c + r1*uy - w/2*py),
                   (c + r0*ux - w/2*px, c + r0*uy - w/2*py)]
        dr.polygon(pts, fill=ink)
    # center art
    if center_mode == "dense":
        dr.ellipse([c-mm(geom.r_center-0.3)]*2 +
                   [c+mm(geom.r_center-0.3)]*2, fill=ink)
    elif center_mode == "text":
        rng = np.random.default_rng(7)
        for _ in range(60):
            x, y = rng.uniform(-geom.r_center*0.75, geom.r_center*0.75, 2)
            if x*x + y*y < (geom.r_center*0.8)**2:
                w_, h_ = rng.uniform(0.4, 1.6, 2)
                dr.rectangle([c+mm(x), c+mm(y), c+mm(x+w_), c+mm(y+h_)],
                             fill=ink)
    # center_mode == "empty": nothing
    return img

# ---------------------------------------------------------------- decoding

def _rim_edge_points(a, cx, cy, rmax):
    ink = a < 128
    ang = np.linspace(0, 2*np.pi, 720, endpoint=False)
    rr = np.arange(rmax, rmax*0.4, -1.0)
    pts = []
    for t in ang:
        x = cx + rr * np.cos(t); y = cy + rr * np.sin(t)
        ok = (x >= 0) & (x < a.shape[1]-1) & (y >= 0) & (y < a.shape[0]-1)
        xi, yi = x[ok].astype(int), y[ok].astype(int)
        hit = np.nonzero(ink[yi, xi])[0]
        if len(hit):
            pts.append((x[ok][hit[0]], y[ok][hit[0]]))
    return np.array(pts)

def _fit_ellipse(P):
    """Algebraic conic LSQ -> (center(2,), M(2,2)) mapping unit circle -> rim."""
    mu = P.mean(0); s = P.std()
    Q = (P - mu) / s
    x, y = Q[:, 0], Q[:, 1]
    D = np.c_[x*x, x*y, y*y, x, y, np.ones_like(x)]
    _, _, Vt = np.linalg.svd(D, full_matrices=False)
    a_, b_, c_, d_, e_, f_ = Vt[-1]
    A2 = np.array([[a_, b_/2], [b_/2, c_]])
    ctr_n = np.linalg.solve(A2, [-d_/2, -e_/2])
    g = -(a_*ctr_n[0]**2 + b_*ctr_n[0]*ctr_n[1] + c_*ctr_n[1]**2
          + d_*ctr_n[0] + e_*ctr_n[1] + f_)
    lam, V = np.linalg.eigh(A2 / g)
    if np.any(lam <= 0):
        raise ReedSolomonError("rim conic is not an ellipse")
    Mn = V @ np.diag(1.0/np.sqrt(lam)) @ V.T
    return ctr_n * s + mu, Mn * s

def _find_square(a):
    """Locate the square frame: (center(2,), half_side_px, phi_rad)."""
    ink = a < 128
    ys, xs = np.nonzero(ink)
    ctr = np.array([xs.mean(), ys.mean()])
    for it in range(3):
        P = _rim_edge_points(a, ctr[0], ctr[1], np.hypot(*a.shape) / 2.0)
        Q = P - P.mean(0)
        best = None
        for phi in np.deg2rad(np.arange(0, 90, 0.5)):
            R = np.array([[np.cos(phi), np.sin(phi)],
                          [-np.sin(phi), np.cos(phi)]])
            W = Q @ R.T
            w = W[:, 0].max() - W[:, 0].min()
            h = W[:, 1].max() - W[:, 1].min()
            if best is None or w*h < best[0]:
                mid = np.array([(W[:,0].max()+W[:,0].min())/2,
                                (W[:,1].max()+W[:,1].min())/2])
                best = (w*h, phi, (w+h)/4.0, mid @ R + P.mean(0))
        _, phi, half, nctr = best
        moved = np.hypot(*(nctr - ctr))
        ctr = nctr
        if moved < 0.5:
            break
    return ctr, half, phi

def _rim_edge_points_skip_frame(a, cx, cy, rmax):
    """Per ray: skip the first ink run (square frame), take next ink onset."""
    ink = a < 128
    ang = np.linspace(0, 2*np.pi, 720, endpoint=False)
    rr = np.arange(rmax, rmax*0.3, -1.0)
    pts = []
    for t in ang:
        x = cx + rr * np.cos(t); y = cy + rr * np.sin(t)
        ok = (x >= 0) & (x < a.shape[1]-1) & (y >= 0) & (y < a.shape[0]-1)
        xi, yi = x[ok].astype(int), y[ok].astype(int)
        prof = ink[yi, xi]
        i = np.argmax(prof)
        if not prof[i]:
            continue
        j = i                                   # traverse frame run
        while j < len(prof) and prof[j]:
            j += 1
        k = j                                   # cross the gap
        while k < len(prof) and not prof[k]:
            k += 1
        if k < len(prof):
            pts.append((x[ok][k], y[ok][k]))
    return np.array(pts)

def _find_rim_in_square(a, geom):
    """Square profile: find frame, then fit the circular rim inside it."""
    ctr, half, _phi = _find_square(a)
    M = None
    for it in range(3):
        rmax = (np.hypot(*a.shape)/2.0 if M is None
                else np.sqrt(abs(np.linalg.det(M))) * 1.6)
        P = _rim_edge_points_skip_frame(a, ctr[0], ctr[1], rmax)
        if len(P) < 200:
            raise ReedSolomonError("rim not found inside frame")
        nctr, M = _fit_ellipse(P)
        moved = np.hypot(*(nctr - ctr))
        ctr = nctr
        if moved < 0.3:
            break
    return ctr, M

def _find_rim(a: np.ndarray):
    """Return (center(2,), M(2,2)): iterated raycast + ellipse fit.
    M maps the unit circle to the rim's outer edge in image px."""
    ink = a < 128
    ys, xs = np.nonzero(ink)
    ctr = np.array([xs.mean(), ys.mean()])
    M = None
    for it in range(4):
        rmax = min(a.shape)/2.0 if M is None else np.sqrt(abs(np.linalg.det(M)))*1.15
        P = _rim_edge_points(a, ctr[0], ctr[1], rmax)
        nctr, M = _fit_ellipse(P)
        moved = np.hypot(*(nctr - ctr))
        ctr = nctr
        if moved < 0.3:
            break
    return ctr, M

def _sample(a, cx, cy, r_px, ang, patch=0.0):
    """Bilinear sample; if patch>0, average 5 points spread by `patch` px."""
    def bil(x, y):
        x = np.clip(x, 0, a.shape[1]-1.001); y = np.clip(y, 0, a.shape[0]-1.001)
        x0 = x.astype(int); y0 = y.astype(int)
        fx, fy = x - x0, y - y0
        return (a[y0, x0]*(1-fx)*(1-fy) + a[y0, x0+1]*fx*(1-fy) +
                a[y0+1, x0]*(1-fx)*fy + a[y0+1, x0+1]*fx*fy)
    x = cx + r_px*np.cos(ang); y = cy + r_px*np.sin(ang)
    v = bil(x, y)
    if patch > 0:
        for dx, dy in ((patch,0), (-patch,0), (0,patch), (0,-patch)):
            v = v + bil(x+dx, y+dy)
        v = v / 5.0
    return v

def _find_locator(a, ctr1, M1, geom):
    """Fit the inner locator ring's outer edge as a second ellipse."""
    Minv = np.linalg.inv(M1)
    rho_hi = (geom.r_band_in - 0.05) / geom.r_rim_out   # inside inner quiet gap
    rho_lo = (geom.r_center + 0.1) / geom.r_rim_out
    n_ang = 360
    pts = []
    exp_w = (geom.r_loc_out - geom.r_locator) / geom.r_rim_out
    for k in range(n_ang):
        alpha = 2*np.pi * k / n_ang
        u = np.array([np.cos(alpha), np.sin(alpha)])
        rhos = np.linspace(rho_hi, rho_lo, 48)
        xy = ctr1[None, :] + rhos[:, None] * (M1 @ u)[None, :]
        x = np.clip(xy[:, 0], 0, a.shape[1]-1).astype(int)
        y = np.clip(xy[:, 1], 0, a.shape[0]-1).astype(int)
        prof = a[y, x]
        th = (prof.min() + prof.max()) / 2.0
        if prof.max() - prof.min() < 40:
            continue                          # no contrast on this ray
        ink = prof < th
        # first ink run marching inward = locator (bridges make some rays odd)
        i = np.argmax(ink)
        if not ink[i]:
            continue
        j = i
        while j < len(ink) and ink[j]:
            j += 1
        w = abs(rhos[min(j, len(rhos)-1)] - rhos[i])
        if w > exp_w * 3.5:                   # merged with bridge/center: skip
            continue
        pts.append(xy[i])
    if len(pts) < 90:
        raise ReedSolomonError("locator ring not found")
    return _fit_ellipse(np.array(pts))

def _sample_lerp(a, anch, r_mm, ang, geom, patch=0.0):
    """Sample interpolating between locator-edge and rim-edge ellipses."""
    (ctr1, M1), (ctr2, M2) = anch             # rim, locator
    u = np.stack([np.cos(ang), np.sin(ang)])
    p_rim = (M1 @ u).T + ctr1
    p_loc = (M2 @ u * (1.0)).T + ctr2
    f = (r_mm - geom.r_loc_out) / (geom.r_rim_out - geom.r_loc_out)
    xy = p_loc + f * (p_rim - p_loc)
    def bil(x, y):
        x = np.clip(x, 0, a.shape[1]-1.001); y = np.clip(y, 0, a.shape[0]-1.001)
        x0 = x.astype(int); y0 = y.astype(int)
        fx, fy = x - x0, y - y0
        return (a[y0, x0]*(1-fx)*(1-fy) + a[y0, x0+1]*fx*(1-fy) +
                a[y0+1, x0]*(1-fx)*fy + a[y0+1, x0+1]*fx*fy)
    v = bil(xy[:, 0], xy[:, 1])
    if patch > 0:
        for dx, dy in ((patch,0), (-patch,0), (0,patch), (0,-patch)):
            v = v + bil(xy[:, 0]+dx, xy[:, 1]+dy)
        v = v / 5.0
    return v

def _band_threshold(vals):
    lo, hi = np.percentile(vals, 8), np.percentile(vals, 92)
    return (lo + hi) / 2.0

BRIDGE_ANGLES = np.deg2rad(-90 + 45*np.arange(8))   # seal-frame image angles

def _find_bridges_blind(a, anch, geom, patch):
    """Scan the guard band for the 8 bridges without knowing orientation.
    Returns (theta0_est, cal) or None. Key bridge (widest) marks 12 o'clock."""
    r_g = (geom.r_center + geom.r_locator) / 2.0
    N = 1440
    ang = np.arange(N) * (2*np.pi / N)
    v = _sample_lerp(a, anch, r_g, ang, geom, patch)
    th = _band_threshold(v)
    ink = (v < th)
    if ink.sum() < 8 or ink.sum() > N//3:
        return None
    gap = int(np.argmin(ink))
    ink_r = np.roll(ink, -gap)
    v_r = np.roll(v, -gap)
    runs = []
    i = 0
    while i < N:
        if ink_r[i]:
            j = i
            while j < N and ink_r[j]:
                j += 1
            w = np.clip(th - v_r[i:j], 0, None)
            idx = np.arange(i, j)
            cen = (idx * w).sum() / max(w.sum(), 1e-9)
            runs.append((((cen + gap) % N) * 2*np.pi / N, j - i))
            i = j
        else:
            i += 1
    runs = [r for r in runs if 2 <= r[1] <= N*10//360]
    if len(runs) < 6:
        return None
    runs.sort(key=lambda r: -r[1])
    key_ang = runs[0][0]
    if len(runs) > 1 and runs[0][1] < runs[1][1] * 1.25:
        return None                            # key not clearly distinct
    theta0 = np.mod(key_ang - BRIDGE_ANGLES[0], 2*np.pi)  # key = seal -90deg
    best = {}                                  # slot -> (|rel|, angle, offset): one reading per slot
    for (ra, rw) in runs[:12]:
        rel = np.mod(ra - theta0 - BRIDGE_ANGLES + np.pi, 2*np.pi) - np.pi
        j = int(np.argmin(np.abs(rel)))
        if abs(rel[j]) < np.deg2rad(12) and (j not in best or abs(rel[j]) < best[j][0]):
            exp = np.mod(BRIDGE_ANGLES[j] + theta0, 2*np.pi)
            best[j] = (abs(rel[j]), exp, float(np.mod(ra - exp + np.pi, 2*np.pi) - np.pi))
    nodes = _plausible([(e, d) for (_, e, d) in best.values()])
    if nodes is None or len(nodes) < 5:
        return None
    return theta0, (np.array([e for e, _ in nodes]), np.array([d for _, d in nodes]))


def _plausible(nodes, tol_deg=2.5):
    """v0.3: keep bridge readings within tol of the median offset. A real bridge sits
    within ~2 deg of its slot; a stray ink run (often a signature stroke) taken as a
    bridge sits 4-11 deg off and would bend the whole angular calibration."""
    if not nodes:
        return None
    d = np.array([dd for _, dd in nodes])
    med = float(np.median(d))
    return [(e, dd) for (e, dd) in nodes if abs(dd - med) <= np.deg2rad(tol_deg)]

def _bridge_calibration(a, anch, geom, theta0, patch):
    """Measure each kissotai bridge's actual angle; return periodic correction
    delta(alpha) as (node_angles, node_offsets), or None if too few found."""
    r_g = (geom.r_center + geom.r_locator) / 2.0
    nodes_a, nodes_d = [], []
    for j, bj in enumerate(BRIDGE_ANGLES):
        exp = bj + theta0
        win = np.deg2rad(10)
        ang = exp + np.linspace(-win, win, 81)
        v = _sample_lerp(a, anch, r_g, ang, geom, patch)
        th = _band_threshold(v)
        ink = v < th
        if ink.sum() < 3 or ink.sum() > 60:
            continue                       # bridge not cleanly isolated
        w = np.clip(th - v, 0, None)
        cen = (ang * w).sum() / w.sum()
        nodes_a.append(np.mod(exp, 2*np.pi))
        nodes_d.append(np.mod(cen - exp + np.pi, 2*np.pi) - np.pi)
    nodes = _plausible(list(zip(nodes_a, nodes_d)))
    if nodes is None or len(nodes) < 5:
        return None
    return np.array([e for e, _ in nodes]), np.array([d for _, d in nodes])

def _apply_cal(ang, cal):
    if cal is None:
        return ang
    na, nd = cal
    order = np.argsort(na)
    na, nd = na[order], nd[order]
    na_ext = np.r_[na, na[0] + 2*np.pi]
    nd_ext = np.r_[nd, nd[0]]
    aa = np.mod(ang - na[0], 2*np.pi) + na[0]
    return ang + np.interp(aa, na_ext, nd_ext)

def decode(img: Image.Image, geom: Geometry, nsym: int):
    a = np.asarray(img.convert("L"), dtype=np.float32)
    if geom.square:
        ctr1, M1 = _find_rim_in_square(a, geom)
    else:
        ctr1, M1 = _find_rim(a)
    try:
        ctr2, M2 = _find_locator(a, ctr1, M1, geom)
    except ReedSolomonError:
        ctr2, M2 = ctr1, M1 * (geom.r_loc_out / geom.r_rim_out)  # fallback
    anch = ((ctr1, M1), (ctr2, M2))
    scale = np.sqrt(abs(np.linalg.det(M1))) / geom.r_rim_out   # avg px per mm
    patch = max(0.0, geom.module * scale * 0.22)
    L = len(SYNC_BITS)
    SUB = 3
    C0 = geom.cells[0]
    pitch = 2*np.pi / C0
    sync_sign = np.where(SYNC_BITS == 1, 1.0, -1.0)

    def frac_refine(theta_base, cal):
        best_s, best_f = -1e18, 0.0
        for frac in np.linspace(-1.5, 1.5, 61):
            ang = theta_base + (frac + np.arange(L) + 0.43) * pitch
            v = _sample_lerp(a, anch, geom.track_r[0],
                             _apply_cal(ang, cal), geom, patch)
            th = _band_threshold(v)
            s = ((th - v) * sync_sign).sum()
            if s > best_s:
                best_s, best_f = s, frac
        return theta_base + best_f * pitch

    def sync_verify(theta, cal):
        ang = theta + (np.arange(L) + 0.43) * pitch
        v = _sample_lerp(a, anch, geom.track_r[0],
                         _apply_cal(ang, cal), geom, patch)
        b = (v < _band_threshold(v)).astype(np.uint8)
        return (b == SYNC_BITS).sum()

    candidates = []                            # (theta0, cal)
    blind = _find_bridges_blind(a, anch, geom, patch)
    if blind is not None:
        tb, cal_b = blind
        t_ref = frac_refine(tb + START_ANGLE, cal_b)   # v0.3: bit 0 starts under the key bridge
        if sync_verify(t_ref, cal_b) >= L - 4:
            candidates.append((t_ref, cal_b))
    # always also derive a sync-search candidate (independent lock)
    def coarse_sync():
        sub_ang = (np.arange(C0 * SUB) / SUB + 0.43) * pitch
        v = _sample_lerp(a, anch, geom.track_r[0], sub_ang, geom, patch)
        th = _band_threshold(v)
        b = (v < th).astype(np.uint8)
        bb, bo = -1, 0
        for off in range(C0 * SUB):
            idx = (off + np.arange(L) * SUB) % (C0 * SUB)
            m = (b[idx] == SYNC_BITS).sum()
            if m > bb:
                bb, bo = m, off
        return bb, bo / SUB
    best, best_off = coarse_sync()
    if best >= L - 4:
        t0 = frac_refine(best_off * pitch, None)
        cal = _bridge_calibration(a, anch, geom, t0 - START_ANGLE, patch)
        t0 = frac_refine(t0, cal) if cal is not None else t0
        if not candidates or abs(np.mod(t0 - candidates[0][0] + np.pi,
                                        2*np.pi) - np.pi) > 0.25 * pitch:
            candidates.append((t0, cal))
    if not candidates:
        raise ReedSolomonError("sync not found")
    # retry ladder: sampling-patch x threshold-bias x radial micro-offset
    attempts = [(patch, 0.0, 0.0), (0.0, 0.0, 0.0), (patch, -8.0, 0.0),
                (patch, +8.0, 0.0), (0.0, -12.0, 0.0), (0.0, +12.0, 0.0),
                (patch, 0.0, +0.15), (patch, 0.0, -0.15),
                (0.0, -12.0, +0.15), (0.0, -12.0, -0.15)]
    last_err = None
    for (theta_c, cal) in candidates:
        for use_cal in ((True, False) if cal is not None else (False,)):
            # v0.3: the no-calibration retry refines its own start angle; the angle
            # refined under a bad calibration would carry the bad calibration's error
            theta0 = theta_c if use_cal else frac_refine(theta_c, None)
            for (p, tb, dr_) in attempts:
                out = []
                for t in range(geom.n_tracks):
                    C = geom.cells[t]
                    rmm = geom.track_r[t] + dr_ * geom.module
                    ang = theta0 + (np.arange(C) + 0.43) * (2*np.pi / C)
                    if use_cal:
                        ang = _apply_cal(ang, cal)
                    vals = _sample_lerp(a, anch, rmm, ang, geom, p)
                    out.append((vals < _band_threshold(vals) + tb)
                               .astype(np.uint8))
                bits = np.concatenate(out)
                try:
                    return parse_stream(bits, nsym)
                except ReedSolomonError as e:
                    last_err = e
    raise last_err
