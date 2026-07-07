import math

# Center of logo
cx, cy = 256, 216 # shifted up a bit more to balance
R = 120

angles = [-90, -30, 30, 90, 150, 210]
pts = []
for a in angles:
    rad = math.radians(a)
    x = cx + R * math.cos(rad)
    y = cy + R * math.sin(rad)
    pts.append((x, y))

# The three diamonds
d1 = [pts[0], pts[1], (cx, cy), pts[5]]
d2 = [(cx, cy), pts[1], pts[2], pts[3]]
d3 = [(cx, cy), pts[3], pts[4], pts[5]]

def scale_poly(poly, factor):
    # calc centroid
    avg_x = sum(p[0] for p in poly) / len(poly)
    avg_y = sum(p[1] for p in poly) / len(poly)
    
    new_poly = []
    for p in poly:
        nx = avg_x + factor * (p[0] - avg_x)
        ny = avg_y + factor * (p[1] - avg_y)
        new_poly.append((nx, ny))
    return new_poly

f = 0.82
sd1 = scale_poly(d1, f)
sd2 = scale_poly(d2, f)
sd3 = scale_poly(d3, f)

def to_str(poly):
    return " ".join(f"{p[0]:.1f},{p[1]:.1f}" for p in poly)

print(f'<polygon points="{to_str(sd1)}" fill="none" stroke="#ffffff" stroke-width="16" stroke-linejoin="round"/>')
print(f'<polygon points="{to_str(sd2)}" fill="none" stroke="#ffffff" stroke-width="16" stroke-linejoin="round"/>')
print(f'<polygon points="{to_str(sd3)}" fill="none" stroke="#ffffff" stroke-width="16" stroke-linejoin="round"/>')

