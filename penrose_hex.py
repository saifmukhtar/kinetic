import math

cx, cy = 256, 216
angles = [-90, -30, 30, 90, 150, 210]

def get_hex(R):
    pts = []
    for a in angles:
        rad = math.radians(a)
        pts.append((cx + R * math.cos(rad), cy + R * math.sin(rad)))
    return pts

h1 = get_hex(120)
h2 = get_hex(85)
h3 = get_hex(50)
h4 = get_hex(15)

def pt_str(pts):
    return " ".join(f"{p[0]:.1f},{p[1]:.1f}" for p in pts)

print('<g fill="none" stroke="#ffffff" stroke-width="4" stroke-linejoin="round" stroke-linecap="round" opacity="0.9">')

# Concentric hexagons
print(f'<polygon points="{pt_str(h1)}" />')
print(f'<polygon points="{pt_str(h2)}" />')
print(f'<polygon points="{pt_str(h3)}" />')
print(f'<polygon points="{pt_str(h4)}" />')

# Offset diagonal connections to create the impossible twisted look
for i in range(6):
    # Connect outer to mid (twisted by 1)
    p1 = h1[i]
    p2 = h2[(i+1)%6]
    print(f'<line x1="{p1[0]:.1f}" y1="{p1[1]:.1f}" x2="{p2[0]:.1f}" y2="{p2[1]:.1f}" />')
    
    # Connect mid to inner (twisted by 1)
    p1 = h2[i]
    p2 = h3[(i+1)%6]
    print(f'<line x1="{p1[0]:.1f}" y1="{p1[1]:.1f}" x2="{p2[0]:.1f}" y2="{p2[1]:.1f}" />')
    
    # Connect inner to core (twisted by 1)
    p1 = h3[i]
    p2 = h4[(i+1)%6]
    print(f'<line x1="{p1[0]:.1f}" y1="{p1[1]:.1f}" x2="{p2[0]:.1f}" y2="{p2[1]:.1f}" />')

    # Add a counter-twist for the wireframe blueprint illusion
    p1 = h1[i]
    p2 = h3[(i-1)%6]
    print(f'<line x1="{p1[0]:.1f}" y1="{p1[1]:.1f}" x2="{p2[0]:.1f}" y2="{p2[1]:.1f}" stroke-width="1.5" opacity="0.5"/>')
    
print('</g>')
