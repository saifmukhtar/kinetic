import math

# Center
cx, cy = 256, 256
R = 110 # radius

# Pointy top hexagon (starts at 30 degrees or -90 for absolute top)
# A pointy top hexagon has vertices at -90, -30, 30, 90, 150, 210 degrees
# Let's use angles: -90, -30, 30, 90, 150, 210 (in degrees) -> Wait, -90 is top.
angles_deg = [-90, -30, 30, 90, 150, 210]
pts = []
for a in angles_deg:
    rad = math.radians(a)
    x = cx + R * math.cos(rad)
    y = cy + R * math.sin(rad)
    pts.append(f"{x:.1f},{y:.1f}")

points_str = " ".join(pts)

svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="16" stdDeviation="24" flood-color="#4f46e5" flood-opacity="0.45"/>
    </filter>
  </defs>
  
  <rect x="56" y="56" width="400" height="400" rx="104" fill="#4f46e5" filter="url(#shadow)"/>
  
  <polygon points="{points_str}" fill="none" stroke="#ffffff" stroke-width="28" stroke-linejoin="round" stroke-linecap="round"/>
</svg>
"""

with open("kinetic-logo.svg", "w") as f:
    f.write(svg)
print("SVG generated")
