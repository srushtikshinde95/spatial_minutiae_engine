import json
import math
import subprocess

def test_rotation(angle_deg=35.0, shift_x=15.0, shift_y=-12.0):
    with open('data/query_1_1_left_real_ZK9500.json') as f:
        orig = json.load(f)

    rad = angle_deg * (math.pi / 180.0)
    cos_a = math.cos(rad)
    sin_a = math.sin(rad)

    cx, cy = 144.0, 187.5
    rotated_minutiae = []

    for m in orig['minutiae']:
        ox = m['x'] - cx
        oy = m['y'] - cy
        rx = cos_a * ox - sin_a * oy + cx + shift_x
        ry = sin_a * ox + cos_a * oy + cy + shift_y
        rtheta = m['theta'] + rad
        while rtheta > math.pi: rtheta -= 2 * math.pi
        while rtheta < -math.pi: rtheta += 2 * math.pi

        rotated_minutiae.append({
            'x': round(rx, 1),
            'y': round(ry, 1),
            'theta': round(rtheta, 3),
            'type': m['type'],
            'quality': m['quality']
        })

    probe = {
        'id': f"PROBE_ROT_{int(angle_deg)}DEG",
        'pattern_class': orig['pattern_class'],
        'minutiae': rotated_minutiae
    }

    probe_path = f"data/_probe_rot_{int(angle_deg)}deg.json"
    with open(probe_path, 'w') as f:
        json.dump(probe, f, indent=2)

    res = subprocess.run(
        ['bin/engine_cli.exe', 'query', 'data/socofing_database.json', probe_path],
        capture_output=True, text=True
    )
    data = json.loads(res.stdout)
    top = data['top_candidates'][0]
    print(f"Angle: {angle_deg:+6.1f} deg | Match: {top['id']} | Score: {top['forensic_score']:6.2f}% | Detected Rot: {top['rotation_deg']:+6.2f} deg | RMSE: {top['spatial_rmse']:4.2f} px | Matched: {top['matched_minutiae']}/30")

if __name__ == '__main__':
    print("========================================================================================")
    print(" MULTI-ANGLE ROTATION-INVARIANCE BENCHMARK TEST (PURE C TIER-3 MINUTIAE GRAPH)")
    print("========================================================================================")
    for ang in [15.0, 30.0, 45.0, 60.0, 90.0, 120.0, 180.0, -45.0, -90.0]:
        test_rotation(ang, shift_x=10.0, shift_y=-8.0)
    print("========================================================================================")
