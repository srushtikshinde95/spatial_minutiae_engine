import urllib.request
import json

def test_top_candidates():
    payload = json.dumps({
        "template_id": "CUSTOM_ENROLLED_USER_99",
        "rotation_deg": 60.0,
        "shift_x": 8.0,
        "shift_y": -14.0
    }).encode('utf-8')

    req = urllib.request.Request(
        "http://localhost:8080/api/rotate_probe",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode('utf-8'))
        for i, c in enumerate(res['top_candidates'][:3]):
            print(f"Rank {i+1}: {c['id']} | Score: {c['forensic_score']:.2f}% | Rot: {c['rotation_deg']:.2f} deg | Latency: {c['latency_us']:.1f} us")

if __name__ == '__main__':
    test_top_candidates()
