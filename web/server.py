#!/usr/bin/env python3
"""
Forensic AFIS Workstation Web Backend Server
Interfaces directly with the C Spatial Minutiae-Graph Indexing Engine.
Supports Live User Fingerprint Enrollment and Rotation-Invariant Matching.
Zero AI dependencies. Pure C-backend execution with microsecond forensic telemetry.
"""

import os
import sys
import json
import base64
import math
import time
import subprocess
import http.server
import socketserver
import urllib.parse
import cv2
import numpy as np

PORT = 8080
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "socofing_database.json")
WEB_DIR = os.path.join(BASE_DIR, "web")
BIN_CLI = os.path.join(BASE_DIR, "bin", "engine_cli.exe" if os.name == "nt" else "engine_cli")

sys.path.append(os.path.join(BASE_DIR, "scripts"))
from extract_minutiae import extract_fingerprint_features

def reload_database():
    global DATABASE_RECORDS, RECORD_DICT
    with open(DB_PATH, "r", encoding="utf-8") as f:
        DATABASE_RECORDS = json.load(f)
    RECORD_DICT = {r["id"]: r for r in DATABASE_RECORDS}

reload_database()

class AFISRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            self.send_json_response({
                "status": "ONLINE",
                "backend": "C11 Engine (Compiled with -O3)",
                "dataset": "Kaggle SOCOFing / Biometric Database",
                "total_records": len(DATABASE_RECORDS),
                "database_path": DB_PATH,
                "engine_binary": BIN_CLI
            })
        elif path == "/api/templates":
            reload_database()
            summary = [
                {
                    "id": r["id"],
                    "pattern_class": r["pattern_class"],
                    "minutiae_count": len(r["minutiae"]),
                    "has_image": os.path.exists(os.path.join(WEB_DIR, "images", f"{r['id']}.png")),
                    "has_skel": os.path.exists(os.path.join(WEB_DIR, "images", f"{r['id']}_skel.png"))
                }
                for r in DATABASE_RECORDS
            ]
            self.send_json_response({"templates": summary})
        elif path.startswith("/api/template/"):
            template_id = path.split("/")[-1]
            if template_id in RECORD_DICT:
                self.send_json_response(RECORD_DICT[template_id])
            else:
                self.send_error_response(404, f"Template {template_id} not found")
        elif path == "/api/benchmark":
            try:
                proc = subprocess.run(
                    [BIN_CLI, "benchmark", DB_PATH, "1"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = proc.stdout
                self.send_json_response({
                    "raw_output": output,
                    "returncode": proc.returncode
                })
            except Exception as e:
                self.send_error_response(500, f"Benchmark execution failure: {str(e)}")
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/query":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")
            try:
                query_payload = json.loads(post_data)
                
                if "id" in query_payload and query_payload["id"] in RECORD_DICT and "minutiae" not in query_payload:
                    query_record = RECORD_DICT[query_payload["id"]]
                else:
                    query_record = query_payload

                temp_query_path = os.path.join(BASE_DIR, "data", "_active_query.json")
                with open(temp_query_path, "w", encoding="utf-8") as f:
                    json.dump(query_record, f)

                proc = subprocess.run(
                    [BIN_CLI, "query", DB_PATH, temp_query_path],
                    capture_output=True,
                    text=True,
                    timeout=15
                )

                if proc.returncode != 0:
                    self.send_error_response(500, f"Engine execution error: {proc.stderr}")
                    return

                output = proc.stdout
                json_start = output.find("{")
                json_end = output.rfind("}")
                if json_start != -1 and json_end != -1:
                    json_str = output[json_start:json_end+1]
                    telemetry = json.loads(json_str)
                    self.send_json_response(telemetry)
                else:
                    self.send_error_response(500, f"Invalid engine JSON output: {output}")

            except Exception as e:
                self.send_error_response(400, f"Query processing failure: {str(e)}")

        elif path == "/api/enroll":
            # Live User Fingerprint Enrollment
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")
            try:
                payload = json.loads(post_data)
                enroll_id = payload.get("id", f"USER_LATENT_{int(time.time())}")
                enroll_id = "".join(c if c.isalnum() or c in "_-" else "_" for c in enroll_id)
                image_b64 = payload.get("image_base64", "")

                if "," in image_b64:
                    image_b64 = image_b64.split(",", 1)[1]

                img_bytes = base64.b64decode(image_b64)
                img_array = np.frombuffer(img_bytes, dtype=np.uint8)
                raw_img = cv2.imdecode(img_array, cv2.IMREAD_GRAYSCALE)

                if raw_img is None:
                    self.send_error_response(400, "Unable to decode fingerprint image file.")
                    return

                # Standardize to 375x288 if needed
                if raw_img.shape != (375, 288):
                    raw_img = cv2.resize(raw_img, (288, 375), interpolation=cv2.INTER_AREA)

                # Save raw upload image
                temp_raw_path = os.path.join(BASE_DIR, "data", f"_raw_enroll_{enroll_id}.png")
                cv2.imwrite(temp_raw_path, raw_img)

                # Run feature extraction pipeline
                rec, skel, enh = extract_fingerprint_features(temp_raw_path, max_minutiae=30)
                rec["id"] = enroll_id

                # Save web assets
                img_out_path = os.path.join(WEB_DIR, "images", f"{enroll_id}.png")
                skel_out_path = os.path.join(WEB_DIR, "images", f"{enroll_id}_skel.png")
                cv2.imwrite(img_out_path, enh)
                cv2.imwrite(skel_out_path, skel)

                # Save lightweight JSON feature vector (< 1 KB)
                temp_json_path = os.path.join(BASE_DIR, "data", f"_enroll_{enroll_id}.json")
                with open(temp_json_path, "w", encoding="utf-8") as f:
                    json.dump(rec, f, indent=2)

                raw_vector_size = len(json.dumps(rec, separators=(',', ':')).encode('utf-8'))

                # Invoke C engine dynamic enrollment (malloc structs, B-Tree, Kd-Tree, Graph)
                proc = subprocess.run(
                    [BIN_CLI, "enroll", DB_PATH, temp_json_path],
                    capture_output=True,
                    text=True,
                    timeout=15
                )

                if proc.returncode != 0:
                    self.send_error_response(500, f"C Engine Enrollment failed: {proc.stderr}")
                    return

                # Reload server database cache
                reload_database()

                endings = sum(1 for m in rec["minutiae"] if m["type"] == 0)
                bifurcs = sum(1 for m in rec["minutiae"] if m["type"] == 1)

                self.send_json_response({
                    "status": "ENROLLED_SUCCESSFULLY",
                    "id": enroll_id,
                    "pattern_class": rec["pattern_class"],
                    "minutiae_count": len(rec["minutiae"]),
                    "endings_count": endings,
                    "bifurcations_count": bifurcs,
                    "raw_vector_bytes": raw_vector_size,
                    "total_database_records": len(DATABASE_RECORDS),
                    "c_engine_output": proc.stdout
                })

            except Exception as e:
                self.send_error_response(400, f"Enrollment error: {str(e)}")

        elif path == "/api/rotate_probe":
            # Rotation-Invariant Verification Test Generator
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")
            try:
                payload = json.loads(post_data)
                template_id = payload.get("template_id", "")
                rotation_deg = float(payload.get("rotation_deg", 30.0))
                shift_x = float(payload.get("shift_x", 0.0))
                shift_y = float(payload.get("shift_y", 0.0))

                if template_id not in RECORD_DICT:
                    self.send_error_response(404, f"Template '{template_id}' not found in database.")
                    return

                orig = RECORD_DICT[template_id]
                rad = rotation_deg * (math.pi / 180.0)
                cos_a = math.cos(rad)
                sin_a = math.sin(rad)

                cx, cy = 144.0, 187.5
                rotated_minutiae = []

                for m in orig["minutiae"]:
                    ox = m["x"] - cx
                    oy = m["y"] - cy
                    rx = cos_a * ox - sin_a * oy + cx + shift_x
                    ry = sin_a * ox + cos_a * oy + cy + shift_y
                    rtheta = m["theta"] + rad
                    while rtheta > math.pi: rtheta -= 2 * math.pi
                    while rtheta < -math.pi: rtheta += 2 * math.pi

                    rotated_minutiae.append({
                        "x": round(float(rx), 1),
                        "y": round(float(ry), 1),
                        "theta": round(float(rtheta), 3),
                        "type": m["type"],
                        "quality": m.get("quality", 0.95)
                    })

                probe_id = f"PROBE_ROT_{template_id}_{int(rotation_deg)}"
                probe = {
                    "id": probe_id,
                    "pattern_class": orig["pattern_class"],
                    "minutiae": rotated_minutiae
                }

                # Rotate visual image as well
                orig_img_path = os.path.join(WEB_DIR, "images", f"{template_id}.png")
                if os.path.exists(orig_img_path):
                    orig_img = cv2.imread(orig_img_path)
                    rot_mat = cv2.getRotationMatrix2D((cx, cy), -rotation_deg, 1.0)
                    rot_mat[0, 2] += shift_x
                    rot_mat[1, 2] += shift_y
                    probe_img = cv2.warpAffine(orig_img, rot_mat, (288, 375), borderMode=cv2.BORDER_CONSTANT, borderValue=(0, 0, 0))
                    cv2.imwrite(os.path.join(WEB_DIR, "images", f"{probe_id}.png"), probe_img)

                temp_probe_path = os.path.join(BASE_DIR, "data", f"_{probe_id}.json")
                with open(temp_probe_path, "w", encoding="utf-8") as f:
                    json.dump(probe, f)

                # Query against C engine
                proc = subprocess.run(
                    [BIN_CLI, "query", DB_PATH, temp_probe_path],
                    capture_output=True,
                    text=True,
                    timeout=15
                )

                output = proc.stdout
                json_start = output.find("{")
                json_end = output.rfind("}")
                if json_start != -1 and json_end != -1:
                    json_str = output[json_start:json_end+1]
                    telemetry = json.loads(json_str)
                    telemetry["probe_record"] = probe
                    telemetry["requested_rotation_deg"] = rotation_deg
                    telemetry["requested_shift"] = [shift_x, shift_y]
                    self.send_json_response(telemetry)
                else:
                    self.send_error_response(500, f"Engine query failed: {output}")

            except Exception as e:
                self.send_error_response(400, f"Rotation probe error: {str(e)}")
        else:
            self.send_error_response(404, "Endpoint not found")

    def send_json_response(self, data, code=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_error_response(self, code, message):
        self.send_json_response({"error": message}, code=code)

def run_server():
    print(f"====================================================================")
    print(f" SPATIAL MINUTIAE-GRAPH AFIS WORKSTATION SERVER (MK-IV)")
    print(f"====================================================================")
    print(f" C Backend Binary   : {BIN_CLI}")
    print(f" Fingerprint Database: {DB_PATH} ({len(DATABASE_RECORDS)} templates)")
    print(f" Web Workstation URL : http://localhost:{PORT}")
    print(f" Live User Enrollment: ENABLED")
    print(f" Rotation-Invariance : ENABLED (Full 360-degree topological invariance)")
    print(f"====================================================================")
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), AFISRequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down AFIS Workstation server.")

if __name__ == "__main__":
    run_server()
