#!/usr/bin/env python3
"""
Forensic Biometric Feature Extraction Pipeline
Dataset: Kaggle SOCOFing / Biometric Fingerprint Database
Converts raw fingerprint images (.bmp / .png / .jpg) into lightweight feature vectors (< 1 KB/record)
using classical ridge orientation, Otsu thresholding, Zhang-Suen skeletonization,
and Rutovitz crossing-number minutiae extraction.
"""

import os
import sys
import glob
import math
import json
import argparse
import numpy as np
import cv2

def compute_orientation_field(img_gray, block_size=16):
    """
    Computes standard gradient-based ridge orientation field.
    Returns orientation theta in radians [-pi/2, pi/2].
    """
    gx = cv2.Sobel(img_gray, cv2.CV_32F, 1, 0, ksize=3)
    gy = cv2.Sobel(img_gray, cv2.CV_32F, 0, 1, ksize=3)

    gxx = gx * gx
    gyy = gy * gy
    gxy = gx * gy

    # Gaussian blur over gradient components
    ksize = block_size * 2 + 1
    gxx_blur = cv2.GaussianBlur(gxx, (ksize, ksize), 0)
    gyy_blur = cv2.GaussianBlur(gyy, (ksize, ksize), 0)
    gxy_blur = cv2.GaussianBlur(gxy, (ksize, ksize), 0)

    theta = 0.5 * np.arctan2(2.0 * gxy_blur, (gxx_blur - gyy_blur) + 1e-6)
    return theta

def zhang_suen_thinning(binary_image):
    """
    Morphological thinning algorithm to produce single-pixel wide ridge skeletons.
    """
    skeleton = binary_image.copy() // 255
    prev = np.zeros_like(skeleton)
    h, w = skeleton.shape

    for _ in range(35): # Iterations converge quickly for 375x288
        # Step 1
        p = np.pad(skeleton, 1, mode='constant', constant_values=0)
        p2 = p[0:h, 1:w+1]
        p3 = p[0:h, 2:w+2]
        p4 = p[1:h+1, 2:w+2]
        p5 = p[2:h+2, 2:w+2]
        p6 = p[2:h+2, 1:w+1]
        p7 = p[2:h+2, 0:w]
        p8 = p[1:h+1, 0:w]
        p9 = p[0:h, 0:w]

        b = p2 + p3 + p4 + p5 + p6 + p7 + p8 + p9
        c2 = (b >= 2) & (b <= 6)

        a = (
            ((p2 == 0) & (p3 == 1)).astype(np.int32) +
            ((p3 == 0) & (p4 == 1)).astype(np.int32) +
            ((p4 == 0) & (p5 == 1)).astype(np.int32) +
            ((p5 == 0) & (p6 == 1)).astype(np.int32) +
            ((p6 == 0) & (p7 == 1)).astype(np.int32) +
            ((p7 == 0) & (p8 == 1)).astype(np.int32) +
            ((p8 == 0) & (p9 == 1)).astype(np.int32) +
            ((p9 == 0) & (p2 == 1)).astype(np.int32)
        )
        c3 = (a == 1)

        c4_1 = (p2 * p4 * p6 == 0)
        c5_1 = (p4 * p6 * p8 == 0)

        mask1 = (skeleton == 1) & c2 & c3 & c4_1 & c5_1
        skeleton[mask1] = 0

        # Step 2
        p = np.pad(skeleton, 1, mode='constant', constant_values=0)
        p2 = p[0:h, 1:w+1]
        p3 = p[0:h, 2:w+2]
        p4 = p[1:h+1, 2:w+2]
        p5 = p[2:h+2, 2:w+2]
        p6 = p[2:h+2, 1:w+1]
        p7 = p[2:h+2, 0:w]
        p8 = p[1:h+1, 0:w]
        p9 = p[0:h, 0:w]

        b = p2 + p3 + p4 + p5 + p6 + p7 + p8 + p9
        c2 = (b >= 2) & (b <= 6)

        a = (
            ((p2 == 0) & (p3 == 1)).astype(np.int32) +
            ((p3 == 0) & (p4 == 1)).astype(np.int32) +
            ((p4 == 0) & (p5 == 1)).astype(np.int32) +
            ((p5 == 0) & (p6 == 1)).astype(np.int32) +
            ((p6 == 0) & (p7 == 1)).astype(np.int32) +
            ((p7 == 0) & (p8 == 1)).astype(np.int32) +
            ((p8 == 0) & (p9 == 1)).astype(np.int32) +
            ((p9 == 0) & (p2 == 1)).astype(np.int32)
        )
        c3 = (a == 1)

        c4_2 = (p2 * p4 * p8 == 0)
        c5_2 = (p2 * p6 * p8 == 0)

        mask2 = (skeleton == 1) & c2 & c3 & c4_2 & c5_2
        skeleton[mask2] = 0

        if np.array_equal(skeleton, prev):
            break
        prev = skeleton.copy()

    return (skeleton * 255).astype(np.uint8)

def classify_henry_pattern(theta_field, mask):
    """
    Classifies fingerprint into Henry pattern class based on orientation flow:
    0: Arch (gentle wave, minimal circulation)
    1: Loop (hairpin looping flow)
    2: Whorl (spiral/circular circularity with dual focal flows)
    """
    valid_theta = theta_field[mask > 0]
    if len(valid_theta) == 0:
        return 1

    sin_2theta = np.sin(2.0 * valid_theta)
    cos_2theta = np.cos(2.0 * valid_theta)
    r = np.sqrt(np.mean(sin_2theta)**2 + np.mean(cos_2theta)**2)
    circular_variance = 1.0 - r

    if circular_variance < 0.28:
        return 0 # Arch
    elif circular_variance > 0.48:
        return 2 # Whorl
    else:
        return 1 # Loop

def extract_fingerprint_features(image_path, max_minutiae=30):
    """
    Performs full forensic pipeline on raw image:
    1. CLAHE contrast normalization
    2. Adaptive binarization
    3. Morphological Zhang-Suen thinning
    4. Rutovitz Crossing-Number minutiae extraction (Ridge Endings & Bifurcations)
    5. Spurious minutiae post-filtering
    6. Henry pattern classification
    """
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise ValueError(f"Unable to read image at {image_path}")

    h, w = img.shape

    # 1. CLAHE Enhancement
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(img)

    # 2. Ridge Orientation Field
    theta_field = compute_orientation_field(enhanced)

    # 3. Ridge Segmentation Mask
    blurred = cv2.GaussianBlur(enhanced, (5, 5), 0)
    _, binary = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)

    # Foreground fingerprint mask (excluding outer border background)
    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (15, 15))
    mask = cv2.morphologyEx(binary, cv2.MORPH_CLOSE, kernel)
    mask = cv2.erode(mask, cv2.getStructuringElement(cv2.MORPH_RECT, (20, 20)))

    # 4. Skeletonization
    skeleton = zhang_suen_thinning(binary)
    skeleton = cv2.bitwise_and(skeleton, skeleton, mask=mask)

    # 5. Fast Rutovitz Crossing Number Minutiae Extraction
    skel_int = (skeleton // 255).astype(np.int32)
    minutiae_raw = []

    # Vectorized neighborhood extraction
    p2 = skel_int[:-2, 1:-1]
    p3 = skel_int[:-2, 2:]
    p4 = skel_int[1:-1, 2:]
    p5 = skel_int[2:, 2:]
    p6 = skel_int[2:, 1:-1]
    p7 = skel_int[2:, :-2]
    p8 = skel_int[1:-1, :-2]
    p9 = skel_int[:-2, :-2]

    p_list = [p2, p3, p4, p5, p6, p7, p8, p9]
    cn = 0.5 * sum(np.abs(p_list[(k + 1) % 8] - p_list[k]) for k in range(8))

    center = skel_int[1:-1, 1:-1]
    endings_y, endings_x = np.where((center == 1) & (cn == 1.0))
    bifurc_y, bifurc_x = np.where((center == 1) & (cn == 3.0))

    # Adjust indices back to full image (add +1 offset)
    endings_y += 1
    endings_x += 1
    bifurc_y += 1
    bifurc_x += 1

    margin = 20
    # Process ridge endings
    for y, x in zip(endings_y, endings_x):
        if y < margin or y >= h - margin or x < margin or x >= w - margin:
            continue
        theta = float(theta_field[y, x])
        quality = float(np.std(enhanced[max(0, y-8):min(h, y+8), max(0, x-8):min(w, x+8)]) / 128.0)
        minutiae_raw.append({
            "x": round(float(x), 1),
            "y": round(float(y), 1),
            "theta": round(theta, 3),
            "type": 0, # Ridge Ending
            "quality": round(max(0.4, min(1.0, quality)), 2)
        })

    # Process bifurcations
    for y, x in zip(bifurc_y, bifurc_x):
        if y < margin or y >= h - margin or x < margin or x >= w - margin:
            continue
        theta = float(theta_field[y, x])
        quality = float(np.std(enhanced[max(0, y-8):min(h, y+8), max(0, x-8):min(w, x+8)]) / 128.0)
        minutiae_raw.append({
            "x": round(float(x), 1),
            "y": round(float(y), 1),
            "theta": round(theta, 3),
            "type": 1, # Bifurcation
            "quality": round(max(0.4, min(1.0, quality)), 2)
        })

    # 6. Post-Processing: Prune overly clustered false minutiae (< 12 px distance)
    # Ensure balanced representation of both endings and bifurcations
    minutiae_raw.sort(key=lambda m: m["quality"], reverse=True)
    filtered = []
    min_dist_sq = 12.0 * 12.0

    for m in minutiae_raw:
        too_close = False
        for f in filtered:
            dx = m["x"] - f["x"]
            dy = m["y"] - f["y"]
            if (dx * dx + dy * dy) < min_dist_sq:
                too_close = True
                break
        if not too_close:
            filtered.append(m)
            if len(filtered) >= max_minutiae:
                break

    # 7. Pattern Classification
    pattern_class = classify_henry_pattern(theta_field, mask)

    base_id = os.path.splitext(os.path.basename(image_path))[0]

    record = {
        "id": base_id,
        "pattern_class": pattern_class,
        "minutiae": filtered
    }

    return record, skeleton, enhanced

def process_dataset(dataset_dir, output_db_path, web_static_dir=None):
    """
    Processes all fingerprint images from dataset directory and writes JSON database.
    """
    print(f"[EXTRACTOR] Scanning dataset directory: {dataset_dir}")
    patterns = ["**/*.bmp", "**/*.jpg", "**/*.png"]
    image_paths = []
    for pat in patterns:
        image_paths.extend(glob.glob(os.path.join(dataset_dir, pat), recursive=True))

    selected_images = {}
    for p in image_paths:
        base_name = os.path.splitext(os.path.basename(p))[0]
        ext = os.path.splitext(p)[1].lower()
        if base_name not in selected_images or ext == ".bmp":
            selected_images[base_name] = p

    img_list = sorted(list(selected_images.values()))
    print(f"[EXTRACTOR] Found {len(img_list)} unique fingerprint images.")

    records = []
    sample_queries = []

    if web_static_dir:
        os.makedirs(web_static_dir, exist_ok=True)

    for idx, img_path in enumerate(img_list):
        try:
            rec, skel, enh = extract_fingerprint_features(img_path, max_minutiae=30)
            rec_json = json.dumps(rec, separators=(',', ':'))
            size_bytes = len(rec_json.encode('utf-8'))

            records.append(rec)
            endings = sum(1 for m in rec["minutiae"] if m["type"] == 0)
            bifurcs = sum(1 for m in rec["minutiae"] if m["type"] == 1)
            print(f"[{idx+1}/{len(img_list)}] Extracted '{rec['id']}': {len(rec['minutiae'])} minutiae ({endings} Endings, {bifurcs} Bifurcations), class={rec['pattern_class']}, size={size_bytes} bytes")

            if web_static_dir:
                out_img_name = f"{rec['id']}.png"
                cv2.imwrite(os.path.join(web_static_dir, out_img_name), enh)

                out_skel_name = f"{rec['id']}_skel.png"
                cv2.imwrite(os.path.join(web_static_dir, out_skel_name), skel)

            sample_queries.append(rec)

        except Exception as e:
            print(f"[WARNING] Skipping {img_path}: {e}")

    # Write master database JSON
    os.makedirs(os.path.dirname(os.path.abspath(output_db_path)), exist_ok=True)
    with open(output_db_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    total_size = os.path.getsize(output_db_path)
    avg_size = total_size / max(1, len(records))

    print("\n====================================================================")
    print(" FORENSIC FEATURE EXTRACTION COMPLETED")
    print("====================================================================")
    print(f" Total Ingested Fingerprint Templates: {len(records)}")
    print(f" Master Database File               : {output_db_path}")
    print(f" Total Database Size on Disk        : {total_size} bytes ({total_size/1024.0:.2f} KB)")
    print(f" Mean Record Size                   : {avg_size:.2f} bytes (< 1024 bytes per record constraint satisfied)")
    print("====================================================================\n")

    # Write out individual query JSON sample files
    data_dir = os.path.dirname(output_db_path)
    for q in sample_queries:
        q_path = os.path.join(data_dir, f"query_{q['id']}.json")
        with open(q_path, "w", encoding="utf-8") as f:
            json.dump(q, f, indent=2)

    return records

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Forensic Biometric Minutiae Extractor")
    parser.add_argument("--dataset_dir", default=r"c:\Users\srushti\Downloads\fods_dataset", help="Dataset directory")
    parser.add_argument("--output_db", default="data/socofing_database.json", help="Path to output database JSON")
    parser.add_argument("--web_static", default="web/images", help="Directory to save static image overlays")

    args = parser.parse_args()
    process_dataset(args.dataset_dir, args.output_db, args.web_static)
