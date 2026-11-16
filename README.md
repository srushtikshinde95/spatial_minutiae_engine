# SPATIAL MINUTIAE-GRAPH INDEXING ENGINE (AFIS-MK4)
### High-Performance Forensic Biometric Latent Print Analysis Workstation

> **Principal Systems Software Engineering & Forensic AFIS Architecture**  
> Developed strictly in standard C (C11/C99) with `-O3` optimization flags.  
> Zero AI dependencies, zero external ML libraries, zero neural networks. Pure deterministic biometric mathematics and spatial indexing.

---

## 1. System Architecture Overview

The **Spatial Minutiae-Graph Indexing Engine** is a production-grade Automated Fingerprint Identification System (AFIS) backend designed for sub-millisecond latent print matching against large-scale biometric databases (Kaggle SOCOFing), featuring live on-the-fly user fingerprint enrollment and full 360-degree rotation-invariant topological graph verification.

```
+-----------------------------------------------------------------------------------------+
|                                FORENSIC INGESTION PIPELINE                              |
|   Raw Sensor Images (.bmp, .jpg) ---> CLAHE Normalization ---> Ridge Orientation Field  |
|   ---> Zhang-Suen Skeletonization ---> Rutovitz Crossing Number ---> Feature Vector     |
|   (Format: ID, Pattern Class [0: Arch, 1: Loop, 2: Whorl], Minutiae [(x, y, theta)])    |
|   Vector Size Budget: < 1024 Bytes / Record                                             |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                               THREE-TIER C INDEXING ENGINE                              |
|                                                                                         |
|  [TIER 1: B-Tree Index (btree.c)]                                                       |
|   * Custom Order M=4 B-Tree partitioning records by Henry Pattern Class                 |
|   * O(log N) category lookup, deterministic candidate pool pre-filtering                |
|                                                                                         |
|  [TIER 2: 2D Spatial Kd-Tree (kdtree.c)]                                                |
|   * Balanced median-partitioned Kd-Tree on 2D (x, y) spatial minutiae coordinates       |
|   * O(log M) nearest-neighbor queries with hyperplane branch pruning                    |
|                                                                                         |
|  [TIER 3: Invariant Minutiae Adjacency Graph (graph.c)]                                 |
|   * Dynamic linked-list weighted adjacency graph (struct GraphEdge*)                    |
|   * Strictly Rotation & Translation Invariant Descriptors:                              |
|       d_ij = ||p_i - p_j|| (Euclidean Distance Invariance)                              |
|       phi_u = atan2(dy, dx) - theta_u (Relative Radial Angle)                           |
|       phi_v = atan2(-dy, -dx) - theta_v (Relative Radial Angle)                         |
|       delta_theta = theta_v - theta_u (Orientation Delta)                               |
|       delta_psi = inter-edge angular delta in star neighborhood                         |
|   * Circular atan2 consensus voting for exact rotation angle detection                  |
|   * Topological correspondence extraction (matched points & matched edges)              |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                          FORENSIC LATENT PRINT WORKSTATION (AFIS)                       |
|   * High-contrast Dark Forensic Interface (Slate / Charcoal #1A1D20 / Deep Navy #0F172A)|
|   * Latent Minutiae Plotter (Overlaid Red Ridge Endings, Green Bifurcations, Graph)     |
|   * Live User Fingerprint Enrollment Modal & Dynamic RAM Ingestion Engine               |
|   * Rotated Match Verification Mode (Split-Screen Enrolled vs. Rotated Query Scan)      |
|   * Multi-Tier Search Execution Console (Real-time microsecond telemetry)              |
|   * Benchmark Metrics Panel (Sub-microsecond timers, memory budget accounting)         |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Directory Structure

```
spatial_minutiae_engine/
├── bin/
│   ├── engine_cli.exe           # Compiled native C AFIS engine CLI executable
│   └── libengine.dll            # Compiled C dynamic shared library
├── build/                       # Intermediate C object files (.o)
├── data/
│   ├── socofing_database.json   # Processed Kaggle SOCOFing fingerprint database
│   └── query_*.json             # Individual query templates for CLI testing
├── include/
│   ├── btree.h                  # Tier-1 B-Tree category index header
│   ├── kdtree.h                 # Tier-2 2D Kd-Tree spatial index header
│   ├── graph.h                  # Tier-3 Invariant Adjacency Graph header
│   └── engine.h                 # Master Engine API & telemetry structures
├── scripts/
│   ├── extract_minutiae.py      # Kaggle SOCOFing image ingestion pipeline
│   ├── test_rotation.py         # Multi-angle rotation-invariance test suite
│   └── test_endpoints.py        # Web backend endpoint integration tests
├── src/
│   ├── btree.c                  # Custom B-Tree C implementation
│   ├── kdtree.c                 # 2D Kd-Tree C implementation
│   ├── graph.c                  # Invariant Adjacency Graph C implementation
│   ├── engine.c                 # Master engine orchestration & dynamic enrollment
│   └── main.c                   # CLI runner, enrollment command & RPC service
├── web/
│   ├── index.html               # Forensic Workstation UI (Enrollment + Rotated Match)
│   ├── style.css                # High-contrast AFIS dark forensic theme
│   ├── app.js                   # Client-side plotter & split-screen controller
│   ├── server.py                # HTTP server bridging C engine & live enrollment
│   └── images/                  # Static sensor latent & skeleton image overlays
├── Makefile                     # Build configuration with GCC -O3 optimization flags
└── README.md                    # System documentation
```

---

## 3. Mathematical & Algorithmic Formulation

### 3.1. Rutovitz Crossing Number (Minutiae Classification)
For a 1-pixel skeletonized ridge image, the Rutovitz Crossing Number $CN(P)$ for a pixel $P$ with 8-neighbors $P_1, \dots, P_8$ in counter-clockwise sequence is:
$$CN(P) = \frac{1}{2} \sum_{k=1}^{8} |P_{k+1} - P_k| \quad (\text{with } P_9 = P_1)$$
- $CN(P) = 1$: **Ridge Ending** (Terminal minutia point, rendered in **Crimson**).
- $CN(P) = 2$: Normal continuing ridge.
- $CN(P) = 3$: **Bifurcation** (Branching minutia point, rendered in **Emerald Green**).

### 3.2. Tier 1: Custom B-Tree Indexing ($O(\log N)$)
Records are partitioned into an Order $M=4$ B-Tree keyed on the Henry classification pattern index:
- Key 0: Arch
- Key 1: Loop
- Key 2: Whorl

When querying, the B-Tree retrieves the candidate bucket in $O(\log N)$ hops, pruning candidates from mismatching categories before spatial verification.

### 3.3. Tier 2: 2D Spatial Kd-Tree ($O(\log M)$)
Each template constructs a 2D Kd-Tree partitioning $(x, y)$ coordinates. The tree alternates split dimensions between $X$ and $Y$ by computing the spatial median. During nearest-neighbor and radius lookups, branches are aggressively pruned whenever:
$$|q_{\text{axis}} - p_{\text{axis}}|^2 \ge \text{best\_dist\_sq}$$

### 3.4. Tier 3: Rotation & Translation Invariant Adjacency Graph
Minutiae are linked into a local $k$-NN topological graph ($k=4 \dots 5$). Each directed edge $(u, v)$ stores an invariant descriptor:
$$E_{uv} = \left( d_{uv}, \phi_u, \phi_v, \Delta \theta, \Delta \psi \right)$$
where:
- $d_{uv} = \sqrt{(x_v - x_u)^2 + (y_v - y_u)^2}$ (Euclidean distance: strictly invariant to rigid body rotation and translation).
- $\phi_u = \text{atan2}(y_v - y_u, x_v - x_u) - \theta_u \pmod{2\pi}$ (Relative radial angle at vertex $u$).
- $\phi_v = \text{atan2}(y_u - y_v, x_u - x_v) - \theta_v \pmod{2\pi}$ (Relative radial angle at vertex $v$).
- $\Delta \theta = \theta_v - \theta_u \pmod{2\pi}$ (Invariant ridge orientation delta).
- $\Delta \psi = \text{atan2}(\sin(\alpha_2 - \alpha_1), \cos(\alpha_2 - \alpha_1))$ (Inter-edge angular delta in star neighborhood).

Two edges $E_1$ and $E_2$ match if $|d_1 - d_2| \le \delta_d$, $|\Delta \theta_1 - \Delta \theta_2| \le \delta_\theta$, and $|\phi_{u1} - \phi_{u2}| \le \delta_\phi$.

Topological star consensus computes the rigid transformation $(R(\Delta \Theta), \mathbf{t})$ via circular angular averaging:
$$\Delta\Theta = \text{atan2}\left(\sum \sin(\alpha_C - \alpha_Q), \sum \cos(\alpha_C - \alpha_Q)\right)$$
and evaluates spatial Root Mean Square Error (RMSE):
$$\text{RMSE} = \sqrt{\frac{1}{K} \sum_{i=1}^K \| \mathbf{p}_C^{(i)} - (R \mathbf{p}_Q^{(i)} + \mathbf{t}) \|^2}$$

---

## 4. Compilation & Execution

### 4.1. Building the Native C Engine
Using MSYS2 GCC or MinGW on Windows (or native GCC on Linux/macOS):
```bash
# Build optimized binary and dynamic library with -O3 flags
mingw32-make
# or
make
```

### 4.2. Ingesting SOCOFing Dataset
```bash
python scripts/extract_minutiae.py --dataset_dir "c:\Users\srushti\Downloads\fods_dataset" --output_db "data/socofing_database.json" --web_static "web/images"
```

### 4.3. CLI Engine Commands
```bash
# Index verification and memory footprint check
./bin/engine_cli.exe index data/socofing_database.json

# Query latent print against database
./bin/engine_cli.exe query data/socofing_database.json data/query_1_1_left_real_ZK9500.json

# Live User Fingerprint Enrollment
./bin/engine_cli.exe enroll data/socofing_database.json data/_test_enroll.json

# Execute multi-tier benchmark suite
./bin/engine_cli.exe benchmark data/socofing_database.json 1
```

### 4.4. Starting the Forensic AFIS Workstation UI
```bash
python web/server.py
```
Open a browser and navigate to: **`http://localhost:8080`**.

---

## 5. Verification & Rotation-Invariance Benchmark

Multi-angle benchmark across arbitrary rotation angles tested with pure C Tier-3 Minutiae Graph:

```
========================================================================================
 MULTI-ANGLE ROTATION-INVARIANCE BENCHMARK TEST (PURE C TIER-3 MINUTIAE GRAPH)
========================================================================================
Angle:  +15.0 deg | Match: 1_1_left_real_ZK9500 | Score:  98.81% | Detected Rot: -14.86 deg | RMSE: 0.18 px | Matched: 30/30
Angle:  +30.0 deg | Match: 1_1_left_real_ZK9500 | Score:  98.73% | Detected Rot: -29.85 deg | RMSE: 0.19 px | Matched: 30/30
Angle:  +45.0 deg | Match: 1_1_left_real_ZK9500 | Score:  98.75% | Detected Rot: -45.15 deg | RMSE: 0.19 px | Matched: 30/30
Angle:  +60.0 deg | Match: 1_1_left_real_ZK9500 | Score:  98.90% | Detected Rot: -59.87 deg | RMSE: 0.17 px | Matched: 30/30
Angle:  +90.0 deg | Match: 1_1_left_real_ZK9500 | Score: 100.00% | Detected Rot: -90.00 deg | RMSE: 0.00 px | Matched: 30/30
Angle: +120.0 deg | Match: 1_1_left_real_ZK9500 | Score:  98.73% | Detected Rot: -119.85 deg | RMSE: 0.19 px | Matched: 30/30
Angle: +180.0 deg | Match: 1_1_left_real_ZK9500 | Score: 100.00% | Detected Rot: +180.00 deg | RMSE: 0.00 px | Matched: 30/30
Angle:  -45.0 deg | Match: 1_1_left_real_ZK9500 | Score:  98.75% | Detected Rot: +44.85 deg | RMSE: 0.19 px | Matched: 30/30
Angle:  -90.0 deg | Match: 1_1_left_real_ZK9500 | Score: 100.00% | Detected Rot: +90.00 deg | RMSE: 0.00 px | Matched: 30/30
========================================================================================
```
