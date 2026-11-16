/**
 * @file engine.h
 * @brief Spatial Minutiae-Graph Indexing Engine: Master Engine Architecture
 * 
 * Principal Systems Software Engineering implementation for biometric fingerprint
 * template indexing and matching using a deterministic Three-Tier C hierarchy:
 *   - Tier 1: Pattern Classification B-Tree Index (O(log N) category pruning)
 *   - Tier 2: 2D Spatial Kd-Tree (O(log M) coordinate partitioning)
 *   - Tier 3: Minutiae Invariant Adjacency Graph (Strict Rotation/Translation invariant edge verification)
 */

#ifndef SPATIAL_MINUTIAE_ENGINE_H
#define SPATIAL_MINUTIAE_ENGINE_H

#include "btree.h"
#include "kdtree.h"
#include "graph.h"
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_FINGERPRINT_ID_LEN 64
#define MAX_TOP_CANDIDATES 16

/**
 * @brief Fingerprint Pattern Classification (Henry System)
 */
typedef enum {
    PATTERN_ARCH = 0,
    PATTERN_LOOP = 1,
    PATTERN_WHORL = 2,
    PATTERN_UNKNOWN = 3
} FingerprintPatternClass;

/**
 * @brief Biometric Fingerprint Record Template
 */
typedef struct FingerprintRecord {
    char id[MAX_FINGERPRINT_ID_LEN];
    int pattern_class;               /**< 0: Arch, 1: Loop, 2: Whorl */
    int num_minutiae;
    MinutiaePoint* minutiae;
    KdTree* kdtree;                  /**< Tier-2 Spatial Kd-Tree */
    MinutiaeGraph* graph;            /**< Tier-3 Invariant Adjacency Graph */
    size_t raw_vector_bytes;         /**< Raw JSON/Vector payload size (< 1 KB) */
    size_t memory_bytes;             /**< Exact in-RAM allocated footprint */
} FingerprintRecord;

/**
 * @brief Candidate match result in ranking list
 */
typedef struct MatchCandidate {
    char id[MAX_FINGERPRINT_ID_LEN];
    int pattern_class;
    float forensic_score;            /**< Topological concordance [0.0 - 100.0%] */
    int matched_minutiae;
    int matched_edges;
    float spatial_rmse;
    float estimated_rotation_deg;
    float estimated_tx;
    float estimated_ty;
    double latency_us;

    /* Verified correspondences for split-screen overlay rendering */
    int num_matched_points;
    PointCorrespondence matched_points[32];
    int num_matched_edges;
    EdgeCorrespondence matched_edge_pairs[64];
} MatchCandidate;

/**
 * @brief Complete diagnostic telemetry for a single query execution
 */
typedef struct QueryTelemetry {
    char query_id[MAX_FINGERPRINT_ID_LEN];
    int query_pattern_class;
    int query_minutiae_count;

    /* Tier-1 B-Tree Telemetry */
    BTreeDiagnostics tier1;

    /* Tier-2 Kd-Tree Telemetry */
    int tier2_total_spatial_hops;
    int tier2_branches_pruned;
    double tier2_total_time_us;

    /* Tier-3 Graph Telemetry */
    int tier3_candidates_evaluated;
    int tier3_total_edges_checked;
    int tier3_total_edges_matched;
    double tier3_total_time_us;

    /* Overall Engine Performance & Latency */
    int candidate_count;
    MatchCandidate top_candidates[MAX_TOP_CANDIDATES];
    double total_execution_time_us;
    size_t engine_total_memory_bytes;
    double memory_per_record_bytes;
} QueryTelemetry;

/**
 * @brief Engine Context Container
 */
typedef struct Engine {
    BTree* btree;                    /**< Tier-1 B-Tree */
    FingerprintRecord** records;     /**< Master pointer array of indexed records */
    size_t record_count;
    size_t record_capacity;
    GraphMatchConfig match_config;
    size_t total_memory_bytes;
} Engine;

/* Engine Lifecycle & Public Interface */
Engine* engine_create(void);
bool engine_add_record(Engine* engine, FingerprintRecord* record);
bool engine_load_database_json(Engine* engine, const char* filepath);
FingerprintRecord* engine_parse_record_json(const char* json_str);
bool engine_query(Engine* engine, const FingerprintRecord* query_record, QueryTelemetry* telemetry);
bool engine_enroll_record(Engine* engine, FingerprintRecord* record, const char* persist_db_path);
bool engine_enroll_file(Engine* engine, const char* json_filepath, const char* persist_db_path);
void engine_free_record(FingerprintRecord* record);
void engine_free(Engine* engine);

/* High-Resolution Forensic System Timer */
double engine_get_time_microseconds(void);

/* Forensic Report Serialization */
char* engine_telemetry_to_json(const QueryTelemetry* telemetry);

#endif /* SPATIAL_MINUTIAE_ENGINE_H */
