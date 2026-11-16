/**
 * @file graph.h
 * @brief Tier-3 Spatial Minutiae-Graph Indexing Engine: Dynamic Invariant Adjacency Graph
 * 
 * Stores relative Euclidean distances, radial directional angles, and inter-edge
 * angular deltas across minutiae pairs. Guarantees strict translation and
 * rotation invariance for forensic latent-to-exemplar graph verification.
 */

#ifndef SPATIAL_MINUTIAE_GRAPH_H
#define SPATIAL_MINUTIAE_GRAPH_H

#include "kdtree.h"
#include <stddef.h>
#include <stdbool.h>

#define GRAPH_DEFAULT_K_NEIGHBORS 5
#define GRAPH_MAX_EDGE_DISTANCE 180.0f // Maximum spatial radius for minutiae edge linkage
#define GRAPH_MAX_MATCHED_EDGES 128
#define GRAPH_MAX_MATCHED_POINTS 64

/**
 * @brief Dynamic Linked-List Adjacency Edge
 */
typedef struct GraphEdge {
    int target_idx;            /**< Target minutia index in vertex array */
    float distance;            /**< Euclidean distance ||p_u - p_v|| (strictly invariant) */
    float radial_angle;        /**< Polar chord angle: atan2(dy, dx) */
    float rel_angle_u;         /**< Relative radial angle at vertex u: radial_angle - theta_u */
    float rel_angle_v;         /**< Relative radial angle at vertex v: radial_angle + pi - theta_v */
    float orientation_diff;    /**< Invariant ridge orientation delta: theta_v - theta_u */
    float inter_edge_delta;    /**< Invariant inter-edge angle to adjacent neighbor in star */
    int target_type;           /**< Target minutia classification: 0 (Ending), 1 (Bifurcation) */
    struct GraphEdge* next;    /**< Pointer to next edge in vertex adjacency list */
} GraphEdge;

/**
 * @brief Dynamic Minutiae Adjacency Graph
 */
typedef struct MinutiaeGraph {
    int num_vertices;
    GraphEdge** adj_lists;     /**< Array of head pointers for vertex linked-lists */
    size_t total_edges;
    size_t memory_bytes;
} MinutiaeGraph;

/**
 * @brief Graph topological verification tolerance parameters
 */
typedef struct GraphMatchConfig {
    float dist_tolerance;       /**< Maximum Euclidean distance discrepancy (pixels, e.g. 12.0) */
    float angle_tolerance;      /**< Maximum relative angle discrepancy (radians, e.g. 0.45 rad ~ 25 deg) */
    float orient_tolerance;     /**< Maximum ridge orientation delta discrepancy (radians, e.g. 0.45 rad) */
    int min_edge_congruence;    /**< Minimum edge matches required for candidate consideration */
} GraphMatchConfig;

/**
 * @brief Point correspondence pair
 */
typedef struct PointCorrespondence {
    int query_idx;
    int cand_idx;
    float rotation_delta_deg;
} PointCorrespondence;

/**
 * @brief Edge correspondence pair
 */
typedef struct EdgeCorrespondence {
    int q_u;
    int q_v;
    int c_u;
    int c_v;
    float distance;
} EdgeCorrespondence;

/**
 * @brief Detailed report from Tier-3 graph topological matching
 */
typedef struct GraphMatchReport {
    int query_minutiae_count;
    int candidate_minutiae_count;
    int total_edges_evaluated;
    int matched_edges;
    int verified_minutiae;
    float forensic_score;       /**< Normalized forensic concordance score [0.0 - 100.0%] */
    float spatial_rmse;         /**< Root-mean-square spatial alignment error */
    float estimated_rotation;   /**< Estimated angular rotation (radians) */
    float estimated_rotation_deg;/**< Estimated angular rotation in degrees */
    float estimated_tx;         /**< Estimated X translation (pixels) */
    float estimated_ty;         /**< Estimated Y translation (pixels) */
    double execution_time_us;   /**< Microseconds elapsed */

    /* Verified topological correspondences for split-screen overlay rendering */
    int num_point_matches;
    PointCorrespondence point_matches[GRAPH_MAX_MATCHED_POINTS];
    int num_edge_matches;
    EdgeCorrespondence edge_matches[GRAPH_MAX_MATCHED_EDGES];
} GraphMatchReport;

/* Graph Lifecycle & Operations */
MinutiaeGraph* graph_create(int num_vertices);
MinutiaeGraph* graph_build_from_points(const MinutiaePoint* points, int count, const KdTree* kdtree, int k_neighbors);
void graph_add_edge(MinutiaeGraph* graph, int src, int dst, float dist, float radial, float rel_u, float rel_v, float ori_diff, float inter_delta, int dst_type);
bool graph_verify_invariance(const MinutiaeGraph* query_graph, const MinutiaePoint* query_points,
                             const MinutiaeGraph* cand_graph, const MinutiaePoint* cand_points,
                             const GraphMatchConfig* config, GraphMatchReport* report);
void graph_free(MinutiaeGraph* graph);
size_t graph_get_memory_usage(const MinutiaeGraph* graph);

#endif /* SPATIAL_MINUTIAE_GRAPH_H */
