/**
 * @file kdtree.h
 * @brief Tier-2 Spatial Minutiae-Graph Indexing Engine: 2D Kd-Tree
 * 
 * Partitions 2D (x, y) spatial coordinates for O(log M) nearest-neighbor
 * and range lookups during topological verification.
 */

#ifndef SPATIAL_MINUTIAE_KDTREE_H
#define SPATIAL_MINUTIAE_KDTREE_H

#include <stddef.h>
#include <stdbool.h>

/**
 * @brief 2D Minutiae Coordinate Point
 */
typedef struct MinutiaePoint {
    int id;              /**< Unique index within the fingerprint record */
    float x;             /**< Spatial X coordinate (pixels) */
    float y;             /**< Spatial Y coordinate (pixels) */
    float theta;         /**< Ridge orientation angle (radians [-pi, pi]) */
    int type;            /**< 0: Ridge Ending, 1: Bifurcation */
    float quality;       /**< Minutia clarity/reliability score [0.0, 1.0] */
} MinutiaePoint;

/**
 * @brief 2D Kd-Tree Node
 */
typedef struct KdNode {
    MinutiaePoint point;
    int axis;            /**< Split axis: 0 for X, 1 for Y */
    struct KdNode* left;
    struct KdNode* right;
} KdNode;

/**
 * @brief Top-level 2D Kd-Tree container
 */
typedef struct KdTree {
    KdNode* root;
    size_t count;
    size_t memory_bytes;
} KdTree;

/**
 * @brief Diagnostics recorded during Kd-Tree query execution
 */
typedef struct KdDiagnostics {
    int hops_traversed;
    int branches_pruned;
    double search_time_us;
} KdDiagnostics;

/* Kd-Tree Lifecycle & Operations */
KdTree* kdtree_create(void);
KdTree* kdtree_build(const MinutiaePoint* points, size_t count);
const MinutiaePoint* kdtree_nearest(const KdTree* tree, float qx, float qy, float max_radius, float* out_dist_sq, KdDiagnostics* diag);
size_t kdtree_radius_search(const KdTree* tree, float qx, float qy, float radius, MinutiaePoint* out_results, size_t max_results, KdDiagnostics* diag);
void kdtree_free(KdTree* tree);
size_t kdtree_get_memory_usage(const KdTree* tree);

#endif /* SPATIAL_MINUTIAE_KDTREE_H */
