/**
 * @file kdtree.c
 * @brief Tier-2 Spatial Minutiae-Graph Indexing Engine: 2D Kd-Tree Implementation
 * 
 * Partitions 2D (x, y) spatial coordinates for O(log M) nearest-neighbor
 * lookups with balanced median partitioning and branch pruning.
 */

#include "kdtree.h"
#include "engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* Sorting comparators for median splitting */
static int compare_points_x(const void* a, const void* b) {
    const MinutiaePoint* pa = (const MinutiaePoint*)a;
    const MinutiaePoint* pb = (const MinutiaePoint*)b;
    if (pa->x < pb->x) return -1;
    if (pa->x > pb->x) return 1;
    return 0;
}

static int compare_points_y(const void* a, const void* b) {
    const MinutiaePoint* pa = (const MinutiaePoint*)a;
    const MinutiaePoint* pb = (const MinutiaePoint*)b;
    if (pa->y < pb->y) return -1;
    if (pa->y > pb->y) return 1;
    return 0;
}

static KdNode* kdtree_build_recursive(MinutiaePoint* points, size_t count, int depth) {
    if (count == 0 || !points) return NULL;

    int axis = depth % 2; // 0 for X, 1 for Y

    if (axis == 0) {
        qsort(points, count, sizeof(MinutiaePoint), compare_points_x);
    } else {
        qsort(points, count, sizeof(MinutiaePoint), compare_points_y);
    }

    size_t median_idx = count / 2;
    KdNode* node = (KdNode*)malloc(sizeof(KdNode));
    if (!node) return NULL;

    node->point = points[median_idx];
    node->axis = axis;

    node->left = kdtree_build_recursive(points, median_idx, depth + 1);
    node->right = kdtree_build_recursive(points + median_idx + 1, count - median_idx - 1, depth + 1);

    return node;
}

KdTree* kdtree_create(void) {
    KdTree* tree = (KdTree*)malloc(sizeof(KdTree));
    if (!tree) return NULL;
    tree->root = NULL;
    tree->count = 0;
    tree->memory_bytes = sizeof(KdTree);
    return tree;
}

KdTree* kdtree_build(const MinutiaePoint* points, size_t count) {
    if (!points || count == 0) return NULL;

    KdTree* tree = kdtree_create();
    if (!tree) return NULL;

    // Duplicate points buffer for median partition sorting
    MinutiaePoint* buffer = (MinutiaePoint*)malloc(sizeof(MinutiaePoint) * count);
    if (!buffer) {
        free(tree);
        return NULL;
    }
    memcpy(buffer, points, sizeof(MinutiaePoint) * count);

    tree->root = kdtree_build_recursive(buffer, count, 0);
    tree->count = count;
    tree->memory_bytes = sizeof(KdTree) + (count * sizeof(KdNode));

    free(buffer);
    return tree;
}

static void kdtree_free_node(KdNode* node) {
    if (!node) return;
    if (node->left) kdtree_free_node(node->left);
    if (node->right) kdtree_free_node(node->right);
    free(node);
}

void kdtree_free(KdTree* tree) {
    if (!tree) return;
    if (tree->root) {
        kdtree_free_node(tree->root);
        tree->root = NULL;
    }
    free(tree);
}

static void kdtree_nearest_recursive(const KdNode* node, float qx, float qy,
                                     const KdNode** best_node, float* best_dist_sq,
                                     KdDiagnostics* diag) {
    if (!node) return;

    if (diag) diag->hops_traversed++;

    float dx = qx - node->point.x;
    float dy = qy - node->point.y;
    float dist_sq = dx * dx + dy * dy;

    if (dist_sq < *best_dist_sq) {
        *best_dist_sq = dist_sq;
        *best_node = node;
    }

    int axis = node->axis;
    float diff = (axis == 0) ? (qx - node->point.x) : (qy - node->point.y);

    const KdNode* first_branch = (diff <= 0.0f) ? node->left : node->right;
    const KdNode* second_branch = (diff <= 0.0f) ? node->right : node->left;

    // Search closest half first
    kdtree_nearest_recursive(first_branch, qx, qy, best_node, best_dist_sq, diag);

    // Hyperplane intersection test for branch pruning
    if ((diff * diff) < *best_dist_sq) {
        kdtree_nearest_recursive(second_branch, qx, qy, best_node, best_dist_sq, diag);
    } else {
        if (diag) diag->branches_pruned++;
    }
}

const MinutiaePoint* kdtree_nearest(const KdTree* tree, float qx, float qy, float max_radius, float* out_dist_sq, KdDiagnostics* diag) {
    if (!tree || !tree->root) return NULL;

    double t_start = engine_get_time_microseconds();
    const KdNode* best_node = NULL;
    float best_dist_sq = (max_radius > 0.0f) ? (max_radius * max_radius) : 1e12f;

    if (diag) {
        diag->hops_traversed = 0;
        diag->branches_pruned = 0;
    }

    kdtree_nearest_recursive(tree->root, qx, qy, &best_node, &best_dist_sq, diag);

    double t_end = engine_get_time_microseconds();
    if (diag) {
        diag->search_time_us = t_end - t_start;
    }

    if (best_node) {
        if (out_dist_sq) *out_dist_sq = best_dist_sq;
        return &best_node->point;
    }
    return NULL;
}

static void kdtree_radius_recursive(const KdNode* node, float qx, float qy, float r_sq,
                                    MinutiaePoint* out_results, size_t* result_count, size_t max_results,
                                    KdDiagnostics* diag) {
    if (!node || *result_count >= max_results) return;

    if (diag) diag->hops_traversed++;

    float dx = qx - node->point.x;
    float dy = qy - node->point.y;
    float dist_sq = dx * dx + dy * dy;

    if (dist_sq <= r_sq) {
        out_results[*result_count] = node->point;
        (*result_count)++;
        if (*result_count >= max_results) return;
    }

    int axis = node->axis;
    float diff = (axis == 0) ? (qx - node->point.x) : (qy - node->point.y);

    if (diff <= 0.0f) {
        kdtree_radius_recursive(node->left, qx, qy, r_sq, out_results, result_count, max_results, diag);
        if ((diff * diff) <= r_sq) {
            kdtree_radius_recursive(node->right, qx, qy, r_sq, out_results, result_count, max_results, diag);
        } else {
            if (diag) diag->branches_pruned++;
        }
    } else {
        kdtree_radius_recursive(node->right, qx, qy, r_sq, out_results, result_count, max_results, diag);
        if ((diff * diff) <= r_sq) {
            kdtree_radius_recursive(node->left, qx, qy, r_sq, out_results, result_count, max_results, diag);
        } else {
            if (diag) diag->branches_pruned++;
        }
    }
}

size_t kdtree_radius_search(const KdTree* tree, float qx, float qy, float radius,
                            MinutiaePoint* out_results, size_t max_results, KdDiagnostics* diag) {
    if (!tree || !tree->root || !out_results || max_results == 0) return 0;

    double t_start = engine_get_time_microseconds();
    size_t result_count = 0;
    float r_sq = radius * radius;

    if (diag) {
        diag->hops_traversed = 0;
        diag->branches_pruned = 0;
    }

    kdtree_radius_recursive(tree->root, qx, qy, r_sq, out_results, &result_count, max_results, diag);

    double t_end = engine_get_time_microseconds();
    if (diag) {
        diag->search_time_us = t_end - t_start;
    }
    return result_count;
}

size_t kdtree_get_memory_usage(const KdTree* tree) {
    if (!tree) return 0;
    return sizeof(KdTree) + (tree->count * sizeof(KdNode));
}
