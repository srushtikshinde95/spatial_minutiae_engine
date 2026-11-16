/**
 * @file btree.h
 * @brief Tier-1 Spatial Minutiae-Graph Indexing Engine: Custom B-Tree Index
 * 
 * Partitions and indexes fingerprint records by pattern classification (Arch: 0,
 * Loop: 1, Whorl: 2) for deterministic O(log N) category pre-filtering.
 */

#ifndef SPATIAL_MINUTIAE_BTREE_H
#define SPATIAL_MINUTIAE_BTREE_H

#include <stddef.h>
#include <stdbool.h>

#define BTREE_ORDER 4 // Order M: Maximum children per node
#define BTREE_MAX_KEYS (BTREE_ORDER - 1) // 3
#define BTREE_MIN_KEYS ((BTREE_ORDER + 1) / 2 - 1) // 1

// Forward declaration
struct FingerprintRecord;

/**
 * @brief Dynamic array of record pointers belonging to a specific key
 */
typedef struct RecordBucket {
    struct FingerprintRecord** records;
    size_t count;
    size_t capacity;
} RecordBucket;

/**
 * @brief B-Tree Node structure
 */
typedef struct BTreeNode {
    int keys[BTREE_MAX_KEYS];
    RecordBucket* buckets[BTREE_MAX_KEYS];
    struct BTreeNode* children[BTREE_ORDER];
    int num_keys;
    bool is_leaf;
} BTreeNode;

/**
 * @brief Top-level B-Tree structure
 */
typedef struct BTree {
    BTreeNode* root;
    size_t total_records;
    size_t node_count;
    size_t memory_bytes;
} BTree;

/**
 * @brief Diagnostics recorded during B-Tree traversal
 */
typedef struct BTreeDiagnostics {
    int hops_traversed;
    size_t candidates_retained;
    size_t candidates_pruned;
    float prune_percentage;
    double search_time_us;
} BTreeDiagnostics;

/* B-Tree Lifecycle & Operations */
BTree* btree_create(void);
bool btree_insert(BTree* tree, int key, struct FingerprintRecord* record);
RecordBucket* btree_search(BTree* tree, int key, BTreeDiagnostics* diag);
void btree_free(BTree* tree);
size_t btree_get_memory_usage(const BTree* tree);

#endif /* SPATIAL_MINUTIAE_BTREE_H */
