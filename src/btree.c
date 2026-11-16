/**
 * @file btree.c
 * @brief Tier-1 Spatial Minutiae-Graph Indexing Engine: Custom B-Tree Implementation
 * 
 * Strict standard C (C99/C11) implementation with explicit struct definitions,
 * manual memory allocation, and zero memory leaks.
 */

#include "btree.h"
#include "engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forward internal declarations */
static BTreeNode* btree_create_node(bool is_leaf);
static void btree_free_node(BTreeNode* node);
static void btree_split_child(BTreeNode* parent, int index, BTreeNode* child);
static void btree_insert_non_full(BTreeNode* node, int key, struct FingerprintRecord* record, BTree* tree);
static RecordBucket* bucket_create(void);
static void bucket_free(RecordBucket* bucket);
static bool bucket_add(RecordBucket* bucket, struct FingerprintRecord* record);

static RecordBucket* bucket_create(void) {
    RecordBucket* bucket = (RecordBucket*)malloc(sizeof(RecordBucket));
    if (!bucket) return NULL;
    bucket->capacity = 16;
    bucket->count = 0;
    bucket->records = (struct FingerprintRecord**)malloc(sizeof(struct FingerprintRecord*) * bucket->capacity);
    if (!bucket->records) {
        free(bucket);
        return NULL;
    }
    return bucket;
}

static void bucket_free(RecordBucket* bucket) {
    if (!bucket) return;
    if (bucket->records) {
        free(bucket->records);
        bucket->records = NULL;
    }
    free(bucket);
}

static bool bucket_add(RecordBucket* bucket, struct FingerprintRecord* record) {
    if (!bucket || !record) return false;
    if (bucket->count >= bucket->capacity) {
        size_t new_cap = bucket->capacity * 2;
        struct FingerprintRecord** new_recs = (struct FingerprintRecord**)realloc(
            bucket->records, sizeof(struct FingerprintRecord*) * new_cap);
        if (!new_recs) return false;
        bucket->records = new_recs;
        bucket->capacity = new_cap;
    }
    bucket->records[bucket->count++] = record;
    return true;
}

static BTreeNode* btree_create_node(bool is_leaf) {
    BTreeNode* node = (BTreeNode*)malloc(sizeof(BTreeNode));
    if (!node) return NULL;
    node->is_leaf = is_leaf;
    node->num_keys = 0;
    for (int i = 0; i < BTREE_MAX_KEYS; ++i) {
        node->keys[i] = 0;
        node->buckets[i] = NULL;
    }
    for (int i = 0; i < BTREE_ORDER; ++i) {
        node->children[i] = NULL;
    }
    return node;
}

static void btree_free_node(BTreeNode* node) {
    if (!node) return;
    if (!node->is_leaf) {
        for (int i = 0; i <= node->num_keys; ++i) {
            if (node->children[i]) {
                btree_free_node(node->children[i]);
                node->children[i] = NULL;
            }
        }
    }
    for (int i = 0; i < node->num_keys; ++i) {
        if (node->buckets[i]) {
            bucket_free(node->buckets[i]);
            node->buckets[i] = NULL;
        }
    }
    free(node);
}

BTree* btree_create(void) {
    BTree* tree = (BTree*)malloc(sizeof(BTree));
    if (!tree) return NULL;
    tree->root = btree_create_node(true);
    tree->total_records = 0;
    tree->node_count = 1;
    tree->memory_bytes = sizeof(BTree) + sizeof(BTreeNode);
    return tree;
}

void btree_free(BTree* tree) {
    if (!tree) return;
    if (tree->root) {
        btree_free_node(tree->root);
        tree->root = NULL;
    }
    free(tree);
}

static void btree_split_child(BTreeNode* parent, int index, BTreeNode* child) {
    BTreeNode* sibling = btree_create_node(child->is_leaf);
    sibling->num_keys = 1; // BTREE_MIN_KEYS for order 4

    // Copy keys and buckets from child to sibling
    sibling->keys[0] = child->keys[2];
    sibling->buckets[0] = child->buckets[2];
    child->buckets[2] = NULL;

    // Copy child pointers if non-leaf
    if (!child->is_leaf) {
        sibling->children[0] = child->children[2];
        sibling->children[1] = child->children[3];
        child->children[2] = NULL;
        child->children[3] = NULL;
    }

    child->num_keys = 1;

    // Shift parent's children to accommodate new sibling
    for (int j = parent->num_keys; j >= index + 1; --j) {
        parent->children[j + 1] = parent->children[j];
    }
    parent->children[index + 1] = sibling;

    // Shift parent's keys to accommodate median key
    for (int j = parent->num_keys - 1; j >= index; --j) {
        parent->keys[j + 1] = parent->keys[j];
        parent->buckets[j + 1] = parent->buckets[j];
    }

    parent->keys[index] = child->keys[1];
    parent->buckets[index] = child->buckets[1];
    child->buckets[1] = NULL;
    parent->num_keys++;
}

static void btree_insert_non_full(BTreeNode* node, int key, struct FingerprintRecord* record, BTree* tree) {
    int i = node->num_keys - 1;

    // Check if key already exists in this node
    for (int k = 0; k < node->num_keys; ++k) {
        if (node->keys[k] == key) {
            bucket_add(node->buckets[k], record);
            tree->total_records++;
            return;
        }
    }

    if (node->is_leaf) {
        // Find insert position
        while (i >= 0 && key < node->keys[i]) {
            node->keys[i + 1] = node->keys[i];
            node->buckets[i + 1] = node->buckets[i];
            i--;
        }
        node->keys[i + 1] = key;
        node->buckets[i + 1] = bucket_create();
        bucket_add(node->buckets[i + 1], record);
        node->num_keys++;
        tree->total_records++;
    } else {
        while (i >= 0 && key < node->keys[i]) {
            i--;
        }
        i++;
        if (node->children[i]->num_keys == BTREE_MAX_KEYS) {
            // Check if key exists in child before split
            for (int k = 0; k < node->children[i]->num_keys; ++k) {
                if (node->children[i]->keys[k] == key) {
                    bucket_add(node->children[i]->buckets[k], record);
                    tree->total_records++;
                    return;
                }
            }
            btree_split_child(node, i, node->children[i]);
            tree->node_count++;
            if (key > node->keys[i]) {
                i++;
            }
        }
        btree_insert_non_full(node->children[i], key, record, tree);
    }
}

bool btree_insert(BTree* tree, int key, struct FingerprintRecord* record) {
    if (!tree || !record) return false;

    BTreeNode* root = tree->root;
    if (root->num_keys == BTREE_MAX_KEYS) {
        // Check if root already contains key
        for (int k = 0; k < root->num_keys; ++k) {
            if (root->keys[k] == key) {
                bucket_add(root->buckets[k], record);
                tree->total_records++;
                return true;
            }
        }

        BTreeNode* new_root = btree_create_node(false);
        tree->root = new_root;
        new_root->children[0] = root;
        btree_split_child(new_root, 0, root);
        tree->node_count++;
        btree_insert_non_full(new_root, key, record, tree);
    } else {
        btree_insert_non_full(root, key, record, tree);
    }
    return true;
}

RecordBucket* btree_search(BTree* tree, int key, BTreeDiagnostics* diag) {
    if (!tree || !tree->root) return NULL;

    double t_start = engine_get_time_microseconds();
    int hops = 0;
    BTreeNode* curr = tree->root;

    while (curr != NULL) {
        hops++;
        int i = 0;
        while (i < curr->num_keys && key > curr->keys[i]) {
            i++;
        }

        if (i < curr->num_keys && key == curr->keys[i]) {
            double t_end = engine_get_time_microseconds();
            if (diag) {
                diag->hops_traversed = hops;
                diag->candidates_retained = curr->buckets[i] ? curr->buckets[i]->count : 0;
                diag->candidates_pruned = tree->total_records - diag->candidates_retained;
                diag->prune_percentage = tree->total_records > 0
                    ? ((float)diag->candidates_pruned / (float)tree->total_records) * 100.0f
                    : 0.0f;
                diag->search_time_us = t_end - t_start;
            }
            return curr->buckets[i];
        }

        if (curr->is_leaf) {
            break;
        }
        curr = curr->children[i];
    }

    double t_end = engine_get_time_microseconds();
    if (diag) {
        diag->hops_traversed = hops;
        diag->candidates_retained = 0;
        diag->candidates_pruned = tree->total_records;
        diag->prune_percentage = 100.0f;
        diag->search_time_us = t_end - t_start;
    }
    return NULL;
}

static size_t calculate_node_memory(const BTreeNode* node) {
    if (!node) return 0;
    size_t mem = sizeof(BTreeNode);
    for (int i = 0; i < node->num_keys; ++i) {
        if (node->buckets[i]) {
            mem += sizeof(RecordBucket) + (node->buckets[i]->capacity * sizeof(struct FingerprintRecord*));
        }
    }
    if (!node->is_leaf) {
        for (int i = 0; i <= node->num_keys; ++i) {
            mem += calculate_node_memory(node->children[i]);
        }
    }
    return mem;
}

size_t btree_get_memory_usage(const BTree* tree) {
    if (!tree) return 0;
    return sizeof(BTree) + calculate_node_memory(tree->root);
}
