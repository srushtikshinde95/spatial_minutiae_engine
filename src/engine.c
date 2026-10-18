/**
 * @file engine.c
 * @brief Master Spatial Minutiae-Graph Indexing Engine Implementation
 * 
 * Strict standard C (C99/C11) implementation adhering to Principal Systems
 * Software Engineering and Forensic AFIS principles. Zero memory leaks,
 * high-resolution microsecond telemetry, and deterministic 3-tier indexing.
 */

#include "engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#if defined(_WIN32) || defined(_WIN64)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#endif

double engine_get_time_microseconds(void) {
#if defined(_WIN32) || defined(_WIN64)
    static LARGE_INTEGER freq;
    static int initialized = 0;
    if (!initialized) {
        QueryPerformanceFrequency(&freq);
        initialized = 1;
    }
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return ((double)counter.QuadPart * 1000000.0) / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((double)ts.tv_sec * 1000000.0) + ((double)ts.tv_nsec / 1000.0);
#endif
}

Engine* engine_create(void) {
    Engine* engine = (Engine*)malloc(sizeof(Engine));
    if (!engine) return NULL;

    engine->btree = btree_create();
    if (!engine->btree) {
        free(engine);
        return NULL;
    }

    engine->record_capacity = 64;
    engine->record_count = 0;
    engine->records = (FingerprintRecord**)malloc(sizeof(FingerprintRecord*) * engine->record_capacity);
    if (!engine->records) {
        btree_free(engine->btree);
        free(engine);
        return NULL;
    }

    // Default forensic tolerance configuration
    engine->match_config.dist_tolerance = 12.0f;       // pixels
    engine->match_config.angle_tolerance = 0.45f;      // radians (~26 deg)
    engine->match_config.orient_tolerance = 0.45f;     // radians
    engine->match_config.min_edge_congruence = 2;

    engine->total_memory_bytes = sizeof(Engine) + sizeof(FingerprintRecord*) * engine->record_capacity;
    return engine;
}

void engine_free_record(FingerprintRecord* record) {
    if (!record) return;

    if (record->minutiae) {
        free(record->minutiae);
        record->minutiae = NULL;
    }
    if (record->kdtree) {
        kdtree_free(record->kdtree);
        record->kdtree = NULL;
    }
    if (record->graph) {
        graph_free(record->graph);
        record->graph = NULL;
    }
    free(record);
}

void engine_free(Engine* engine) {
    if (!engine) return;

    if (engine->records) {
        for (size_t i = 0; i < engine->record_count; ++i) {
            engine_free_record(engine->records[i]);
        }
        free(engine->records);
        engine->records = NULL;
    }

    if (engine->btree) {
        btree_free(engine->btree);
        engine->btree = NULL;
    }

    free(engine);
}

bool engine_add_record(Engine* engine, FingerprintRecord* record) {
    if (!engine || !record) return false;

    // Check if duplicate ID already exists; replace if so
    for (size_t i = 0; i < engine->record_count; ++i) {
        if (strcmp(engine->records[i]->id, record->id) == 0) {
            engine->total_memory_bytes -= engine->records[i]->memory_bytes;
            engine_free_record(engine->records[i]);
            engine->records[i] = record;
            btree_insert(engine->btree, record->pattern_class, record);
            engine->total_memory_bytes += record->memory_bytes;
            return true;
        }
    }

    // Expand records master list if needed
    if (engine->record_count >= engine->record_capacity) {
        size_t new_cap = engine->record_capacity * 2;
        FingerprintRecord** new_recs = (FingerprintRecord**)realloc(
            engine->records, sizeof(FingerprintRecord*) * new_cap);
        if (!new_recs) return false;
        engine->records = new_recs;
        engine->record_capacity = new_cap;
    }

    engine->records[engine->record_count++] = record;

    // Index into Tier-1 B-Tree by pattern classification
    btree_insert(engine->btree, record->pattern_class, record);

    // Update memory statistics
    engine->total_memory_bytes += record->memory_bytes;
    return true;
}

/* ========================================================================= */
/* Custom Safe C JSON Parser (zero external dependencies)                   */
/* ========================================================================= */

static const char* skip_whitespace(const char* s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

static bool parse_json_string(const char** json, char* out_str, size_t max_len) {
    *json = skip_whitespace(*json);
    if (**json != '\"') return false;
    (*json)++;
    size_t i = 0;
    while (**json && **json != '\"' && i < max_len - 1) {
        if (**json == '\\') {
            (*json)++;
            if (!**json) break;
        }
        out_str[i++] = **json;
        (*json)++;
    }
    out_str[i] = '\0';
    if (**json == '\"') {
        (*json)++;
        return true;
    }
    return false;
}

static bool parse_json_number(const char** json, float* out_val) {
    *json = skip_whitespace(*json);
    char* endptr = NULL;
    *out_val = strtof(*json, &endptr);
    if (endptr == *json) return false;
    *json = endptr;
    return true;
}

static bool parse_json_int(const char** json, int* out_val) {
    *json = skip_whitespace(*json);
    char* endptr = NULL;
    long v = strtol(*json, &endptr, 10);
    if (endptr == *json) return false;
    *out_val = (int)v;
    *json = endptr;
    return true;
}

FingerprintRecord* engine_parse_record_json(const char* json_str) {
    if (!json_str) return NULL;

    const char* p = skip_whitespace(json_str);
    if (*p != '{') return NULL;
    p++;

    FingerprintRecord* rec = (FingerprintRecord*)calloc(1, sizeof(FingerprintRecord));
    if (!rec) return NULL;

    rec->pattern_class = PATTERN_UNKNOWN;
    size_t minutiae_capacity = 64;
    rec->minutiae = (MinutiaePoint*)malloc(sizeof(MinutiaePoint) * minutiae_capacity);
    if (!rec->minutiae) {
        free(rec);
        return NULL;
    }

    while (*p && *p != '}') {
        p = skip_whitespace(p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') break;

        char key[64] = {0};
        if (!parse_json_string(&p, key, sizeof(key))) break;

        p = skip_whitespace(p);
        if (*p != ':') break;
        p++; // skip ':'
        p = skip_whitespace(p);

        if (strcmp(key, "id") == 0 || strcmp(key, "fingerprint_id") == 0) {
            parse_json_string(&p, rec->id, sizeof(rec->id));
        } else if (strcmp(key, "pattern_class") == 0) {
            parse_json_int(&p, &rec->pattern_class);
        } else if (strcmp(key, "minutiae") == 0) {
            if (*p != '[') break;
            p++; // skip '['
            while (*p && *p != ']') {
                p = skip_whitespace(p);
                if (*p == ',') { p++; continue; }
                if (*p == ']') break;

                MinutiaePoint pt;
                pt.id = rec->num_minutiae;
                pt.x = 0.0f;
                pt.y = 0.0f;
                pt.theta = 0.0f;
                pt.type = 0;
                pt.quality = 1.0f;

                if (*p == '{') {
                    p++;
                    while (*p && *p != '}') {
                        p = skip_whitespace(p);
                        if (*p == ',') { p++; continue; }
                        if (*p == '}') break;

                        char mkey[32] = {0};
                        if (!parse_json_string(&p, mkey, sizeof(mkey))) break;
                        p = skip_whitespace(p);
                        if (*p != ':') break;
                        p++;
                        p = skip_whitespace(p);

                        if (strcmp(mkey, "x") == 0) parse_json_number(&p, &pt.x);
                        else if (strcmp(mkey, "y") == 0) parse_json_number(&p, &pt.y);
                        else if (strcmp(mkey, "theta") == 0) parse_json_number(&p, &pt.theta);
                        else if (strcmp(mkey, "type") == 0) parse_json_int(&p, &pt.type);
                        else if (strcmp(mkey, "quality") == 0) parse_json_number(&p, &pt.quality);
                        else {
                            float dummy; parse_json_number(&p, &dummy);
                        }
                    }
                    if (*p == '}') p++;
                } else if (*p == '[') {
                    p++;
                    parse_json_number(&p, &pt.x);
                    p = skip_whitespace(p); if (*p == ',') p++;
                    parse_json_number(&p, &pt.y);
                    p = skip_whitespace(p); if (*p == ',') p++;
                    parse_json_number(&p, &pt.theta);
                    p = skip_whitespace(p);
                    if (*p == ',') {
                        p++;
                        parse_json_int(&p, &pt.type);
                        p = skip_whitespace(p);
                        if (*p == ',') {
                            p++;
                            parse_json_number(&p, &pt.quality);
                        }
                    }
                    while (*p && *p != ']') p++;
                    if (*p == ']') p++;
                } else {
                    p++;
                }

                if (rec->num_minutiae >= (int)minutiae_capacity) {
                    minutiae_capacity *= 2;
                    MinutiaePoint* new_pts = (MinutiaePoint*)realloc(
                        rec->minutiae, sizeof(MinutiaePoint) * minutiae_capacity);
                    if (!new_pts) break;
                    rec->minutiae = new_pts;
                }
                rec->minutiae[rec->num_minutiae++] = pt;
            }
            if (*p == ']') p++;
        } else {
            if (*p == '\"') {
                char dummy[128]; parse_json_string(&p, dummy, sizeof(dummy));
            } else if (*p == '{' || *p == '[') {
                int depth = 1;
                char open_c = *p;
                char close_c = (open_c == '{') ? '}' : ']';
                p++;
                while (*p && depth > 0) {
                    if (*p == open_c) depth++;
                    else if (*p == close_c) depth--;
                    p++;
                }
            } else {
                while (*p && *p != ',' && *p != '}') p++;
            }
        }
    }

    // Build Tier-2 Kd-Tree
    rec->kdtree = kdtree_build(rec->minutiae, (size_t)rec->num_minutiae);

    // Build Tier-3 Minutiae Adjacency Graph
    rec->graph = graph_build_from_points(rec->minutiae, rec->num_minutiae, rec->kdtree, GRAPH_DEFAULT_K_NEIGHBORS);

    // Memory accounting
    size_t minutiae_bytes = rec->num_minutiae * sizeof(MinutiaePoint);
    size_t kdtree_bytes = kdtree_get_memory_usage(rec->kdtree);
    size_t graph_bytes = graph_get_memory_usage(rec->graph);

    rec->memory_bytes = sizeof(FingerprintRecord) + minutiae_bytes + kdtree_bytes + graph_bytes;
    rec->raw_vector_bytes = sizeof(FingerprintRecord) + minutiae_bytes;

    return rec;
}

bool engine_load_database_json(Engine* engine, const char* filepath) {
    if (!engine || !filepath) return false;

    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "[ERROR] Unable to open database file: %s\n", filepath);
        return false;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0) {
        fclose(fp);
        return false;
    }

    char* buffer = (char*)malloc((size_t)fsize + 1);
    if (!buffer) {
        fclose(fp);
        return false;
    }

    size_t read_bytes = fread(buffer, 1, (size_t)fsize, fp);
    buffer[read_bytes] = '\0';
    fclose(fp);

    const char* p = skip_whitespace(buffer);
    if (*p == '[') p++;

    int loaded_count = 0;

    while (*p && *p != ']') {
        p = skip_whitespace(p);
        if (*p == ',') { p++; continue; }
        if (*p == ']') break;

        if (*p == '{') {
            const char* obj_start = p;
            int depth = 1;
            p++;
            while (*p && depth > 0) {
                if (*p == '{') depth++;
                else if (*p == '}') depth--;
                p++;
            }

            size_t obj_len = (size_t)(p - obj_start);
            char* obj_str = (char*)malloc(obj_len + 1);
            if (obj_str) {
                memcpy(obj_str, obj_start, obj_len);
                obj_str[obj_len] = '\0';

                FingerprintRecord* rec = engine_parse_record_json(obj_str);
                if (rec) {
                    engine_add_record(engine, rec);
                    loaded_count++;
                }
                free(obj_str);
            }
        } else {
            p++;
        }
    }

    free(buffer);
    return (loaded_count > 0);
}

/* ========================================================================= */
/* Live User Fingerprint Dynamic Enrollment Pipeline                         */
/* ========================================================================= */

bool engine_enroll_record(Engine* engine, FingerprintRecord* record, const char* persist_db_path) {
    if (!engine || !record) return false;

    double t_start = engine_get_time_microseconds();

    // 1. Ingest dynamically into live RAM (malloc structs, B-Tree, Kd-Tree, Graph)
    if (!engine_add_record(engine, record)) {
        return false;
    }

    double t_end = engine_get_time_microseconds();
    printf("[ENROLL_PASS] Enrolled latent '%s' into live RAM index in %.2f us. Allocated %zu bytes in RAM.\n",
           record->id, t_end - t_start, record->memory_bytes);

    // 2. Persist update to database JSON if path provided
    if (persist_db_path) {
        // Read existing file
        FILE* fp = fopen(persist_db_path, "r+b");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long sz = ftell(fp);
            if (sz > 2) {
                // Seek back to find the closing ']'
                long pos = sz - 1;
                while (pos > 0) {
                    fseek(fp, pos, SEEK_SET);
                    int ch = fgetc(fp);
                    if (ch == ']') {
                        break;
                    }
                    pos--;
                }
                if (pos > 0) {
                    fseek(fp, pos, SEEK_SET);
                    // Check if need comma
                    bool need_comma = (pos > 2);
                    if (need_comma) {
                        fputs(",\n", fp);
                    }
                    // Write new record JSON
                    fprintf(fp, "  {\n    \"id\": \"%s\",\n    \"pattern_class\": %d,\n    \"minutiae\": [\n",
                            record->id, record->pattern_class);
                    for (int m = 0; m < record->num_minutiae; ++m) {
                        fprintf(fp, "      {\"x\": %.1f, \"y\": %.1f, \"theta\": %.3f, \"type\": %d, \"quality\": %.2f}%s\n",
                                record->minutiae[m].x, record->minutiae[m].y, record->minutiae[m].theta,
                                record->minutiae[m].type, record->minutiae[m].quality,
                                (m < record->num_minutiae - 1) ? "," : "");
                    }
                    fprintf(fp, "    ]\n  }\n]\n");
                }
            }
            fclose(fp);
        }
    }

    return true;
}

bool engine_enroll_file(Engine* engine, const char* json_filepath, const char* persist_db_path) {
    if (!engine || !json_filepath) return false;

    FILE* fp = fopen(json_filepath, "rb");
    if (!fp) return false;

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { fclose(fp); return false; }

    char* buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return false; }
    size_t rd = fread(buf, 1, (size_t)sz, fp);
    buf[rd] = '\0';
    fclose(fp);

    FingerprintRecord* rec = engine_parse_record_json(buf);
    free(buf);
    if (!rec) return false;

    return engine_enroll_record(engine, rec, persist_db_path);
}

/* Comparator for sorting match candidates by forensic score descending */
static int compare_candidates_desc(const void* a, const void* b) {
    const MatchCandidate* ca = (const MatchCandidate*)a;
    const MatchCandidate* cb = (const MatchCandidate*)b;
    if (ca->forensic_score > cb->forensic_score) return -1;
    if (ca->forensic_score < cb->forensic_score) return 1;
    return 0;
}

bool engine_query(Engine* engine, const FingerprintRecord* query, QueryTelemetry* telemetry) {
    if (!engine || !query || !telemetry) return false;

    double t_total_start = engine_get_time_microseconds();

    memset(telemetry, 0, sizeof(QueryTelemetry));
    snprintf(telemetry->query_id, sizeof(telemetry->query_id), "%s", query->id);
    telemetry->query_pattern_class = query->pattern_class;
    telemetry->query_minutiae_count = query->num_minutiae;

    /* ===================================================================== */
    /* TIER-1: Pattern Classification B-Tree Pre-Filtering (O(log N))        */
    /* ===================================================================== */
    double t_b_start = engine_get_time_microseconds();
    RecordBucket* bucket = btree_search(engine->btree, query->pattern_class, &telemetry->tier1);
    telemetry->tier1.search_time_us = engine_get_time_microseconds() - t_b_start;

    size_t candidate_pool_size = bucket ? bucket->count : 0;
    telemetry->tier1.candidates_retained = candidate_pool_size;
    telemetry->tier1.candidates_pruned = engine->record_count - candidate_pool_size;
    telemetry->tier1.prune_percentage = (engine->record_count > 0)
        ? ((float)telemetry->tier1.candidates_pruned / (float)engine->record_count) * 100.0f
        : 0.0f;

    if (candidate_pool_size == 0) {
        telemetry->total_execution_time_us = engine_get_time_microseconds() - t_total_start;
        return true;
    }

    MatchCandidate* all_candidates = (MatchCandidate*)malloc(sizeof(MatchCandidate) * candidate_pool_size);
    if (!all_candidates) {
        telemetry->total_execution_time_us = engine_get_time_microseconds() - t_total_start;
        return false;
    }

    double t_kdtree_accum = 0.0;
    double t_graph_accum = 0.0;
    int total_spatial_hops = 0;
    int branches_pruned = 0;
    int edges_evaluated = 0;
    int edges_matched = 0;

    for (size_t c = 0; c < candidate_pool_size; ++c) {
        FingerprintRecord* cand = bucket->records[c];
        if (!cand) continue;

        double t_cand_start = engine_get_time_microseconds();

        /* ================================================================= */
        /* TIER-2: Spatial Kd-Tree Coordinate Evaluation                     */
        /* ================================================================= */
        double t_kd_start = engine_get_time_microseconds();
        for (int q = 0; q < query->num_minutiae; ++q) {
            KdDiagnostics kdiag;
            float dist_sq = 0.0f;
            kdtree_nearest(cand->kdtree, query->minutiae[q].x, query->minutiae[q].y, 25.0f, &dist_sq, &kdiag);
            total_spatial_hops += kdiag.hops_traversed;
            branches_pruned += kdiag.branches_pruned;
        }
        t_kdtree_accum += (engine_get_time_microseconds() - t_kd_start);

        /* ================================================================= */
        /* TIER-3: Invariant Minutiae Graph Verification                     */
        /* ================================================================= */
        double t_gr_start = engine_get_time_microseconds();
        GraphMatchReport grep;
        graph_verify_invariance(query->graph, query->minutiae,
                                cand->graph, cand->minutiae,
                                &engine->match_config, &grep);
        t_graph_accum += (engine_get_time_microseconds() - t_gr_start);

        edges_evaluated += grep.total_edges_evaluated;
        edges_matched += grep.matched_edges;

        // Record candidate output
        memset(&all_candidates[c], 0, sizeof(MatchCandidate));
        snprintf(all_candidates[c].id, sizeof(all_candidates[c].id), "%s", cand->id);
        all_candidates[c].pattern_class = cand->pattern_class;
        all_candidates[c].forensic_score = grep.forensic_score;
        all_candidates[c].matched_minutiae = grep.verified_minutiae;
        all_candidates[c].matched_edges = grep.matched_edges;
        all_candidates[c].spatial_rmse = grep.spatial_rmse;
        all_candidates[c].estimated_rotation_deg = grep.estimated_rotation_deg;
        all_candidates[c].estimated_tx = grep.estimated_tx;
        all_candidates[c].estimated_ty = grep.estimated_ty;
        all_candidates[c].latency_us = engine_get_time_microseconds() - t_cand_start;

        // Copy correspondences for top alignment visualization
        int pt_copy = (grep.num_point_matches < 32) ? grep.num_point_matches : 32;
        all_candidates[c].num_matched_points = pt_copy;
        for (int p = 0; p < pt_copy; ++p) {
            all_candidates[c].matched_points[p] = grep.point_matches[p];
        }

        int ed_copy = (grep.num_edge_matches < 64) ? grep.num_edge_matches : 64;
        all_candidates[c].num_matched_edges = ed_copy;
        for (int e = 0; e < ed_copy; ++e) {
            all_candidates[c].matched_edge_pairs[e] = grep.edge_matches[e];
        }
    }

    telemetry->tier2_total_spatial_hops = total_spatial_hops;
    telemetry->tier2_branches_pruned = branches_pruned;
    telemetry->tier2_total_time_us = t_kdtree_accum;

    telemetry->tier3_candidates_evaluated = (int)candidate_pool_size;
    telemetry->tier3_total_edges_checked = edges_evaluated;
    telemetry->tier3_total_edges_matched = edges_matched;
    telemetry->tier3_total_time_us = t_graph_accum;

    qsort(all_candidates, candidate_pool_size, sizeof(MatchCandidate), compare_candidates_desc);

    int top_n = (candidate_pool_size < MAX_TOP_CANDIDATES) ? (int)candidate_pool_size : MAX_TOP_CANDIDATES;
    telemetry->candidate_count = top_n;
    for (int i = 0; i < top_n; ++i) {
        telemetry->top_candidates[i] = all_candidates[i];
    }

    free(all_candidates);

    telemetry->total_execution_time_us = engine_get_time_microseconds() - t_total_start;
    telemetry->engine_total_memory_bytes = engine->total_memory_bytes;
    telemetry->memory_per_record_bytes = (engine->record_count > 0)
        ? (double)engine->total_memory_bytes / (double)engine->record_count
        : 0.0;

    return true;
}

char* engine_telemetry_to_json(const QueryTelemetry* t) {
    if (!t) return NULL;

    size_t buf_size = 65536;
    char* json = (char*)malloc(buf_size);
    if (!json) return NULL;

    int offset = snprintf(json, buf_size,
        "{\n"
        "  \"query_id\": \"%s\",\n"
        "  \"query_pattern_class\": %d,\n"
        "  \"query_minutiae_count\": %d,\n"
        "  \"tier1_btree\": {\n"
        "    \"hops_traversed\": %d,\n"
        "    \"candidates_retained\": %zu,\n"
        "    \"candidates_pruned\": %zu,\n"
        "    \"prune_percentage\": %.2f,\n"
        "    \"search_time_us\": %.2f\n"
        "  },\n"
        "  \"tier2_kdtree\": {\n"
        "    \"total_spatial_hops\": %d,\n"
        "    \"branches_pruned\": %d,\n"
        "    \"execution_time_us\": %.2f\n"
        "  },\n"
        "  \"tier3_graph\": {\n"
        "    \"candidates_evaluated\": %d,\n"
        "    \"total_edges_checked\": %d,\n"
        "    \"total_edges_matched\": %d,\n"
        "    \"execution_time_us\": %.2f\n"
        "  },\n"
        "  \"benchmarks\": {\n"
        "    \"total_execution_time_us\": %.2f,\n"
        "    \"total_memory_bytes\": %zu,\n"
        "    \"memory_per_record_bytes\": %.2f\n"
        "  },\n"
        "  \"top_candidates\": [\n",
        t->query_id,
        t->query_pattern_class,
        t->query_minutiae_count,
        t->tier1.hops_traversed,
        t->tier1.candidates_retained,
        t->tier1.candidates_pruned,
        t->tier1.prune_percentage,
        t->tier1.search_time_us,
        t->tier2_total_spatial_hops,
        t->tier2_branches_pruned,
        t->tier2_total_time_us,
        t->tier3_candidates_evaluated,
        t->tier3_total_edges_checked,
        t->tier3_total_edges_matched,
        t->tier3_total_time_us,
        t->total_execution_time_us,
        t->engine_total_memory_bytes,
        t->memory_per_record_bytes
    );

    for (int i = 0; i < t->candidate_count; ++i) {
        const MatchCandidate* c = &t->top_candidates[i];
        offset += snprintf(json + offset, buf_size - offset,
            "    {\n"
            "      \"rank\": %d,\n"
            "      \"id\": \"%s\",\n"
            "      \"pattern_class\": %d,\n"
            "      \"forensic_score\": %.2f,\n"
            "      \"matched_minutiae\": %d,\n"
            "      \"matched_edges\": %d,\n"
            "      \"spatial_rmse\": %.2f,\n"
            "      \"rotation_deg\": %.2f,\n"
            "      \"translation_x\": %.2f,\n"
            "      \"translation_y\": %.2f,\n"
            "      \"latency_us\": %.2f,\n"
            "      \"matched_points\": [",
            i + 1,
            c->id,
            c->pattern_class,
            c->forensic_score,
            c->matched_minutiae,
            c->matched_edges,
            c->spatial_rmse,
            c->estimated_rotation_deg,
            c->estimated_tx,
            c->estimated_ty,
            c->latency_us
        );

        for (int p = 0; p < c->num_matched_points; ++p) {
            offset += snprintf(json + offset, buf_size - offset,
                "[%d, %d, %.2f]%s",
                c->matched_points[p].query_idx,
                c->matched_points[p].cand_idx,
                c->matched_points[p].rotation_delta_deg,
                (p < c->num_matched_points - 1) ? ", " : ""
            );
        }

        offset += snprintf(json + offset, buf_size - offset, "],\n      \"matched_edges_list\": [");
        for (int e = 0; e < c->num_matched_edges; ++e) {
            offset += snprintf(json + offset, buf_size - offset,
                "[%d, %d, %d, %d, %.1f]%s",
                c->matched_edge_pairs[e].q_u, c->matched_edge_pairs[e].q_v,
                c->matched_edge_pairs[e].c_u, c->matched_edge_pairs[e].c_v,
                c->matched_edge_pairs[e].distance,
                (e < c->num_matched_edges - 1) ? ", " : ""
            );
        }

        offset += snprintf(json + offset, buf_size - offset,
            "]\n    }%s\n",
            (i < t->candidate_count - 1) ? "," : ""
        );
    }

    snprintf(json + offset, buf_size - offset, "  ]\n}\n");
    return json;
}
