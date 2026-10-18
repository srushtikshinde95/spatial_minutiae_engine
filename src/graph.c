/**
 * @file graph.c
 * @brief Tier-3 Spatial Minutiae-Graph Indexing Engine: Dynamic Invariant Adjacency Graph
 * 
 * Strict standard C (C99/C11) implementation with zero AI dependencies.
 * Implements relative Euclidean distances, radial directional angles, and inter-edge
 * angular deltas across minutiae pairs. Guarantees translation and rotation
 * invariance for forensic latent-to-exemplar graph verification.
 */

#include "graph.h"
#include "engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/**
 * @brief Normalize an angle to [-pi, pi]
 */
static inline float normalize_angle(float angle) {
    while (angle > (float)M_PI) angle -= 2.0f * (float)M_PI;
    while (angle < -(float)M_PI) angle += 2.0f * (float)M_PI;
    return angle;
}

/**
 * @brief Angular absolute difference in [-pi, pi]
 */
static inline float angle_diff(float a, float b) {
    return fabsf(normalize_angle(a - b));
}

MinutiaeGraph* graph_create(int num_vertices) {
    if (num_vertices <= 0) return NULL;

    MinutiaeGraph* graph = (MinutiaeGraph*)malloc(sizeof(MinutiaeGraph));
    if (!graph) return NULL;

    graph->num_vertices = num_vertices;
    graph->total_edges = 0;
    graph->adj_lists = (GraphEdge**)calloc(num_vertices, sizeof(GraphEdge*));
    if (!graph->adj_lists) {
        free(graph);
        return NULL;
    }

    graph->memory_bytes = sizeof(MinutiaeGraph) + (num_vertices * sizeof(GraphEdge*));
    return graph;
}

void graph_add_edge(MinutiaeGraph* graph, int src, int dst, float dist, float radial, float rel_u, float rel_v, float ori_diff, float inter_delta, int dst_type) {
    if (!graph || src < 0 || src >= graph->num_vertices || dst < 0 || dst >= graph->num_vertices) return;

    GraphEdge* edge = (GraphEdge*)malloc(sizeof(GraphEdge));
    if (!edge) return;

    edge->target_idx = dst;
    edge->distance = dist;
    edge->radial_angle = radial;
    edge->rel_angle_u = rel_u;
    edge->rel_angle_v = rel_v;
    edge->orientation_diff = ori_diff;
    edge->inter_edge_delta = inter_delta;
    edge->target_type = dst_type;

    // Prepend to adjacency linked list
    edge->next = graph->adj_lists[src];
    graph->adj_lists[src] = edge;

    graph->total_edges++;
    graph->memory_bytes += sizeof(GraphEdge);
}

void graph_free(MinutiaeGraph* graph) {
    if (!graph) return;
    if (graph->adj_lists) {
        for (int i = 0; i < graph->num_vertices; ++i) {
            GraphEdge* curr = graph->adj_lists[i];
            while (curr) {
                GraphEdge* next = curr->next;
                free(curr);
                curr = next;
            }
        }
        free(graph->adj_lists);
        graph->adj_lists = NULL;
    }
    free(graph);
}

MinutiaeGraph* graph_build_from_points(const MinutiaePoint* points, int count, const KdTree* kdtree, int k_neighbors) {
    if (!points || count <= 1 || !kdtree) return NULL;

    MinutiaeGraph* graph = graph_create(count);
    if (!graph) return NULL;

    if (k_neighbors <= 0) k_neighbors = GRAPH_DEFAULT_K_NEIGHBORS;

    size_t max_search = (size_t)(count < 32 ? count : 32);
    MinutiaePoint* neighbors = (MinutiaePoint*)malloc(sizeof(MinutiaePoint) * max_search);
    if (!neighbors) {
        graph_free(graph);
        return NULL;
    }

    for (int i = 0; i < count; ++i) {
        float qx = points[i].x;
        float qy = points[i].y;
        float theta_u = points[i].theta;

        KdDiagnostics diag;
        size_t found = kdtree_radius_search(kdtree, qx, qy, GRAPH_MAX_EDGE_DISTANCE, neighbors, max_search, &diag);

        typedef struct NeighborDist {
            int idx;
            float dist;
            float radial_angle;
        } NeighborDist;

        NeighborDist dist_list[64];
        int dist_count = 0;

        for (size_t j = 0; j < found && dist_count < 64; ++j) {
            if (neighbors[j].id == points[i].id) continue;
            float dx = neighbors[j].x - qx;
            float dy = neighbors[j].y - qy;
            float d = sqrtf(dx * dx + dy * dy);
            if (d < 1e-3f) continue;

            dist_list[dist_count].idx = neighbors[j].id;
            dist_list[dist_count].dist = d;
            dist_list[dist_count].radial_angle = atan2f(dy, dx);
            dist_count++;
        }

        // Sort by distance ascending to select top K
        for (int a = 0; a < dist_count - 1; ++a) {
            for (int b = a + 1; b < dist_count; ++b) {
                if (dist_list[b].dist < dist_list[a].dist) {
                    NeighborDist tmp = dist_list[a];
                    dist_list[a] = dist_list[b];
                    dist_list[b] = tmp;
                }
            }
        }

        int edges_added = 0;
        int k_sel = (dist_count < k_neighbors) ? dist_count : k_neighbors;

        for (int n = 0; n < k_sel; ++n) {
            int j = dist_list[n].idx;
            if (j < 0 || j >= count) continue;

            float dist = dist_list[n].dist;
            float radial = dist_list[n].radial_angle;
            float rel_u = normalize_angle(radial - theta_u);
            float rel_v = normalize_angle(radial + (float)M_PI - points[j].theta);
            float ori_diff = normalize_angle(points[j].theta - theta_u);

            // Calculate inter-edge angular delta relative to subsequent neighbor in star
            float next_radial = dist_list[(n + 1) % k_sel].radial_angle;
            float inter_delta = normalize_angle(next_radial - radial);

            graph_add_edge(graph, i, j, dist, radial, rel_u, rel_v, ori_diff, inter_delta, points[j].type);
            edges_added++;
        }
    }

    free(neighbors);
    return graph;
}

/**
 * @brief Candidate point correspondence struct
 */
typedef struct PointMatchInternal {
    int query_idx;
    int cand_idx;
    int edge_votes;
    float rot_delta;
} PointMatchInternal;

bool graph_verify_invariance(const MinutiaeGraph* query_graph, const MinutiaePoint* query_points,
                             const MinutiaeGraph* cand_graph, const MinutiaePoint* cand_points,
                             const GraphMatchConfig* config, GraphMatchReport* report) {
    if (!query_graph || !query_points || !cand_graph || !cand_points || !report) return false;

    double t_start = engine_get_time_microseconds();

    // Tolerances for spatial and angular invariance
    float d_tol = (config && config->dist_tolerance > 0.0f) ? config->dist_tolerance : 12.0f;
    float a_tol = (config && config->angle_tolerance > 0.0f) ? config->angle_tolerance : 0.45f; // ~26 deg
    float o_tol = (config && config->orient_tolerance > 0.0f) ? config->orient_tolerance : 0.45f;

    int Q = query_graph->num_vertices;
    int C = cand_graph->num_vertices;

    memset(report, 0, sizeof(GraphMatchReport));
    report->query_minutiae_count = Q;
    report->candidate_minutiae_count = C;

    if (Q == 0 || C == 0) {
        report->execution_time_us = engine_get_time_microseconds() - t_start;
        return false;
    }

    // Association vote matrix [Q][C]
    int* vote_matrix = (int*)calloc((size_t)(Q * C), sizeof(int));
    float* rot_sin_matrix = (float*)calloc((size_t)(Q * C), sizeof(float));
    float* rot_cos_matrix = (float*)calloc((size_t)(Q * C), sizeof(float));
    if (!vote_matrix || !rot_sin_matrix || !rot_cos_matrix) {
        if (vote_matrix) free(vote_matrix);
        if (rot_sin_matrix) free(rot_sin_matrix);
        if (rot_cos_matrix) free(rot_cos_matrix);
        report->execution_time_us = engine_get_time_microseconds() - t_start;
        return false;
    }

    int matched_edges_count = 0;

    // Traverse all edges in query graph
    for (int u = 0; u < Q; ++u) {
        for (GraphEdge* eQ = query_graph->adj_lists[u]; eQ != NULL; eQ = eQ->next) {
            int v = eQ->target_idx;

            // Compare against all edges in candidate graph
            for (int uc = 0; uc < C; ++uc) {
                for (GraphEdge* eC = cand_graph->adj_lists[uc]; eC != NULL; eC = eC->next) {
                    report->total_edges_evaluated++;

                    // 1. Strict Euclidean Distance Invariance Check
                    if (fabsf(eQ->distance - eC->distance) > d_tol) continue;

                    // 2. Relative Orientation Delta Invariance Check
                    float d_ori = angle_diff(eQ->orientation_diff, eC->orientation_diff);
                    if (d_ori > o_tol && fabsf(d_ori - (float)M_PI) > o_tol) continue;

                    // 3. Radial relative angles invariance check
                    float d_rel_u = angle_diff(eQ->rel_angle_u, eC->rel_angle_u);
                    float d_rel_v = angle_diff(eQ->rel_angle_v, eC->rel_angle_v);
                    bool rel_ok = (d_rel_u <= a_tol && d_rel_v <= a_tol) ||
                                  (fabsf(d_rel_u - (float)M_PI) <= a_tol && fabsf(d_rel_v - (float)M_PI) <= a_tol);
                    if (!rel_ok) continue;

                    // 4. Minutia type compatibility
                    if (eQ->target_type != eC->target_type) continue;

                    // Record edge correspondence
                    if (report->num_edge_matches < GRAPH_MAX_MATCHED_EDGES) {
                        EdgeCorrespondence* ec = &report->edge_matches[report->num_edge_matches++];
                        ec->q_u = u;
                        ec->q_v = v;
                        ec->c_u = uc;
                        ec->c_v = eC->target_idx;
                        ec->distance = eQ->distance;
                    }

                    matched_edges_count++;

                    // Exact rotation delta between candidate and query chord angles
                    float chord_rot = normalize_angle(eC->radial_angle - eQ->radial_angle);
                    float s_rot = sinf(chord_rot);
                    float c_rot = cosf(chord_rot);

                    int idx_u = u * C + uc;
                    vote_matrix[idx_u]++;
                    rot_sin_matrix[idx_u] += s_rot;
                    rot_cos_matrix[idx_u] += c_rot;

                    int vc = eC->target_idx;
                    int idx_v = v * C + vc;
                    vote_matrix[idx_v]++;
                    rot_sin_matrix[idx_v] += s_rot;
                    rot_cos_matrix[idx_v] += c_rot;
                }
            }
        }
    }

    report->matched_edges = matched_edges_count;

    // Greedy 1-to-1 minutiae correspondence assignment
    int* cand_assigned = (int*)calloc(C, sizeof(int));
    int verified_count = 0;

    PointMatchInternal* matches = (PointMatchInternal*)malloc(sizeof(PointMatchInternal) * Q);

    for (int u = 0; u < Q; ++u) {
        int best_c = -1;
        int max_votes = 1;

        for (int c = 0; c < C; ++c) {
            if (cand_assigned[c]) continue;
            int votes = vote_matrix[u * C + c];
            if (votes > max_votes) {
                max_votes = votes;
                best_c = c;
            }
        }

        if (best_c >= 0) {
            cand_assigned[best_c] = 1;
            matches[verified_count].query_idx = u;
            matches[verified_count].cand_idx = best_c;
            matches[verified_count].edge_votes = max_votes;
            matches[verified_count].rot_delta = atan2f(rot_sin_matrix[u * C + best_c], rot_cos_matrix[u * C + best_c]);
            verified_count++;
        }
    }

    report->verified_minutiae = verified_count;

    if (verified_count >= 3) {
        // Robust median/circular mean rotation estimation
        float sum_sin = 0.0f;
        float sum_cos = 0.0f;
        for (int m = 0; m < verified_count; ++m) {
            sum_sin += sinf(matches[m].rot_delta);
            sum_cos += cosf(matches[m].rot_delta);
        }

        float mean_rot = atan2f(sum_sin, sum_cos);
        report->estimated_rotation = mean_rot;
        report->estimated_rotation_deg = mean_rot * (180.0f / (float)M_PI);

        // Store verified point matches into report
        report->num_point_matches = 0;
        for (int m = 0; m < verified_count && m < GRAPH_MAX_MATCHED_POINTS; ++m) {
            PointCorrespondence* pc = &report->point_matches[report->num_point_matches++];
            pc->query_idx = matches[m].query_idx;
            pc->cand_idx = matches[m].cand_idx;
            pc->rotation_delta_deg = matches[m].rot_delta * (180.0f / (float)M_PI);
        }

        // Compute translation offset after rotation: t = p_cand - R(mean_rot) * p_query
        float cos_r = cosf(mean_rot);
        float sin_r = sinf(mean_rot);

        float sum_tx = 0.0f;
        float sum_ty = 0.0f;

        for (int m = 0; m < verified_count; ++m) {
            int qu = matches[m].query_idx;
            int cu = matches[m].cand_idx;

            float rx = cos_r * query_points[qu].x - sin_r * query_points[qu].y;
            float ry = sin_r * query_points[qu].x + cos_r * query_points[qu].y;

            sum_tx += (cand_points[cu].x - rx);
            sum_ty += (cand_points[cu].y - ry);
        }

        float tx = sum_tx / (float)verified_count;
        float ty = sum_ty / (float)verified_count;
        report->estimated_tx = tx;
        report->estimated_ty = ty;

        // Calculate spatial RMSE
        float sum_sq_err = 0.0f;
        for (int m = 0; m < verified_count; ++m) {
            int qu = matches[m].query_idx;
            int cu = matches[m].cand_idx;

            float rx = cos_r * query_points[qu].x - sin_r * query_points[qu].y + tx;
            float ry = sin_r * query_points[qu].x + cos_r * query_points[qu].y + ty;

            float err_x = cand_points[cu].x - rx;
            float err_y = cand_points[cu].y - ry;
            sum_sq_err += (err_x * err_x + err_y * err_y);
        }

        float rmse = sqrtf(sum_sq_err / (float)verified_count);
        report->spatial_rmse = rmse;

        // Forensic scoring model:
        int min_qc = (Q < C) ? Q : C;
        float ratio = (float)verified_count / (float)min_qc;
        float edge_ratio = (query_graph->total_edges > 0)
            ? (float)matched_edges_count / (float)(query_graph->total_edges)
            : 0.0f;
        if (edge_ratio > 1.0f) edge_ratio = 1.0f;

        float spatial_penalty = expf(-rmse / 15.0f);

        float score = (0.65f * ratio + 0.35f * edge_ratio) * spatial_penalty * 100.0f;
        if (score > 100.0f) score = 100.0f;
        if (score < 0.0f) score = 0.0f;
        report->forensic_score = score;
    } else {
        report->forensic_score = 0.0f;
        report->spatial_rmse = 999.0f;
        report->estimated_rotation = 0.0f;
        report->estimated_rotation_deg = 0.0f;
    }

    free(vote_matrix);
    free(rot_sin_matrix);
    free(rot_cos_matrix);
    free(cand_assigned);
    free(matches);

    double t_end = engine_get_time_microseconds();
    report->execution_time_us = t_end - t_start;

    return (report->forensic_score > 25.0f);
}

size_t graph_get_memory_usage(const MinutiaeGraph* graph) {
    if (!graph) return 0;
    return graph->memory_bytes;
}
