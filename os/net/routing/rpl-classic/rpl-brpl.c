#include "contiki.h"
#include "net/routing/rpl-classic/rpl.h"
#include "net/routing/rpl-classic/rpl-conf.h"
#include "net/routing/rpl-classic/rpl-private.h"
#include "net/routing/rpl-classic/brpl-queue.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/nbr-table.h"
#include "net/linkaddr.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>

#define BRPL_SCALE 1000

#if BRPL_CONF_ENABLE

extern rpl_of_t rpl_mrhof;
NBR_TABLE_DECLARE(rpl_parents);

/* Forward declarations */
static uint16_t brpl_parent_id(rpl_parent_t *p);
static uint16_t brpl_self_id(void);

#ifndef TRUST_SCALE
#define TRUST_SCALE 1000
#endif
#ifndef TRUST_MIN
#define TRUST_MIN 300
#endif
#ifndef TRUST_PENALTY_GAMMA
#define TRUST_PENALTY_GAMMA 1
#endif
#ifndef TRUST_LAMBDA
#define TRUST_LAMBDA 0
#endif
#ifdef TRUST_LAMBDA_CONF
#undef TRUST_LAMBDA
#define TRUST_LAMBDA TRUST_LAMBDA_CONF
#endif
#ifdef TRUST_PENALTY_GAMMA_CONF
#undef TRUST_PENALTY_GAMMA
#define TRUST_PENALTY_GAMMA TRUST_PENALTY_GAMMA_CONF
#endif

/*---------------------------------------------------------------------------*/
/* Trust computation functions */
/*---------------------------------------------------------------------------*/

/* Compute Sinkhole Advertisement Trust (based on rank plausibility) */
static uint16_t
brpl_compute_trust_sink_adv(rpl_parent_t *p, rpl_dag_t *dag)
{
#if BRPL_CONF_TRUST_ENABLE
  if(p == NULL || dag == NULL) {
    return TRUST_SCALE;
  }
  
  /* Compute rank delta: R_j + MIN_HOPRANKINC - R_i */
  int32_t rank_delta = (int32_t)p->rank + RPL_MIN_HOPRANKINC - (int32_t)dag->rank;
  
  /* Compute anomaly score: max(0, -rank_delta - tau) */
  int32_t anomaly = rank_delta < -BRPL_CONF_TAU_RANK ? 
                    (-rank_delta - BRPL_CONF_TAU_RANK) : 0;
  
  /* Trust = exp(-lambda * anomaly) 
   * Approximation: exp(-x) ≈ 1 / (1 + x) for small x */
  uint32_t penalty = ((uint32_t)anomaly * BRPL_CONF_LAMBDA_SH_ADV) / 1000;
  uint16_t trust = (TRUST_SCALE * TRUST_SCALE) / (TRUST_SCALE + penalty);
  
  return trust;
#else
  return TRUST_SCALE;
#endif
}

/* Compute Sinkhole Stability Trust (based on rank stability after parent selection) */
static uint16_t
brpl_compute_trust_sink_stab(rpl_parent_t *p, rpl_dag_t *dag)
{
#if BRPL_CONF_TRUST_ENABLE
  if(p == NULL || dag == NULL) {
    return TRUST_SCALE;
  }
  
  /* Check if we have history */
  clock_time_t now = clock_seconds();
  if(p->last_rank_update == 0 || 
     (now - p->last_rank_update) < BRPL_CONF_STABILITY_WINDOW) {
    /* Not enough history yet */
    return TRUST_SCALE;
  }
  
  /* Compute rank increase */
  int32_t rank_increase = (int32_t)dag->rank - (int32_t)p->last_rank;
  
  /* Compute instability penalty: max(0, rank_increase - kappa) */
  int32_t instability = rank_increase > BRPL_CONF_KAPPA_RANK ?
                        (rank_increase - BRPL_CONF_KAPPA_RANK) : 0;
  
  /* Trust = exp(-lambda * instability) */
  uint32_t penalty = ((uint32_t)instability * BRPL_CONF_LAMBDA_SH_STAB) / 1000;
  uint16_t trust = (TRUST_SCALE * TRUST_SCALE) / (TRUST_SCALE + penalty);
  
  return trust;
#else
  return TRUST_SCALE;
#endif
}

/* Compute Grayhole Trust (data-plane, from external source) */
__attribute__((weak)) uint16_t brpl_trust_get(uint16_t node_id)
{
  (void)node_id;
  return TRUST_SCALE;
}

/* Update trust values for a parent with EWMA smoothing */
static void
brpl_update_trust(rpl_parent_t *p, rpl_dag_t *dag)
{
#if BRPL_CONF_TRUST_ENABLE
  if(p == NULL || dag == NULL) {
    return;
  }
  
  uint16_t beta = BRPL_CONF_TRUST_BETA; /* 0-1000 scale */
  
  /* Compute new trust values */
  uint16_t new_sink_adv = brpl_compute_trust_sink_adv(p, dag);
  uint16_t new_sink_stab = brpl_compute_trust_sink_stab(p, dag);
  uint16_t new_gray = brpl_trust_get(brpl_parent_id(p));
  
  /* EWMA smoothing */
  p->trust_sink_adv = ((TRUST_SCALE - beta) * p->trust_sink_adv + 
                       beta * new_sink_adv) / TRUST_SCALE;
  p->trust_sink_stab = ((TRUST_SCALE - beta) * p->trust_sink_stab + 
                        beta * new_sink_stab) / TRUST_SCALE;
  p->trust_gray = ((TRUST_SCALE - beta) * p->trust_gray + 
                   beta * new_gray) / TRUST_SCALE;
  
  /* Combine sinkhole trust components: T_sink = (T_adv^0.5) * (T_stab^0.5) 
   * Approximation: geometric mean */
  uint32_t sink_combined = ((uint32_t)p->trust_sink_adv * p->trust_sink_stab) / TRUST_SCALE;
  uint16_t trust_sink = (uint16_t)sink_combined;
  
  /* Combine gray and sink: T_total = (T_gray^alpha) * (T_sink^(1-alpha))
   * Using alpha = 0.5 for equal weighting */
  uint16_t alpha = BRPL_CONF_TRUST_ALPHA; /* 0-1000 scale */
  p->trust_total = ((alpha * p->trust_gray + (TRUST_SCALE - alpha) * trust_sink)) / TRUST_SCALE;
  
  /* Clamp to minimum */
  if(p->trust_total < TRUST_MIN) {
    p->trust_total = TRUST_MIN;
  }
#endif
}

/* Initialize trust values for a new parent */
__attribute__((unused))
static void
brpl_init_trust(rpl_parent_t *p)
{
#if BRPL_CONF_TRUST_ENABLE
  if(p == NULL) {
    return;
  }
  
  p->trust_gray = TRUST_SCALE;
  p->trust_sink_adv = TRUST_SCALE;
  p->trust_sink_stab = TRUST_SCALE;
  p->trust_total = TRUST_SCALE;
  p->last_rank = 0;
  p->last_rank_update = 0;
  p->packets_sent = 0;
  p->packets_dropped = 0;
#endif
}

/* Helper functions */
static uint16_t
brpl_parent_id(rpl_parent_t *p)
{
  const linkaddr_t *lladdr = rpl_get_parent_lladdr(p);
  if(lladdr == NULL) {
    return 0xFFFF;
  }
  return (uint16_t)lladdr->u8[LINKADDR_SIZE - 1];
}

static uint16_t
brpl_self_id(void)
{
  return (uint16_t)linkaddr_node_addr.u8[LINKADDR_SIZE - 1];
}

#if defined(CSV_VERBOSE_LOGGING) && CSV_VERBOSE_LOGGING
#if defined(CSV_LOG_SAMPLE_RATE)
#define BRPL_LOG_SAMPLE_RATE CSV_LOG_SAMPLE_RATE
#else
#define BRPL_LOG_SAMPLE_RATE 1
#endif

static uint32_t brpl_log_counter;

static int
brpl_should_log(void)
{
  brpl_log_counter++;
  if(BRPL_LOG_SAMPLE_RATE == 0) {
    return 0;
  }
  return (brpl_log_counter % BRPL_LOG_SAMPLE_RATE) == 0;
}
#endif

static uint16_t
brpl_trust_clamped(rpl_parent_t *p)
{
#if BRPL_CONF_TRUST_ENABLE
  if(p == NULL) {
    return TRUST_SCALE;
  }
  uint16_t trust = p->trust_total;
  if(trust < TRUST_MIN) {
    trust = TRUST_MIN;
  }
  return trust;
#else
  uint16_t trust = brpl_trust_get(brpl_parent_id(p));
  if(trust < TRUST_MIN) {
    trust = TRUST_MIN;
  }
  return trust;
#endif
}

static int32_t
brpl_apply_trust_penalty(int32_t weight, rpl_parent_t *p)
{
  uint16_t trust = brpl_trust_clamped(p);
  uint16_t distrust = TRUST_SCALE - trust;
  
  /* Apply penalty using gamma exponent and lambda weight:
   * BP^trust = BP * (T^gamma) / (1 + lambda * (1-T)^gamma) */
  uint16_t lambda = BRPL_CONF_TRUST_LAMBDA_PENALTY; /* scaled by 1000 */
  
#if TRUST_PENALTY_GAMMA >= 2
  /* For gamma = 2: T^2 and (1-T)^2 */
  int64_t num = (int64_t)trust * trust;
  int64_t distrust_sq = (int64_t)distrust * distrust;
  int64_t den = (int64_t)TRUST_SCALE * TRUST_SCALE
                + ((int64_t)lambda * distrust_sq) / TRUST_SCALE;
#else
  /* For gamma = 1: linear */
  int64_t num = (int64_t)trust;
  int64_t den = (int64_t)TRUST_SCALE
                + ((int64_t)lambda * distrust) / TRUST_SCALE;
#endif
  
  if(den <= 0) {
    return weight;
  }
  return (int32_t)(((int64_t)weight * num) / den);
}

static uint16_t
brpl_scale_ratio(uint32_t num, uint32_t den)
{
  if(den == 0) {
    return 0;
  }
  uint32_t val = (num * BRPL_SCALE) / den;
  if(val > BRPL_SCALE) {
    val = BRPL_SCALE;
  }
  return (uint16_t)val;
}

static uint16_t
brpl_symmetric_diff(const linkaddr_t *prev, uint16_t prev_count,
                    const linkaddr_t *curr, uint16_t curr_count)
{
  uint16_t diff = 0;
  uint16_t intersection = 0;

  for(uint16_t i = 0; i < prev_count; i++) {
    for(uint16_t j = 0; j < curr_count; j++) {
      if(linkaddr_cmp(&prev[i], &curr[j])) {
        intersection++;
        break;
      }
    }
  }
  diff = prev_count + curr_count - 2 * intersection;
  uint16_t uni = prev_count + curr_count - intersection;
  if(uni == 0) {
    return 0;
  }
  return brpl_scale_ratio(diff, uni);
}

static void
brpl_update_state(rpl_dag_t *dag)
{
  uint16_t qx = brpl_queue_length();
  uint16_t qmax = brpl_queue_max();
  uint16_t lambda = BRPL_CONF_QUEUE_EWMA_ALPHA;

  dag->brpl_q_avg = (uint16_t)(((BRPL_SCALE - lambda) * dag->brpl_q_avg +
                               lambda * qx) / BRPL_SCALE);

  uint16_t rho = brpl_scale_ratio(dag->brpl_q_avg, qmax);

  static linkaddr_t prev_neighbors[NBR_TABLE_MAX_NEIGHBORS];
  static linkaddr_t curr_neighbors[NBR_TABLE_MAX_NEIGHBORS];
  uint16_t prev_count = dag->brpl_last_nbr_count;
  uint16_t curr_count = 0;

  clock_time_t now = clock_time();
  if(dag->brpl_last_beta_update == 0) {
    dag->brpl_last_beta_update = now;
    dag->brpl_last_nbr_count = 0;
    dag->brpl_beta = BRPL_SCALE;
  }

  if(now - dag->brpl_last_beta_update >= (clock_time_t)(BRPL_CONF_BETA_WINDOW_SECONDS * CLOCK_SECOND)) {
    for(uip_ds6_nbr_t *n = uip_ds6_nbr_head(); n != NULL && curr_count < NBR_TABLE_MAX_NEIGHBORS; n = uip_ds6_nbr_next(n)) {
      linkaddr_copy(&curr_neighbors[curr_count], (const linkaddr_t *)uip_ds6_nbr_get_ll(n));
      curr_count++;
    }
    if(prev_count > NBR_TABLE_MAX_NEIGHBORS) {
      prev_count = NBR_TABLE_MAX_NEIGHBORS;
    }

    uint16_t beta = brpl_symmetric_diff(prev_neighbors, prev_count, curr_neighbors, curr_count);
    dag->brpl_beta = beta;

    memcpy(prev_neighbors, curr_neighbors, curr_count * sizeof(linkaddr_t));
    dag->brpl_last_nbr_count = curr_count;
    dag->brpl_last_beta_update = now;
  }

  uint16_t theta_part = (uint16_t)((BRPL_SCALE - dag->brpl_beta) * (BRPL_SCALE - rho) / BRPL_SCALE);
  dag->brpl_theta = (uint16_t)(dag->brpl_beta + theta_part);

  dag->brpl_pmax = 1;
  for(rpl_parent_t *p = nbr_table_head(rpl_parents); p != NULL; p = nbr_table_next(rpl_parents, p)) {
    if(p->dag == dag && p->rank != RPL_INFINITE_RANK) {
      uint32_t p_tilde = (uint32_t)rpl_get_parent_link_metric(p) + (uint32_t)p->rank;
      if(p_tilde > dag->brpl_pmax) {
        dag->brpl_pmax = p_tilde;
      }
    }
  }

#if defined(CSV_VERBOSE_LOGGING) && CSV_VERBOSE_LOGGING
  if(brpl_should_log()) {
    printf("CSV,BRPL_STATE,%u,%u,%u,%u,%u,%u,%lu\n",
           (unsigned)brpl_self_id(),
           (unsigned)qx,
           (unsigned)qmax,
           (unsigned)dag->brpl_q_avg,
           (unsigned)rho,
           (unsigned)dag->brpl_theta,
           (unsigned long)dag->brpl_pmax);
  }
#endif
}

static uint16_t
brpl_neighbor_queue(rpl_parent_t *p, rpl_dag_t *dag, uint16_t qx, uint16_t qmax)
{
  if(p->brpl_queue_valid && p->brpl_queue_max > 0) {
    return p->brpl_queue;
  }
  if(dag == NULL || dag->rank == 0) {
    return qx;
  }
  uint32_t est = ((uint32_t)qx * p->rank) / dag->rank;
  if(est > qmax) {
    est = qmax;
  }
  return (uint16_t)est;
}

static int32_t
brpl_weight_base(rpl_parent_t *p)
{
  rpl_dag_t *dag = p->dag;
  brpl_update_state(dag);

  uint16_t qx = brpl_queue_length();
  uint16_t qmax = brpl_queue_max();
  uint16_t qy = brpl_neighbor_queue(p, dag, qx, qmax);
  int32_t delta_q = (int32_t)qx - (int32_t)qy;

  uint32_t p_tilde = (uint32_t)rpl_get_parent_link_metric(p) + (uint32_t)p->rank;
  uint16_t p_norm = brpl_scale_ratio(p_tilde, dag->brpl_pmax);
  int32_t dq_norm = qmax > 0 ? (delta_q * BRPL_SCALE) / (int32_t)qmax : 0;

  int32_t theta = dag->brpl_theta;
  int32_t weight = (theta * (int32_t)p_norm - (BRPL_SCALE - theta) * dq_norm) / BRPL_SCALE;

#if defined(CSV_VERBOSE_LOGGING) && CSV_VERBOSE_LOGGING
  if(brpl_should_log()) {
    uint16_t link_metric = rpl_get_parent_link_metric(p);
    printf("CSV,BRPL_METRIC,%u,%u,%u,%u,%lu\n",
           (unsigned)brpl_self_id(),
           (unsigned)brpl_parent_id(p),
           (unsigned)link_metric,
           (unsigned)p->rank,
           (unsigned long)p_tilde);
    printf("CSV,BRPL_WEIGHT,%u,%u,%u,%u,%u,%lu,%u,%ld,%ld,%ld\n",
           (unsigned)brpl_self_id(),
           (unsigned)brpl_parent_id(p),
           (unsigned)qx,
           (unsigned)qy,
           (unsigned)qmax,
           (unsigned long)p_tilde,
           (unsigned)p_norm,
           (long)dq_norm,
           (long)theta,
           (long)weight);
  }
#endif
  return weight;
}

static rpl_parent_t *
brpl_best_parent(rpl_parent_t *p1, rpl_parent_t *p2)
{
  if(p1 == NULL) {
    return p2;
  }
  if(p2 == NULL) {
    return p1;
  }
  int32_t w1_base = brpl_weight_base(p1);
  int32_t w2_base = brpl_weight_base(p2);
  int32_t w1 = brpl_apply_trust_penalty(w1_base, p1);
  int32_t w2 = brpl_apply_trust_penalty(w2_base, p2);
  rpl_parent_t *best = (w2 < w1) ? p2 : p1;
#if defined(CSV_VERBOSE_LOGGING) && CSV_VERBOSE_LOGGING
  if(brpl_should_log()) {
    uint16_t t1 = brpl_trust_clamped(p1);
    uint16_t t2 = brpl_trust_clamped(p2);
    printf("CSV,BRPL_TRUST,%u,%u,%u,%u,%u,%ld\n",
           (unsigned)brpl_self_id(),
           (unsigned)brpl_parent_id(p1),
           (unsigned)t1,
           (unsigned)TRUST_MIN,
           (unsigned)TRUST_PENALTY_GAMMA,
           (long)w1);
    printf("CSV,BRPL_TRUST,%u,%u,%u,%u,%u,%ld\n",
           (unsigned)brpl_self_id(),
           (unsigned)brpl_parent_id(p2),
           (unsigned)t2,
           (unsigned)TRUST_MIN,
           (unsigned)TRUST_PENALTY_GAMMA,
           (long)w2);
    printf("PARENT_CANDIDATE: self=%u id=%u BP=%ld T=%.3f gamma=%u lambda=%u score=%ld\n",
           (unsigned)brpl_self_id(),
           (unsigned)brpl_parent_id(p1),
           (long)w1_base,
           (double)t1 / (double)TRUST_SCALE,
           (unsigned)TRUST_PENALTY_GAMMA,
           (unsigned)TRUST_LAMBDA,
           (long)w1);
    printf("PARENT_CANDIDATE: self=%u id=%u BP=%ld T=%.3f gamma=%u lambda=%u score=%ld\n",
           (unsigned)brpl_self_id(),
           (unsigned)brpl_parent_id(p2),
           (long)w2_base,
           (double)t2 / (double)TRUST_SCALE,
           (unsigned)TRUST_PENALTY_GAMMA,
           (unsigned)TRUST_LAMBDA,
           (long)w2);
    printf("CSV,BRPL_BEST,%u,%u,%ld,%u,%ld,%u\n",
           (unsigned)brpl_self_id(),
           (unsigned)brpl_parent_id(p1),
           (long)w1,
           (unsigned)brpl_parent_id(p2),
           (long)w2,
           (unsigned)brpl_parent_id(best));
  }
#endif
  return best;
}

static void
brpl_reset(rpl_dag_t *dag)
{
#if defined(CSV_VERBOSE_LOGGING) && CSV_VERBOSE_LOGGING
  static uint8_t brpl_params_logged = 0;
  if(!brpl_params_logged) {
    printf("BRPL_PARAMS: lambda=%u gamma=%u trust_min=%u\n",
           (unsigned)TRUST_LAMBDA,
           (unsigned)TRUST_PENALTY_GAMMA,
           (unsigned)TRUST_MIN);
    brpl_params_logged = 1;
  }
#endif
  if(dag == NULL) {
    return;
  }
  dag->brpl_theta = BRPL_SCALE;
  dag->brpl_beta = BRPL_SCALE;
  dag->brpl_q_avg = 0;
  dag->brpl_pmax = 1;
  dag->brpl_last_beta_update = 0;
  dag->brpl_last_nbr_count = 0;
}

static uint16_t
brpl_parent_link_metric(rpl_parent_t *p)
{
  return rpl_mrhof.parent_link_metric(p);
}

static int
brpl_parent_has_usable_link(rpl_parent_t *p)
{
  return rpl_mrhof.parent_has_usable_link(p);
}

static uint16_t
brpl_parent_path_cost(rpl_parent_t *p)
{
  return rpl_mrhof.parent_path_cost(p);
}

static rpl_rank_t
brpl_rank_via_parent(rpl_parent_t *p)
{
  return rpl_mrhof.rank_via_parent(p);
}

/* Public function to update trust for a parent */
void
brpl_update_parent_trust(rpl_parent_t *p, rpl_dag_t *dag)
{
#if BRPL_CONF_TRUST_ENABLE
  brpl_update_trust(p, dag);
#endif
}

rpl_of_t rpl_brpl = {
  .reset = brpl_reset,
#if RPL_WITH_DAO_ACK
  .dao_ack_callback = NULL,
#endif
  .parent_link_metric = brpl_parent_link_metric,
  .parent_has_usable_link = brpl_parent_has_usable_link,
  .parent_path_cost = brpl_parent_path_cost,
  .rank_via_parent = brpl_rank_via_parent,
  .best_parent = brpl_best_parent,
  .best_dag = NULL,
  .update_metric_container = NULL,
  .ocp = RPL_OCP_BRPL,
};
#else
rpl_of_t rpl_brpl = { 0 };
#endif
