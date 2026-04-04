#ifndef BRPL_SWITCH_POLICY_H_
#define BRPL_SWITCH_POLICY_H_

#include <stdint.h>

/* Unified switch policy decision passed from trust engine to BRPL selector.
 * - block_switch: force keep preferred parent
 * - bypass_dwell: ignore default dwell gate for this switch
 * - extra_margin_abs: extra absolute margin required on top of BRPL base
 * - reason_code: implementation-defined reason for logging/debugging
 */
typedef struct brpl_switch_policy_decision {
  uint16_t extra_margin_abs;
  uint8_t block_switch;
  uint8_t bypass_dwell;
  uint8_t reason_code;
} brpl_switch_policy_decision_t;

/* Returns 1 if decision was produced. Implementations should always fill out.
 * Default implementation in rpl-brpl.c composes legacy hooks. */
int brpl_switch_policy_get(uint16_t preferred_id,
                           uint16_t challenger_id,
                           int32_t preferred_weight,
                           int32_t challenger_weight,
                           uint8_t preferred_allowed,
                           brpl_switch_policy_decision_t *out);

#endif /* BRPL_SWITCH_POLICY_H_ */
