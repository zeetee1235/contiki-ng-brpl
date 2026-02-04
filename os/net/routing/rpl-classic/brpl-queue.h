#ifndef BRPL_QUEUE_H
#define BRPL_QUEUE_H

#include "net/routing/rpl-classic/rpl-conf.h"
#include <stdint.h>

void brpl_queue_init(uint16_t max_len);
void brpl_queue_on_enqueue(void);
void brpl_queue_on_dequeue(void);
void brpl_queue_on_drop(void);

uint16_t brpl_queue_length(void);
uint16_t brpl_queue_max(void);
uint32_t brpl_queue_enqueued(void);
uint32_t brpl_queue_dropped(void);

#endif /* BRPL_QUEUE_H */
