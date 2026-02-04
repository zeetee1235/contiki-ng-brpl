#include "net/routing/rpl-classic/brpl-queue.h"

static uint16_t queue_len = 0;
static uint16_t queue_max = 0;
static uint32_t queue_enqueued = 0;
static uint32_t queue_dropped = 0;

void
brpl_queue_init(uint16_t max_len)
{
  queue_len = 0;
  queue_max = max_len;
  queue_enqueued = 0;
  queue_dropped = 0;
}

void
brpl_queue_on_enqueue(void)
{
  if(queue_len < queue_max || queue_max == 0) {
    queue_len++;
  }
  queue_enqueued++;
}

void
brpl_queue_on_dequeue(void)
{
  if(queue_len > 0) {
    queue_len--;
  }
}

void
brpl_queue_on_drop(void)
{
  queue_dropped++;
}

uint16_t
brpl_queue_length(void)
{
  return queue_len;
}

uint16_t
brpl_queue_max(void)
{
  return queue_max;
}

uint32_t
brpl_queue_enqueued(void)
{
  return queue_enqueued;
}

uint32_t
brpl_queue_dropped(void)
{
  return queue_dropped;
}
