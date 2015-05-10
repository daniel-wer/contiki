/*
 * Copyright (c) 2017, Hasso-Plattner-Institut.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Leaky Bucket Counter (LBC)
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "lib/leaky-bucket.h"
#include "sys/cc.h"
#include <string.h>

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

/*---------------------------------------------------------------------------*/
static void
leak(void *ptr)
{
  struct leaky_bucket *lb;

  lb = (struct leaky_bucket *) ptr;
  lb->filling_level--;

  PRINTF("leaky-bucket#leak: (%p) filling_level = %i\n",
      lb, lb->filling_level);

  if(lb->filling_level) {
    ctimer_reset(&lb->leakage_timer);
  }
}
/*---------------------------------------------------------------------------*/
void
leaky_bucket_init(struct leaky_bucket *lb,
    uint16_t capacity,
    clock_time_t leakage_duration)
{
  PRINTF("leaky-bucket#init: (%p) capacity = %i; leakage_duration = %lus\n",
      lb, capacity, leakage_duration / CLOCK_SECOND);
  memset(lb, 0, sizeof(struct leaky_bucket));
  lb->capacity = capacity;
  lb->leakage_duration = leakage_duration;
}
/*---------------------------------------------------------------------------*/
void
leaky_bucket_pour(struct leaky_bucket *lb, uint16_t drop_size)
{
  lb->filling_level = MIN(lb->filling_level + drop_size, lb->capacity);

  PRINTF("leaky-bucket#pour: (%p) filling_level = %i\n",
      lb, lb->filling_level);

  if(!ctimer_expired(&lb->leakage_timer)) {
    /* already scheduled */
    return;
  }

  if(!lb->filling_level) {
    /* nothing to leak */
    return;
  }

  ctimer_set(&lb->leakage_timer, lb->leakage_duration, leak, lb);
}
/*---------------------------------------------------------------------------*/
int
leaky_bucket_is_full(struct leaky_bucket *lb)
{
  return lb->filling_level == lb->capacity;
}
/*---------------------------------------------------------------------------*/
