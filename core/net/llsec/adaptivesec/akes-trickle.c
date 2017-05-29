/*
 * Copyright (c) 2015, Hasso-Plattner-Institut.
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
 *         Trickles HELLOs.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/adaptivesec/akes.h"
#include "net/llsec/adaptivesec/akes-trickle.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "sys/cc.h"
#include <string.h>

#ifdef AKES_TRICKLE_CONF_IMIN
#define IMIN AKES_TRICKLE_CONF_IMIN
#else /* AKES_TRICKLE_CONF_IMIN */
#define IMIN (30 * CLOCK_SECOND)
#endif /* AKES_TRICKLE_CONF_IMIN */

#ifdef AKES_TRICKLE_CONF_IMAX
#define IMAX AKES_TRICKLE_CONF_IMAX
#else /* AKES_TRICKLE_CONF_IMAX */
#define IMAX 8
#endif /* AKES_TRICKLE_CONF_IMAX */

#ifdef AKES_TRICKLE_CONF_REDUNDANCY_CONSTANT
#define REDUNDANCY_CONSTANT AKES_TRICKLE_CONF_REDUNDANCY_CONSTANT
#else /* AKES_TRICKLE_CONF_REDUNDANCY_CONSTANT */
#define REDUNDANCY_CONSTANT 2
#endif /* AKES_TRICKLE_CONF_REDUNDANCY_CONSTANT */

#ifdef AKES_TRICKLE_CONF_MAX_RESET_RATE
#define MAX_RESET_RATE AKES_TRICKLE_CONF_MAX_RESET_RATE
#else /* AKES_TRICKLE_CONF_MAX_RESET_RATE */
#define MAX_RESET_RATE (10 * 60 * CLOCK_SECOND) /* 1 reset per 10min */
#endif /* AKES_TRICKLE_CONF_MAX_RESET_RATE */

#ifdef AKES_TRICKLE_CONF_MAX_CONSECUTIVE_RESETS
#define MAX_CONSECUTIVE_RESETS AKES_TRICKLE_CONF_MAX_CONSECUTIVE_RESETS
#else /* AKES_TRICKLE_CONF_MAX_CONSECUTIVE_RESETS */
#define MAX_CONSECUTIVE_RESETS (3)
#endif /* AKES_TRICKLE_CONF_MAX_CONSECUTIVE_RESETS */

#ifdef AKES_TRICKLE_CONF_ENABLED
#define ENABLED AKES_TRICKLE_CONF_ENABLED
#else /* AKES_TRICKLE_CONF_ENABLED */
#define ENABLED 1
#endif /* AKES_TRICKLE_CONF_ENABLED */

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

#if ENABLED

static void on_interval_expired(void *ptr);
static void on_hello_done(void *ptr);

static uint16_t counter;
/* Counts new neighbors within the current Trickle interval */
static uint8_t new_nbrs_count;
static clock_time_t interval_size;
static struct ctimer trickle_timer;
static struct ctimer hello_timer;

/*---------------------------------------------------------------------------*/
static clock_time_t
get_random_time(clock_time_t min, clock_time_t max)
{
  return min + (((max - min) * random_rand()) / RANDOM_RAND_MAX);
}
/*---------------------------------------------------------------------------*/
static void
reset_trickle_info(void)
{
  struct akes_nbr_entry *next;

  next = akes_nbr_head();
  while(next) {
    if(next->permanent) {
      next->permanent->sent_authentic_hello = 0;
    }
    next = akes_nbr_next(next);
  }
}
/*---------------------------------------------------------------------------*/
void
akes_trickle_on_fresh_authentic_hello(struct akes_nbr *sender)
{
  if(!sender->sent_authentic_hello) {
    sender->sent_authentic_hello = 1;
    counter++;
  }
}
/*---------------------------------------------------------------------------*/
/* Corresponds to Rule 4 of Trickle */
static void
on_timeout(void *ptr)
{
  if(counter >= REDUNDANCY_CONSTANT) {
    PRINTF("akes-trickle: Suppressed HELLO\n");
  } else if(!ctimer_expired(&hello_timer)) {
    PRINTF("akes-trickle: Still waiting for HELLOACKs\n");
  } else {
    PRINTF("akes-trickle: Broadcasting HELLO\n");
    akes_broadcast_hello();
    reset_trickle_info();
    ctimer_set(&hello_timer,
        (AKES_MAX_WAITING_PERIOD * CLOCK_SECOND + CLOCK_SECOND /* leeway */),
        on_hello_done,
        NULL);
  }

  ctimer_set(&trickle_timer,
      interval_size - trickle_timer.etimer.timer.interval,
      on_interval_expired,
      NULL);
}
/*---------------------------------------------------------------------------*/
static void
on_hello_done(void *ptr)
{
  akes_change_hello_challenge();
}
/*---------------------------------------------------------------------------*/
/* Corresponds to Rule 5 of Trickle */
static void
on_interval_expired(void *ptr)
{
  /* double interval size */
  interval_size = MIN(2 * interval_size, IMIN << IMAX);

  new_nbrs_count = 0;
  counter = 0;

  ctimer_set(&trickle_timer,
      get_random_time(interval_size / 2, interval_size),
      on_timeout,
      NULL);
  PRINTF("akes-trickle: I=%lus t=%lus\n",
      interval_size / CLOCK_SECOND,
      trickle_timer.etimer.timer.interval / CLOCK_SECOND);
}
/*---------------------------------------------------------------------------*/
void
akes_trickle_on_new_nbr(void)
{
  PRINTF("akes-trickle: New neighbor\n");

  if(++new_nbrs_count >= MAX(akes_nbr_count(AKES_NBR_PERMANENT) / 4, 1)) {
    akes_trickle_reset();
  }
}
/*---------------------------------------------------------------------------*/
void
akes_trickle_stop(void)
{
  PRINTF("akes-trickle: Stopping Trickle\n");

  ctimer_stop(&trickle_timer);
  ctimer_stop(&hello_timer);
}
/*---------------------------------------------------------------------------*/
/* Corresponds to Rule 6 of Trickle */
void
akes_trickle_reset(void)
{
  if(interval_size == IMIN) {
    PRINTF("akes-trickle: Not resetting Trickle since I = I_min\n");
    return;
  }

  PRINTF("akes-trickle: Resetting Trickle\n");

  ctimer_stop(&trickle_timer);
  interval_size = IMIN / 2;
  on_interval_expired(NULL);
}
/*---------------------------------------------------------------------------*/
void
akes_trickle_start(void)
{
  PRINTF("akes-trickle: Starting Trickle\n");

  akes_change_hello_challenge();
  interval_size = get_random_time(IMIN, IMIN << IMAX);

  on_timeout(NULL);
}
/*---------------------------------------------------------------------------*/
#else /* ENABLED */
void
akes_trickle_on_fresh_authentic_hello(struct akes_nbr *sender)
{

}
/*---------------------------------------------------------------------------*/
void
akes_trickle_on_new_nbr(void)
{

}
/*---------------------------------------------------------------------------*/
void
akes_trickle_stop(void)
{

}
/*---------------------------------------------------------------------------*/
void
akes_trickle_reset(void)
{

}
/*---------------------------------------------------------------------------*/
void
akes_trickle_start(void)
{

}
#endif /* ENABLED */
/*---------------------------------------------------------------------------*/
