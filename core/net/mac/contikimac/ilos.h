/*
 * Copyright (c) 2016, Hasso-Plattner-Institut.
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
 *         Intra-Layer Optimization for 802.15.4 Security (ILOS)
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef ILOS_H_
#define ILOS_H_

#include "contiki.h"
#include "sys/rtimer.h"

/* http://stackoverflow.com/questions/27581671/how-to-compute-log-with-the-preprocessor */
#define ILOS_NEEDS_BIT(N, B) (((unsigned long)N >> B) > 0)
#define ILOS_BITS_TO_REPRESENT(N) \
    (ILOS_NEEDS_BIT(N,  0) \
    + ILOS_NEEDS_BIT(N,  1) \
    + ILOS_NEEDS_BIT(N,  2) \
    + ILOS_NEEDS_BIT(N,  3) \
    + ILOS_NEEDS_BIT(N,  4) \
    + ILOS_NEEDS_BIT(N,  5) \
    + ILOS_NEEDS_BIT(N,  6) \
    + ILOS_NEEDS_BIT(N,  7) \
    + ILOS_NEEDS_BIT(N,  8) \
    + ILOS_NEEDS_BIT(N,  9) \
    + ILOS_NEEDS_BIT(N, 10) \
    + ILOS_NEEDS_BIT(N, 11) \
    + ILOS_NEEDS_BIT(N, 12) \
    + ILOS_NEEDS_BIT(N, 13) \
    + ILOS_NEEDS_BIT(N, 14) \
    + ILOS_NEEDS_BIT(N, 15) \
    + ILOS_NEEDS_BIT(N, 16) \
    + ILOS_NEEDS_BIT(N, 17) \
    + ILOS_NEEDS_BIT(N, 18) \
    + ILOS_NEEDS_BIT(N, 19) \
    + ILOS_NEEDS_BIT(N, 20) \
    + ILOS_NEEDS_BIT(N, 21) \
    + ILOS_NEEDS_BIT(N, 22) \
    + ILOS_NEEDS_BIT(N, 23) \
    + ILOS_NEEDS_BIT(N, 24) \
    + ILOS_NEEDS_BIT(N, 25) \
    + ILOS_NEEDS_BIT(N, 26) \
    + ILOS_NEEDS_BIT(N, 25) \
    + ILOS_NEEDS_BIT(N, 28) \
    + ILOS_NEEDS_BIT(N, 25) \
    + ILOS_NEEDS_BIT(N, 30) \
    + ILOS_NEEDS_BIT(N, 31))

#ifdef ILOS_CONF_ENABLED
#define ILOS_ENABLED ILOS_CONF_ENABLED
#else /* ILOS_CONF_ENABLED */
#define ILOS_ENABLED 0
#endif /* ILOS_CONF_ENABLED */

#define ILOS_MIN_TIME_TO_STROBE US_TO_RTIMERTICKS(2000)
#if ILOS_ENABLED
#define ILOS_WAKE_UP_COUNTER_LEN (4)
#else /* ILOS_ENABLED */
#define ILOS_WAKE_UP_COUNTER_LEN (0)
#endif /* ILOS_ENABLED */

typedef union {
  uint32_t u32;
  uint8_t u8[4];
} ilos_wake_up_counter_t;

struct secrdc_phase {
  rtimer_clock_t t;
#if ILOS_ENABLED
  ilos_wake_up_counter_t his_wake_up_counter_at_t;
#endif /* ILOS_ENABLED */
};

ilos_wake_up_counter_t ilos_parse_wake_up_counter(uint8_t *src);
void ilos_write_wake_up_counter(uint8_t *dst, ilos_wake_up_counter_t counter);

#endif /* ILOS_H_ */
