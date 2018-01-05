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
 *         Blom's scheme.
 * \author
 *         Daniel Werner <daniel.werner@student.hpi.de>
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "net/llsec/adaptivesec/akes-bloms.h"
#include "lib/csprng.h"
#include "net/linkaddr.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

#ifdef LAMBDA_CONF
#define LAMBDA LAMBDA_CONF
#else /* LAMBDA_CONF */
#define LAMBDA 5
#endif /* LAMBDA_CONF */

/* TODO Preload the mote with a secret symmetric matrix D
    with size LAMBDA x LAMBDA
uint8_t matrix_d[LAMBDA * LAMBDA] = { ..., ..., ...,
                                      ..., ..., ...,
                                      ..., ..., ... } */

static uint16_t row[LAMBDA];
static uint8_t cache[LAMBDA][2];

uint16_t my_pow (int x, int n)
{
    int i;
    int number = 1;

    for(i = 0; i < n; ++i)
        number *= x;

    return number;
}
/*---------------------------------------------------------------------------*/
uint32_t
mod_0x10001(uint32_t divident)
{
  uint16_t least;
  uint16_t most;

  least = divident & 0xFFFF;
  most = divident >> 16;

  if(least >= most) {
    return least - most;
  } else {
    return 0x10001 + least - most;
  }
}
/*---------------------------------------------------------------------------*/
uint32_t
mult_0x10001(uint32_t x, uint32_t y)
{
  if((x <= 0x10001 - 2) || (y <= 0x10001 - 2)) {
    return mod_0x10001(x * y);
  } else if((x == 0x10001 - 1) && (y == 0x10001 - 1)) {
    return 1;
  } else {
    return 2;
  }
}
/*---------------------------------------------------------------------------*/
uint16_t
get_id_hacky(const linkaddr_t *addr)
{
  const char ids[LAMBDA] = { '\x3b', '\x1a', '\xc6', '\x5d', '\x00' };
  int i;
  for(i = 0; i < LAMBDA; i++) {
    if(memcmp(&addr->u8[LINKADDR_SIZE-1], &ids[i], 1) == 0) {
      PRINTF("[Bloms]: Unique id is %02X\n", ids[i]);
      return i;
    }
  }
  PRINTF("[Bloms]: Unique id is unknown, last byte is %02X\n", addr->u8[LINKADDR_SIZE-1]);
  return 3;
}
/*---------------------------------------------------------------------------*/
/**
 * \brief blom wihout using % operators
 * \param a coefficients
 * \param id identifier
 */
uint16_t
blom_0x10001_optimized(uint16_t *a, uint16_t id)
{
  uint8_t i;
  uint32_t exp;
  uint32_t sum;
  sum = a[0];
  exp = id;

  for(i = 1; i < LAMBDA; i++) {
    sum += mult_0x10001(a[i], exp);
    exp *= id;
    
    sum = mod_0x10001(sum);
    exp = mod_0x10001(exp);
  }
  return (uint16_t) sum;
}
/*---------------------------------------------------------------------------*/
static uint8_t *
get_secret_with(const linkaddr_t *addr)
{
  uint16_t id = get_id_hacky(addr);
  if(cache[id][0] == 0 && cache[id][1] == 0) {
    PRINTF("[Bloms]: GENERATE secret.\n");
    uint16_t val = blom_0x10001_optimized(row, id);
    cache[id][0] = val & 0xff;
    cache[id][1] = val >> 8;
  }
  PRINTF("[Bloms]: Secret with id %d is %d %d\n", id, cache[id][0], cache[id][1]);
  return cache[id];
}
/*---------------------------------------------------------------------------*/
static void
update_secret_with(const linkaddr_t *addr, const uint8_t *newSecret, const int secretLen)
{
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  int i,j;
  // TODO Use the preloaded matrix D instead of this generated one
  // HACK: Sync the prng to get the same random matrix on each node
  csprng_init();
  // Create symmetrical matrix D
  uint8_t matrix_d[LAMBDA * LAMBDA];
  for(i = 0; i < LAMBDA; i++) {
    for(j = 0; j <= i; j++) {
        csprng_rand(&matrix_d[i*LAMBDA+j], 1);
        matrix_d[j*LAMBDA+i] = matrix_d[i*LAMBDA+j];
    }
  }

  uint16_t id = get_id_hacky(&linkaddr_node_addr);
  PRINTF("[Bloms]: My id is %d.\n", id);

  // Calculate only the relevant column of the Vandermonde matrix G
  // and use it to calculate the relevant row vector of A
  for(i = 0; i < LAMBDA; i++) {
    row[i] = 0;
    for(j = 0; j < LAMBDA; j++) {
      row[i] += matrix_d[i*LAMBDA+j] * my_pow(id, j);
    }
    PRINTF("[Bloms]: Row %d is %d.\n", i, row[i]);
  }
}
/*---------------------------------------------------------------------------*/
const struct akes_scheme akes_bloms_scheme = {
  init,
  get_secret_with,
  get_secret_with,
  update_secret_with
};
/*---------------------------------------------------------------------------*/
