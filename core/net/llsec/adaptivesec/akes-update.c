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
 *         Updates group key and re-distributes it to all neighbors
 * \author
 *         Daniel Werner <daniel.werner@student.hpi.de>
 */

#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/llsec/adaptivesec/akes-update.h"
#include "net/llsec/adaptivesec/akes.h"

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

void
akes_print_group_key(void)
{
  PRINTF("[KeyRev] Broadcast key:");
  int i;
  for(i = 0; i < AES_128_KEY_LENGTH; i++) {
    PRINTF("%x", adaptivesec_group_key[i]);
  }
  PRINTF("\n");
}
/*---------------------------------------------------------------------------*/
void
akes_update_group_key(void)
{
  static struct akes_nbr_entry *next;

  akes_print_group_key();

  adaptivesec_group_key_init();
  PRINTF("[KeyRev]: Renew broadcast key\n");
  
  akes_print_group_key();

  PRINTF("[KeyRev]: Number of permanent neighbors is %d\n", akes_nbr_count(AKES_NBR_PERMANENT));
  next = akes_nbr_head();
  while(next) {
    if(!next->permanent) {
      next = akes_nbr_next(next);
      continue;
    }

    /* send UPDATE */
    akes_send_update(next);
    PRINTF("[KeyRev]: Sent UPDATE\n");
    next = akes_nbr_next(next);
  }
}
/*---------------------------------------------------------------------------*/
