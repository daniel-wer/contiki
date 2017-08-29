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
 *         Node revocation list.
 * \author
 *         Daniel Werner <daniel.werner@student.hpi.de>
 */

#include <stdint.h>
#include "net/llsec/adaptivesec/nrl.h"

#ifdef REVOCATION_LIST_LENGTH_CONF
#define REVOCATION_LIST_LENGTH REVOCATION_LIST_LENGTH_CONF
#else /* REVOCATION_LIST_LENGTH_CONF */
#define REVOCATION_LIST_LENGTH 50
#endif /* REVOCATION_LIST_LENGTH_CONF */

#if KEY_REVOCATION_ENABLED
static const linkaddr_t *nrl[REVOCATION_LIST_LENGTH];
static uint16_t nrlLength = 0;


int
is_revoked(const linkaddr_t *addr)
{
  int i;
  for(i = 0; i < nrlLength; i++) {
    if(memcmp(&nrl[i], addr, LINKADDR_SIZE) == 0) {
      return 1;
    }
  }
  return 0;
}

int
revoke(const linkaddr_t *addr)
{
  if(nrlLength < REVOCATION_LIST_LENGTH) {
    memcpy(&nrl[nrlLength], addr, LINKADDR_SIZE);
    return ++nrlLength;
  } else {
    return -1;
  }
}

void
clear()
{
  nrlLength = 0;
}
#endif /* KEY_REVOCATION_ENABLED */