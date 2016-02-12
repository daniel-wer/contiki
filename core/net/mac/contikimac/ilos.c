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

#include "net/mac/contikimac/ilos.h"
#include "net/llsec/llsec802154.h"
#include "net/packetbuf.h"
#include "net/llsec/adaptivesec/akes-nbr.h"

#if ILOS_ENABLED
uint8_t ilos_my_broadcast_seqno;

/*---------------------------------------------------------------------------*/
ilos_wake_up_counter_t
ilos_parse_wake_up_counter(uint8_t *src)
{
  ilos_wake_up_counter_t counter;

  memcpy(counter.u8, src, 4);
  counter.u32 = LLSEC802154_HTONL(counter.u32);
  return counter;
}
/*---------------------------------------------------------------------------*/
void
ilos_write_wake_up_counter(uint8_t *dst, ilos_wake_up_counter_t counter)
{
  counter.u32 = LLSEC802154_HTONL(counter.u32);
  memcpy(dst, counter.u8, 4);
}
/*---------------------------------------------------------------------------*/
#endif /* ILOS_ENABLED */
