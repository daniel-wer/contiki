/*
 * Copyright (c) 2013, Hasso-Plattner-Institut.
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
 *         CCM* convenience functions for LLSEC use
 * \author
 *         Justin King-Lacroix <justin.kinglacroix@gmail.com>
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "llsec/ccm-star-packetbuf.h"
#include "net/llsec/anti-replay.h"
#include "net/linkaddr.h"
#include "net/packetbuf.h"
#include "net/llsec/llsec802154.h"
#include "net/mac/contikimac/secrdc.h"
#include "net/llsec/adaptivesec/potr.h"
#include <string.h>

/*---------------------------------------------------------------------------*/
static const uint8_t *
get_extended_address(const linkaddr_t *addr)
#if LINKADDR_SIZE == 1
{
  /* workaround for short addresses: derive EUI64 as in RFC 6282 */
  static linkaddr_extended_t template = { { 0x00 , 0x00 , 0x00 ,
                                            0xFF , 0xFE , 0x00 , 0x00 , 0x00 } };

  template.u8[7] = addr->u8[0];

  return template.u8;
}
#elif LINKADDR_SIZE == 2
{
  /* workaround for short addresses: derive EUI64 as in RFC 6282 */
  static linkaddr_extended_t template = { { 0x00 , 0x00 , 0x00 ,
                                            0xFF , 0xFE , 0x00 , 0x00 , 0x00 } };
  
  template.u16[3] = LLSEC802154_HTONS(addr->u16);
  
  return template.u8;
}
#else /* LINKADDR_SIZE == 2 */
{
  return addr->u8;
}
#endif /* LINKADDR_SIZE == 2 */
/*---------------------------------------------------------------------------*/
#if ILOS_ENABLED
ilos_wake_up_counter_t
ccm_star_packetbuf_predict_wake_up_counter(struct secrdc_phase *phase)
{
  ilos_wake_up_counter_t count;

  count.u32 = phase->his_wake_up_counter_at_t.u32
      + (rtimer_delta(phase->t, secrdc_get_next_strobe_start()) >> SECRDC_WAKEUP_INTERVAL_BITS)
      + 1;

  return count;
}
/*---------------------------------------------------------------------------*/
static ilos_wake_up_counter_t
restore_wake_up_counter(struct secrdc_phase *phase)
{
  rtimer_clock_t diff;
  uint32_t div;
  uint32_t mod;
  ilos_wake_up_counter_t count;

  diff = secrdc_get_last_wake_up_time() - phase->t;
  div = diff >> SECRDC_WAKEUP_INTERVAL_BITS;
  count.u32 = phase->his_wake_up_counter_at_t.u32 + div;

  if(count.u32 & 1) {
    /* odd --> we need to round */
    mod = diff & (~(SECRDC_WAKEUP_INTERVAL - 1));
    if(mod < (SECRDC_WAKEUP_INTERVAL / 2)) {
      count.u32--;
    } else  {
      count.u32++;
    }
  }

  return count;
}
#endif /* ILOS_ENABLED */
/*---------------------------------------------------------------------------*/
void
ccm_star_packetbuf_set_nonce(uint8_t *nonce, int forward
#if ILOS_ENABLED
, struct secrdc_phase *phase
#endif /* ILOS_ENABLED */
)
{
  const linkaddr_t *source_addr;
#if SECRDC_WITH_SECURE_PHASE_LOCK
  uint8_t *hdrptr;
#if ILOS_ENABLED
  ilos_wake_up_counter_t count;
#endif /* ILOS_ENABLED */
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  
  source_addr = forward ? &linkaddr_node_addr : packetbuf_addr(PACKETBUF_ADDR_SENDER);
  memcpy(nonce, get_extended_address(source_addr), 8);
#if ILOS_ENABLED
  hdrptr = packetbuf_hdrptr();
  nonce[8] = potr_has_strobe_index(hdrptr[0]) ? hdrptr[POTR_HEADER_LEN] : 0;
  if(potr_is_helloack() || potr_is_ack()) {
    count = ilos_parse_wake_up_counter(((uint8_t *)packetbuf_dataptr()) + 1);
  } else if(packetbuf_holds_broadcast()) {
    count = forward
        ? secrdc_get_wake_up_counter(secrdc_get_next_strobe_start() + SECRDC_WAKEUP_INTERVAL)
        : restore_wake_up_counter(phase);
    count.u32 += 0xC0000000;
  } else {
    count = forward
        ? ccm_star_packetbuf_predict_wake_up_counter(phase)
        : secrdc_get_wake_up_counter(secrdc_get_last_wake_up_time());
    count.u32 += 0x40000000;
  }
  ilos_write_wake_up_counter(nonce + 9, count);
#elif LLSEC802154_USES_FRAME_COUNTER
#if SECRDC_WITH_SECURE_PHASE_LOCK
  hdrptr = packetbuf_hdrptr();
  nonce[8] = potr_has_strobe_index(hdrptr[0]) ? hdrptr[POTR_HEADER_LEN] : 0;
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
  nonce[8] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3) >> 8;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  nonce[9] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_2_3) & 0xff;
  nonce[10] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1) >> 8;
  nonce[11] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1) & 0xff;
#if LLSEC802154_USES_AUX_HEADER
  nonce[12] = packetbuf_attr(PACKETBUF_ATTR_SECURITY_LEVEL);
#else /* LLSEC802154_USES_AUX_HEADER */
  nonce[12] = packetbuf_holds_broadcast() ? 0xFF : packetbuf_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX);
#endif /* LLSEC802154_USES_AUX_HEADER */
#endif /* ILOS_ENABLED */
}
/*---------------------------------------------------------------------------*/
void
ccm_star_packetbuf_to_acknowledgement_nonce(uint8_t *nonce)
{
#if ILOS_ENABLED
  nonce[12] |= (1 << 7);
  nonce[12] &= ~(1 << 6);
#else /* ILOS_ENABLED */
  nonce[12] = 0xFE;
#endif /* ILOS_ENABLED */
}
/*---------------------------------------------------------------------------*/
