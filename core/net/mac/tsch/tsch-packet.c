/*
 * Copyright (c) 2014, SICS Swedish ICT.
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
 *         TSCH packet format management
 * \author
 *         Simon Duquennoy <simonduq@sics.se>
 *         Beshr Al Nahas <beshr@sics.se>
 */

#include "contiki.h"
#include "net/packetbuf.h"
#include "net/mac/tsch/tsch.h"
#include "net/mac/tsch/tsch-packet.h"
#include "net/mac/tsch/tsch-private.h"
#include "net/mac/tsch/tsch-schedule.h"
#include "net/mac/tsch/tsch-security.h"
#include "net/mac/tsch/tsch-log.h"
#include "net/mac/frame802154.h"
#include "net/mac/framer-802154.h"
#include "net/netstack.h"
#include "net/llsec/anti-replay.h"
#include "lib/ccm-star.h"
#include "lib/aes-128.h"
#include <stdio.h>
#include <string.h>

#if TSCH_LOG_LEVEL >= 1
#define DEBUG DEBUG_PRINT
#else /* TSCH_LOG_LEVEL */
#define DEBUG DEBUG_NONE
#endif /* TSCH_LOG_LEVEL */
#include "net/net-debug.h"

/*---------------------------------------------------------------------------*/
/* Construct enhanced ACK packet and return ACK length */
int
tsch_packet_create_eack(const linkaddr_t *dest_addr, uint8_t seqno, int16_t drift, int nack)
{
  int ret;
  struct ieee802154_ies ies;

  packetbuf_clear();

  /* IE timesync */
  memset(&ies, 0, sizeof(ies));
  ies.ie_time_correction = drift;
  ies.ie_is_nack = nack;

  if((ret = frame80215e_create_ie_header_ack_nack_time_correction(packetbuf_hdrptr(), PACKETBUF_SIZE, &ies)) == -1) {
    return -1;
  }
  if(!packetbuf_hdralloc(ret)) {
    return -1;
  }

  /* Create 802.15.4 header */
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_ACKFRAME);
  packetbuf_set_attr(PACKETBUF_ATTR_IE_LIST_PRESENT, 1);
  packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO, seqno);
  packetbuf_set_addr(PACKETBUF_ADDR_RECEIVER, dest_addr);
#if LLSEC802154_ENABLED
  if(tsch_is_pan_secured) {
    /* Set security level, key id and index */
    packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, TSCH_SECURITY_KEY_SEC_LEVEL_ACK);
    packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, FRAME802154_1_BYTE_KEY_ID_MODE);
    packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, TSCH_SECURITY_KEY_INDEX_ACK);
  }
#endif /* LLSEC802154_ENABLED */
  if(NETSTACK_FRAMER.create() == FRAMER_FAILED) {
    return -1;
  }

  return packetbuf_totlen();
}
/*---------------------------------------------------------------------------*/
/* Parse enhanced ACK packet, extract drift and nack */
int
tsch_packet_parse_eack(uint8_t seqno, struct ieee802154_ies *ies, uint8_t *hdr_len)
{
  uint8_t curr_len = 0;
  int ret;

  /* Parse 802.15.4-2006 frame, i.e. all fields before Information Elements */
  if(NETSTACK_FRAMER.parse() == FRAMER_FAILED) {
    return 0;
  }
  if(hdr_len != NULL) {
    *hdr_len = packetbuf_hdrlen();
  }
  curr_len += packetbuf_hdrlen();

  /* Check seqno */
  if(seqno != packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO)) {
    return 0;
  }

  if(ies != NULL) {
    memset(ies, 0, sizeof(struct ieee802154_ies));
  }

  if(packetbuf_attr(PACKETBUF_ATTR_IE_LIST_PRESENT)) {
    int mic_len = 0;
#if LLSEC802154_ENABLED
    /* Check if there is space for the security MIC (if any) */
    mic_len = tsch_security_mic_len();
    if(packetbuf_datalen() < mic_len) {
      return 0;
    }
#endif /* LLSEC802154_ENABLED */
    /* Parse information elements. We need to substract the MIC length, as the exact payload len is needed while parsing */
    if((ret = frame802154e_parse_information_elements(packetbuf_dataptr(), packetbuf_datalen() - mic_len, ies)) == -1) {
      return 0;
    }
    curr_len += ret;
  }

  if(hdr_len != NULL) {
    *hdr_len += ies->ie_payload_ie_offset;
  }

  return curr_len;
}
/*---------------------------------------------------------------------------*/
/* Create an EB packet */
int
tsch_packet_create_eb(uint8_t *hdr_len, uint8_t *tsch_sync_ie_offset)
{
  int ret = 0;
  uint8_t curr_len = 0;
  uint8_t mlme_ie_offset;
  uint8_t *buf;
  int buf_size;
  struct ieee802154_ies ies;

  packetbuf_clear();
  buf = packetbuf_hdrptr();
  buf_size = PACKETBUF_SIZE;

  /* Prepare Information Elements for inclusion in the EB */
  memset(&ies, 0, sizeof(ies));

  /* Add TSCH timeslot timing IE. */
#if TSCH_PACKET_EB_WITH_TIMESLOT_TIMING
  {
    int i;
    ies.ie_tsch_timeslot_id = 1;
    for(i = 0; i < tsch_ts_elements_count; i++) {
      ies.ie_tsch_timeslot[i] = RTIMERTICKS_TO_US(tsch_timing[i]);
    }
  }
#endif /* TSCH_PACKET_EB_WITH_TIMESLOT_TIMING */

  /* Add TSCH hopping sequence IE */
#if TSCH_PACKET_EB_WITH_HOPPING_SEQUENCE
  if(tsch_hopping_sequence_length.val <= sizeof(ies.ie_hopping_sequence_list)) {
    ies.ie_channel_hopping_sequence_id = 1;
    ies.ie_hopping_sequence_len = tsch_hopping_sequence_length.val;
    memcpy(ies.ie_hopping_sequence_list, tsch_hopping_sequence, ies.ie_hopping_sequence_len);
  }
#endif /* TSCH_PACKET_EB_WITH_HOPPING_SEQUENCE */

  /* Add Slotframe and Link IE */
#if TSCH_PACKET_EB_WITH_SLOTFRAME_AND_LINK
  {
    /* Send slotframe 0 with link at timeslot 0 */
    struct tsch_slotframe *sf0 = tsch_schedule_get_slotframe_by_handle(0);
    struct tsch_link *link0 = tsch_schedule_get_link_by_timeslot(sf0, 0);
    if(sf0 && link0) {
      ies.ie_tsch_slotframe_and_link.num_slotframes = 1;
      ies.ie_tsch_slotframe_and_link.slotframe_handle = sf0->handle;
      ies.ie_tsch_slotframe_and_link.slotframe_size = sf0->size.val;
      ies.ie_tsch_slotframe_and_link.num_links = 1;
      ies.ie_tsch_slotframe_and_link.links[0].timeslot = link0->timeslot;
      ies.ie_tsch_slotframe_and_link.links[0].channel_offset = link0->channel_offset;
      ies.ie_tsch_slotframe_and_link.links[0].link_options = link0->link_options;
    }
  }
#endif /* TSCH_PACKET_EB_WITH_SLOTFRAME_AND_LINK */

  /* First add header-IE termination IE to stipulate that next come payload IEs */
  if((ret = frame80215e_create_ie_header_list_termination_1(buf, buf_size, &ies)) == -1) {
    return -1;
  }
  /* header-IE termination IE goes to the header portion */
  if(!packetbuf_hdralloc(ret)) {
    return -1;
  }

  /* Create 802.15.4 header */
  packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_BEACONFRAME);
  packetbuf_set_attr(PACKETBUF_ATTR_IE_LIST_PRESENT, 1);
#if LLSEC802154_ENABLED
  if(tsch_is_pan_secured) {
    /* Set security level, key id and index */
    packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, TSCH_SECURITY_KEY_SEC_LEVEL_EB);
    packetbuf_set_attr(PACKETBUF_ATTR_KEY_ID_MODE, FRAME802154_1_BYTE_KEY_ID_MODE);
    packetbuf_set_attr(PACKETBUF_ATTR_KEY_INDEX, TSCH_SECURITY_KEY_INDEX_EB);
  }
#endif /* LLSEC802154_ENABLED */
  if(NETSTACK_FRAMER.create() == FRAMER_FAILED) {
    return -1;
  }
  /* store hdr_len */
  if(hdr_len) {
    *hdr_len = packetbuf_hdrlen();
  }

  /* subsequent IEs go to the data portion */
  buf = packetbuf_dataptr();
  curr_len = 0;
  /* Save offset of the MLME IE descriptor, we need to know the total length
   * before writing it */
  mlme_ie_offset = curr_len;
  curr_len += 2; /* Space needed for MLME descriptor */

  /* Save the offset of the TSCH Synchronization IE, needed to update ASN and join priority before sending */
  if(tsch_sync_ie_offset != NULL) {
    *tsch_sync_ie_offset = *hdr_len + curr_len;
  }
  if((ret = frame80215e_create_ie_tsch_synchronization(buf + curr_len, buf_size - curr_len, &ies)) == -1) {
    return -1;
  }
  curr_len += ret;

  if((ret = frame80215e_create_ie_tsch_timeslot(buf + curr_len, buf_size - curr_len, &ies)) == -1) {
    return -1;
  }
  curr_len += ret;

  if((ret = frame80215e_create_ie_tsch_channel_hopping_sequence(buf + curr_len, buf_size - curr_len, &ies)) == -1) {
    return -1;
  }
  curr_len += ret;

  if((ret = frame80215e_create_ie_tsch_slotframe_and_link(buf + curr_len, buf_size - curr_len, &ies)) == -1) {
    return -1;
  }
  curr_len += ret;

  ies.ie_mlme_len = curr_len - mlme_ie_offset - 2;
  if((ret = frame80215e_create_ie_mlme(buf + mlme_ie_offset, buf_size - mlme_ie_offset, &ies)) == -1) {
    return -1;
  }

  /* Payload IE list termination: optional */
  /*
  if((ret = frame80215e_create_ie_payload_list_termination(buf + curr_len, buf_size - curr_len, &ies)) == -1) {
    return -1;
  }
  curr_len += ret;
  */
  packetbuf_set_datalen(curr_len);

  return packetbuf_totlen();
}
/*---------------------------------------------------------------------------*/
/* Update ASN in EB packet */
int
tsch_packet_update_eb(uint8_t *buf, int buf_size, uint8_t tsch_sync_ie_offset)
{
  struct ieee802154_ies ies;
  ies.ie_asn = tsch_current_asn;
  ies.ie_join_priority = tsch_join_priority;
  frame80215e_create_ie_tsch_synchronization(buf+tsch_sync_ie_offset, buf_size-tsch_sync_ie_offset, &ies);
  return 1;
}
/*---------------------------------------------------------------------------*/
/* Parse a IEEE 802.15.4e TSCH Enhanced Beacon (EB) */
int
tsch_packet_parse_eb(struct ieee802154_ies *ies, uint8_t *hdr_len, int frame_without_mic)
{
  uint8_t curr_len = 0;
  int ret;

  if(hdr_len != NULL) {
    *hdr_len = packetbuf_hdrlen();
  }
  curr_len += packetbuf_hdrlen();

  if(ies != NULL) {
    memset(ies, 0, sizeof(struct ieee802154_ies));
    ies->ie_join_priority = 0xff; /* Use max value in case the Beacon does not include a join priority */
  }
  if(packetbuf_attr(PACKETBUF_ATTR_IE_LIST_PRESENT)) {
    /* Calculate space needed for the security MIC, if any, before attempting to parse IEs */
    int mic_len = 0;
#if LLSEC802154_ENABLED
    if(!frame_without_mic) {
      mic_len = tsch_security_mic_len();
      if(packetbuf_datalen() < mic_len) {
        return 0;
      }
    }
#endif /* LLSEC802154_ENABLED */

    /* Parse information elements. We need to substract the MIC length, as the exact payload len is needed while parsing */
    if((ret = frame802154e_parse_information_elements(packetbuf_dataptr(), packetbuf_datalen() - mic_len, ies)) == -1) {
      PRINTF("TSCH:! parse_eb: failed to parse IEs\n");
      return 0;
    }
    curr_len += ret;
  }

  if(hdr_len != NULL) {
    *hdr_len += ies->ie_payload_ie_offset;
  }

  return curr_len;
}
/*---------------------------------------------------------------------------*/
