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
 *         Adaptive Key Establishment Scheme (AKES).
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/llsec/adaptivesec/akes.h"
#include "net/llsec/adaptivesec/akes-delete.h"
#include "net/llsec/adaptivesec/akes-trickle.h"
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/llsec/adaptivesec/nrl.h"
#include "net/llsec/anti-replay.h"
#include "net/cmd-broker.h"
#include "net/packetbuf.h"
#include "lib/csprng.h"
#include "lib/memb.h"
#include "lib/random.h"
#include "lib/leaky-bucket.h"
#include <string.h>

#ifdef AKES_CONF_MAX_HELLO_RATE
#define MAX_HELLO_RATE AKES_CONF_MAX_HELLO_RATE
#else /* AKES_CONF_MAX_HELLO_RATE */
#define MAX_HELLO_RATE (5 * 60 * CLOCK_SECOND) /* 1 HELLO per 5min */
#endif /* AKES_CONF_MAX_HELLO_RATE */

#ifdef AKES_CONF_MAX_CONSECUTIVE_HELLOS
#define MAX_CONSECUTIVE_HELLOS AKES_CONF_MAX_CONSECUTIVE_HELLOS
#else /* AKES_CONF_MAX_CONSECUTIVE_HELLOS */
#define MAX_CONSECUTIVE_HELLOS (5)
#endif /* AKES_CONF_MAX_CONSECUTIVE_HELLOS */

#ifdef AKES_CONF_MAX_HELLOACK_RATE
#define MAX_HELLOACK_RATE AKES_CONF_MAX_HELLOACK_RATE
#else /* AKES_CONF_MAX_HELLOACK_RATE */
#define MAX_HELLOACK_RATE (150 * CLOCK_SECOND) /* 1 HELOACK per 150s */
#endif /* AKES_CONF_MAX_HELLOACK_RATE */

#ifdef AKES_CONF_MAX_CONSECUTIVE_HELLOACKS
#define MAX_CONSECUTIVE_HELLOACKS AKES_CONF_MAX_CONSECUTIVE_HELLOACKS
#else /* AKES_CONF_MAX_CONSECUTIVE_HELLOACKS */
#define MAX_CONSECUTIVE_HELLOACKS (10)
#endif /* AKES_CONF_MAX_CONSECUTIVE_HELLOACKS */

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

static void send_helloack(void *ptr);
static void send_ack(struct akes_nbr_entry *entry);
#if !ILOS_ENABLED
static void send_updateack(struct akes_nbr_entry *entry);
#endif /* !ILOS_ENABLED */
#if SECRDC_WITH_SECURE_PHASE_LOCK
static void on_helloack_sent(void *ptr, int status, int transmissions);
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
#if !AKES_NBR_WITH_PAIRWISE_KEYS
static void on_ack_sent(void *ptr, int status, int transmissions);
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS */

/* A random challenge, which will be attached to HELLO commands */
uint8_t akes_hello_challenge[AKES_NBR_CHALLENGE_LEN];
static struct cmd_broker_subscription subscription;
static struct leaky_bucket hello_bucket;
static struct leaky_bucket helloack_bucket;

/*---------------------------------------------------------------------------*/
static void
prepare_update_command(uint8_t cmd_id,
    struct akes_nbr_entry *entry,
    enum akes_nbr_status status)
{
  uint8_t *payload;
  uint8_t payload_len;

  payload = adaptivesec_prepare_command(cmd_id, akes_nbr_get_addr(entry));
#if ILOS_ENABLED
  if(cmd_id == AKES_UPDATE_IDENTIFIER) {
    potr_set_seqno(entry->refs[status]);
  }
#elif POTR_ENABLED
  switch(cmd_id) {
  case AKES_UPDATE_IDENTIFIER:
  case AKES_UPDATEACK_IDENTIFIER:
    potr_set_seqno(entry->refs[status]);
    break;
  }
#else /* POTR_ENABLED */
  adaptivesec_add_security_header(entry->refs[status]);
  anti_replay_suppress_counter();
#endif /* POTR_ENABLED */
  if(status) {
    /* avoids that csma.c confuses frames for tentative and permanent neighbors */
    packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO,
        0xff00 + packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO));
  }
#if ANTI_REPLAY_WITH_SUPPRESSION
  packetbuf_set_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX, entry->local_index);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
#if SECRDC_WITH_SECURE_PHASE_LOCK
  switch(cmd_id) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
  case AKES_ACK_IDENTIFIER:
    /*
     * limit number of retransmissions since collision
     * attacks are still severe at this stage
     */
    packetbuf_set_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS, 2);
    break;
  default:
    break;
  }
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */

  /* write payload */
  if(status) {
#if ILOS_ENABLED
    payload += ILOS_WAKE_UP_COUNTER_LEN;
#endif /* ILOS_ENABLED */
    akes_nbr_copy_challenge(payload, entry->tentative->challenge);
    payload += AKES_NBR_CHALLENGE_LEN;
  }

#if SECRDC_WITH_SECURE_PHASE_LOCK
  if(cmd_id == AKES_ACK_IDENTIFIER) {
#if ILOS_ENABLED
    payload += ILOS_WAKE_UP_COUNTER_LEN;
#endif /* ILOS_ENABLED */
    memcpy(payload, secrdc_get_last_random_number(), AKES_NBR_CHALLENGE_LEN);
    payload += AKES_NBR_CHALLENGE_LEN;
    payload[0] = entry->tentative->meta->strobe_index;
    payload++;
#if ILOS_ENABLED
    ilos_write_wake_up_counter(payload, secrdc_get_wake_up_counter(secrdc_get_last_wake_up_time()));
    payload += ILOS_WAKE_UP_COUNTER_LEN;
#endif /* ILOS_ENABLED */
    payload[0] = secrdc_get_last_delta();
    payload++;
  }
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
#if AKES_NBR_WITH_INDICES
  payload[0] = entry->local_index;
  payload++;
#endif /* AKES_NBR_WITH_INDICES */
#if ANTI_REPLAY_WITH_SUPPRESSION
  {
    frame802154_frame_counter_t reordered_counter;
#if !POTR_ENABLED
    /* otherwise this is done in adaptivesec.c */
    anti_replay_write_counter(payload);
#endif /* !POTR_ENABLED */
    payload += 4;
    reordered_counter.u32 = LLSEC802154_HTONL(anti_replay_my_broadcast_counter);
    memcpy(payload, reordered_counter.u8, 4);
    payload += 4;
  }
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */

  payload_len = payload - ((uint8_t *)packetbuf_hdrptr());

#if AKES_NBR_WITH_GROUP_KEYS
  switch(cmd_id) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
  case AKES_ACK_IDENTIFIER:
  case AKES_UPDATE_IDENTIFIER:
    akes_nbr_copy_key(payload, adaptivesec_group_key);
    packetbuf_set_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES, payload_len);
    payload_len += AES_128_KEY_LENGTH;
    break;
  }
#endif /* AKES_NBR_WITH_GROUP_KEYS */
  packetbuf_set_datalen(payload_len);
}
/*---------------------------------------------------------------------------*/
/*
 * We use AES-128 as a key derivation function (KDF). This is possible due to
 * simple circumstances. Speaking in terms of the extract-then-expand paradigm
 * [RFC 5869], we can skip over the extraction step since we already have a
 * uniformly-distributed key which we want to expand into session keys. For
 * implementing the expansion step, we may just use AES-128 [Paar and Pelzl,
 * Understanding Cryptography].
 */
static void
generate_pairwise_key(uint8_t *result, uint8_t *shared_secret)
{
  AES_128_GET_LOCK();
  AES_128.set_key(shared_secret);
  AES_128.encrypt(result);
  AES_128_RELEASE_LOCK();
}
/*---------------------------------------------------------------------------*/
void
akes_change_hello_challenge(void)
{
  csprng_rand(akes_hello_challenge, AKES_NBR_CHALLENGE_LEN);
}
/*---------------------------------------------------------------------------*/
void
akes_broadcast_hello(void)
{
  uint8_t *payload;

  if(leaky_bucket_is_full(&hello_bucket)) {
    PRINTF("akes: Not broadcasting HELLO since bucket is full\n");
    return;
  }
  leaky_bucket_pour(&hello_bucket, 1);

#if POTR_ENABLED
  potr_clear_cached_otps();
#endif /* POTR_ENABLED */

  payload = adaptivesec_prepare_command(AKES_HELLO_IDENTIFIER, &linkaddr_null);
#if !ILOS_ENABLED
  adaptivesec_add_security_header(NULL);
  anti_replay_suppress_counter();
#endif /* !ILOS_ENABLED */

  /* write payload */
  akes_nbr_copy_challenge(payload, akes_hello_challenge);
  payload += AKES_NBR_CHALLENGE_LEN;

  packetbuf_set_datalen(1        /* command frame identifier */
      + AKES_NBR_CHALLENGE_LEN); /* challenge */

  PRINTF("akes: broadcasting HELLO\n");
  ADAPTIVESEC_STRATEGY.send(NULL, NULL);
}
/*---------------------------------------------------------------------------*/
clock_time_t
akes_get_random_waiting_period(void)
{
  return CLOCK_SECOND + (((AKES_MAX_WAITING_PERIOD - 1) * CLOCK_SECOND * (uint32_t)random_rand()) / RANDOM_RAND_MAX);
}
/*---------------------------------------------------------------------------*/
int
akes_is_acceptable_hello(struct akes_nbr_entry *entry)
{
  akes_nbr_delete_expired_tentatives();
  return (akes_nbr_count(AKES_NBR_TENTATIVE) < AKES_NBR_MAX_TENTATIVES)
      && !leaky_bucket_is_full(&hello_bucket)
      && !(entry && entry->tentative)
      && akes_nbr_free_slots();
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_hello(uint8_t *payload)
{
  struct akes_nbr_entry *entry;
  clock_time_t waiting_period;

  PRINTF("akes: Received HELLO\n");

  entry = akes_nbr_get_sender_entry();
  if(!akes_is_acceptable_hello(entry)) {
    PRINTF("akes: Ignored HELLO\n");
    return CMD_BROKER_ERROR;
  }

  if(entry && entry->permanent) {
#if ANTI_REPLAY_WITH_SUPPRESSION && !POTR_ENABLED
    anti_replay_restore_counter(&entry->permanent->anti_replay_info);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION && !POTR_ENABLED */
    switch(ADAPTIVESEC_STRATEGY.verify(entry->permanent)) {
    case ADAPTIVESEC_VERIFY_SUCCESS:
#if !ILOS_ENABLED
      akes_nbr_prolong(entry->permanent);
#endif /* !ILOS_ENABLED */
      akes_trickle_on_fresh_authentic_hello(entry->permanent);
      return CMD_BROKER_CONSUMED;
    case ADAPTIVESEC_VERIFY_INAUTHENTIC:
      PRINTF("akes: Starting new session with permanent neighbor\n");
      break;
#if !POTR_ENABLED
    case ADAPTIVESEC_VERIFY_REPLAYED:
      PRINTF("akes: Replayed HELLO\n");
      return CMD_BROKER_ERROR;
#endif /* !POTR_ENABLED */
    }
  }

  /* Create tentative neighbor */
  entry = akes_nbr_new(AKES_NBR_TENTATIVE);
  if(!entry) {
    PRINTF("akes: HELLO flood?\n");
    return CMD_BROKER_ERROR;
  }

  leaky_bucket_pour(&helloack_bucket, 1);

  akes_nbr_copy_challenge(entry->tentative->challenge, payload);
  waiting_period = akes_get_random_waiting_period();
#if ILOS_ENABLED
  entry->tentative->meta->expiration_time = clock_seconds()
#else /* ILOS_ENABLED */
  entry->tentative->expiration_time = clock_seconds()
#endif /* ILOS_ENABLED */
      + (waiting_period / CLOCK_SECOND)
      + AKES_ACK_DELAY;
  ctimer_set(&entry->tentative->meta->wait_timer,
      waiting_period,
      send_helloack,
      entry);
  PRINTF("akes: Will send HELLOACK in %lus\n", waiting_period / CLOCK_SECOND);
  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
static void
send_helloack(void *ptr)
{
  struct akes_nbr_entry *entry;
  uint8_t challenges[2 * AKES_NBR_CHALLENGE_LEN];
  uint8_t *secret;

  PRINTF("akes: Sending HELLOACK\n");

  entry = (struct akes_nbr_entry *)ptr;

#if KEY_REVOCATION_ENABLED
  if(is_revoked(akes_nbr_get_addr(entry))) {
    PRINTF("akes: HELLO sender is revoked, communication aborted\n");
    return;
  }
#endif /* KEY_REVOCATION_ENABLED */

  akes_nbr_copy_challenge(challenges, entry->tentative->challenge);
  csprng_rand(challenges + AKES_NBR_CHALLENGE_LEN, AKES_NBR_CHALLENGE_LEN);
  akes_nbr_copy_challenge(entry->tentative->challenge, challenges + AKES_NBR_CHALLENGE_LEN);

  /* write payload */
  prepare_update_command(entry->permanent ? AKES_HELLOACK_P_IDENTIFIER : AKES_HELLOACK_IDENTIFIER,
      entry,
      AKES_NBR_TENTATIVE);

  /* generate pairwise key */
#if POTR_ENABLED
  /* create HELLOACK OTP */
  potr_create_special_otp(&entry->tentative->meta->otp, &linkaddr_node_addr, challenges);
#endif /* POTR_ENABLED */
  secret = AKES_SCHEME.get_secret_with_hello_sender(akes_nbr_get_addr(entry));
  if(!secret) {
    PRINTF("akes: No secret with HELLO sender\n");
    return;
  }
  generate_pairwise_key(challenges, secret);
  akes_nbr_copy_key(entry->tentative->tentative_pairwise_key, challenges);

#if SECRDC_WITH_SECURE_PHASE_LOCK
  NETSTACK_MAC.send(on_helloack_sent, entry->tentative);
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
  adaptivesec_send_command_frame();
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
}
/*---------------------------------------------------------------------------*/
#if SECRDC_WITH_SECURE_PHASE_LOCK
static void
on_helloack_sent(void *ptr, int status, int transmissions)
{
  struct akes_nbr *nbr;

  if(status != MAC_TX_OK) {
    return;
  }

  nbr = (struct akes_nbr *) ptr;
  nbr->meta->t1 = secrdc_get_last_but_one_t1();
  nbr->meta->strobe_index = secrdc_get_last_strobe_index();
  memcpy(nbr->meta->tail, secrdc_get_last_random_number(), AKES_NBR_CHALLENGE_LEN);
}
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_helloack(uint8_t *payload, int p_flag)
{
  struct akes_nbr_entry *entry;
  uint8_t *secret;
  uint8_t key[AKES_NBR_CHALLENGE_LEN * 2];

  PRINTF("akes: Received HELLOACK\n");

#if KEY_REVOCATION_ENABLED
  if(is_revoked(packetbuf_addr(PACKETBUF_ADDR_SENDER))) {
    PRINTF("akes: HELLOACK sender is revoked, communication aborted\n");
    return CMD_BROKER_ERROR;
  }
#endif /* KEY_REVOCATION_ENABLED */

  akes_nbr_delete_expired_tentatives();
  entry = akes_nbr_get_sender_entry();
  if(entry && entry->permanent && p_flag) {
    PRINTF("akes: No need to start a new session\n");
    return CMD_BROKER_ERROR;
  }

  secret = AKES_SCHEME.get_secret_with_helloack_sender(packetbuf_addr(PACKETBUF_ADDR_SENDER));
  if(!secret) {
    PRINTF("akes: No secret with HELLOACK sender\n");
    return CMD_BROKER_ERROR;
  }

  /* copy challenges and generate key */
  akes_nbr_copy_challenge(key, akes_hello_challenge);
  akes_nbr_copy_challenge(key + AKES_NBR_CHALLENGE_LEN, payload + ILOS_WAKE_UP_COUNTER_LEN);
  generate_pairwise_key(key, secret);

#if ANTI_REPLAY_WITH_SUPPRESSION
  packetbuf_set_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX, payload[ILOS_WAKE_UP_COUNTER_LEN + AKES_NBR_CHALLENGE_LEN]);
  anti_replay_parse_counter(payload + ILOS_WAKE_UP_COUNTER_LEN + AKES_NBR_CHALLENGE_LEN + 1);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  if(adaptivesec_verify(key
#if ILOS_ENABLED
      , NULL
#endif /* ILOS_ENABLED */
      )) {
    PRINTF("akes: Invalid HELLOACK\n");
    return CMD_BROKER_ERROR;
  }

  if(entry) {
    if(entry->permanent) {
#if !POTR_ENABLED
      if(
#if AKES_NBR_WITH_PAIRWISE_KEYS
          !memcmp(key, entry->permanent->pairwise_key, AES_128_KEY_LENGTH)) {
#else /* AKES_NBR_WITH_PAIRWISE_KEYS */
          !memcmp(payload, entry->permanent->helloack_challenge, AKES_NBR_CACHED_HELLOACK_CHALLENGE_LEN)) {
#endif /* AKES_NBR_WITH_PAIRWISE_KEYS */

        PRINTF("akes: Replayed HELLOACK\n");
        return CMD_BROKER_ERROR;
      } else
#endif /* !POTR_ENABLED */
      {
        akes_nbr_delete(entry, AKES_NBR_PERMANENT);
      }
    }

    if(entry->tentative) {
      if(ctimer_expired(&entry->tentative->meta->wait_timer)) {
        PRINTF("akes: Awaiting ACK\n");
        return CMD_BROKER_ERROR;
      } else {
        PRINTF("akes: Skipping HELLOACK\n");
        ctimer_stop(&entry->tentative->meta->wait_timer);
        akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
      }
    }
  }

  entry = akes_nbr_new(AKES_NBR_PERMANENT);
  if(!entry) {
    return CMD_BROKER_ERROR;
  }

#if AKES_NBR_WITH_PAIRWISE_KEYS
  akes_nbr_copy_key(entry->permanent->pairwise_key, key);
#else /* AKES_NBR_WITH_PAIRWISE_KEYS */
#if !POTR_ENABLED
  memcpy(entry->permanent->helloack_challenge,
      payload,
      AKES_NBR_CACHED_HELLOACK_CHALLENGE_LEN);
#endif /* !POTR_ENABLED */
  akes_nbr_new(AKES_NBR_TENTATIVE);
  if(!entry->tentative) {
    akes_nbr_delete(entry, AKES_NBR_PERMANENT);
    return CMD_BROKER_ERROR;
  }
#if ILOS_ENABLED
  entry->tentative->meta->expiration_time = clock_seconds()
#else /* ILOS_ENABLED */
  entry->tentative->expiration_time = clock_seconds()
#endif /* ILOS_ENABLED */
      + AKES_MAX_WAITING_PERIOD
      + 1 /* leeway */;
  akes_nbr_copy_key(entry->tentative->tentative_pairwise_key, key);
#if SECRDC_WITH_SECURE_PHASE_LOCK
  entry->tentative->meta->strobe_index = ((uint8_t *)packetbuf_hdrptr())[POTR_HEADER_LEN];
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
#if POTR_ENABLED
  /* create ACK OTP */
  potr_create_special_otp(&entry->tentative->meta->otp, &linkaddr_node_addr, payload + ILOS_WAKE_UP_COUNTER_LEN);
#endif /* POTR_ENABLED */
#endif /* AKES_NBR_WITH_PAIRWISE_KEYS */
  akes_nbr_update(entry->permanent,
      payload + ILOS_WAKE_UP_COUNTER_LEN + AKES_NBR_CHALLENGE_LEN,
      AKES_HELLOACK_IDENTIFIER);
  send_ack(entry);
  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
static void
send_ack(struct akes_nbr_entry *entry)
{
  PRINTF("akes: Sending ACK\n");
  prepare_update_command(AKES_ACK_IDENTIFIER, entry, AKES_NBR_PERMANENT);
#if AKES_NBR_WITH_PAIRWISE_KEYS
  adaptivesec_send_command_frame();
#else /* AKES_NBR_WITH_PAIRWISE_KEYS */
  NETSTACK_MAC.send(on_ack_sent, entry);
#endif /* AKES_NBR_WITH_PAIRWISE_KEYS */
}
/*---------------------------------------------------------------------------*/
#if !AKES_NBR_WITH_PAIRWISE_KEYS
static void
on_ack_sent(void *ptr, int status, int transmissions)
{
  struct akes_nbr_entry *entry;

  entry = ptr;
  akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
  if(status != MAC_TX_OK) {
    PRINTF("akes: ACK was not acknowledged\n");
    akes_nbr_delete(entry, AKES_NBR_PERMANENT);
    return;
  }
  akes_trickle_on_new_nbr();
}
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS */
/*---------------------------------------------------------------------------*/
int
akes_is_acceptable_ack(struct akes_nbr_entry *entry)
{
  return entry
      && entry->tentative
      && ctimer_expired(&entry->tentative->meta->wait_timer);
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_ack(uint8_t *payload)
{
  struct akes_nbr_entry *entry;
  int is_new;

  PRINTF("akes: Received ACK\n");

  entry = akes_nbr_get_sender_entry();
#if !SECRDC_WITH_SECURE_PHASE_LOCK
#if ANTI_REPLAY_WITH_SUPPRESSION
  packetbuf_set_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX, payload[0]);
  anti_replay_parse_counter(payload + 1);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  if(!akes_is_acceptable_ack(entry)
      || adaptivesec_verify(entry->tentative->tentative_pairwise_key)) {
#if POTR_ENABLED
    akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
#endif /* POTR_ENABLED */
    PRINTF("akes: Invalid ACK\n");
    return CMD_BROKER_ERROR;
  }
#endif /* !SECRDC_WITH_SECURE_PHASE_LOCK */

  if(entry->permanent) {
    akes_nbr_delete(entry, AKES_NBR_PERMANENT);
    is_new = 0;
  } else {
    is_new = 1;
  }
  entry->permanent = entry->tentative;
  entry->tentative = NULL;
  akes_nbr_update(entry->permanent,
#if SECRDC_WITH_SECURE_PHASE_LOCK
      payload + ILOS_WAKE_UP_COUNTER_LEN + AKES_NBR_CHALLENGE_LEN + 1,
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
      payload,
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
      AKES_ACK_IDENTIFIER);
  if(is_new) {
    akes_trickle_on_new_nbr();
  }

  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
void
akes_send_update(struct akes_nbr_entry *entry)
{
  prepare_update_command(AKES_UPDATE_IDENTIFIER, entry, AKES_NBR_PERMANENT);
  NETSTACK_MAC.send(akes_delete_on_update_sent, NULL);
}
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_update(uint8_t cmd_id, uint8_t *payload)
{
  struct akes_nbr_entry *entry;

  PRINTF("akes: Received %s\n", (cmd_id == AKES_UPDATE_IDENTIFIER) ? "UPDATE" : "UPDATEACK");

  entry = akes_nbr_get_sender_entry();
  if(!entry || !entry->permanent) {
    PRINTF("akes: Invalid %s\n", (cmd_id == AKES_UPDATE_IDENTIFIER) ? "UPDATE" : "UPDATEACK");
    return CMD_BROKER_ERROR;
  }
#if !ILOS_ENABLED
#if !SECRDC_WITH_SECURE_PHASE_LOCK
#if ANTI_REPLAY_WITH_SUPPRESSION && !POTR_ENABLED
  anti_replay_parse_counter(payload + 1);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION  && !POTR_ENABLED */
  if(ADAPTIVESEC_STRATEGY.verify(entry->permanent)
      != ADAPTIVESEC_VERIFY_SUCCESS) {
    PRINTF("akes: Invalid %s\n", (cmd_id == AKES_UPDATE_IDENTIFIER) ? "UPDATE" : "UPDATEACK");
    return CMD_BROKER_ERROR;
  }
#endif /* !SECRDC_WITH_SECURE_PHASE_LOCK */
#endif /* !ILOS_ENABLED */

#if POTR_ENABLED
  if(potr_received_duplicate()) {
    PRINTF("akes: Duplicated UPDATE\n");
    return CMD_BROKER_ERROR;
  }
#endif /* POTR_ENABLED */

  akes_nbr_update(entry->permanent, payload, cmd_id);

#if !ILOS_ENABLED
  if(cmd_id == AKES_UPDATE_IDENTIFIER) {
    send_updateack(entry);
  }
#endif /* !ILOS_ENABLED */
  return CMD_BROKER_CONSUMED;
}
/*---------------------------------------------------------------------------*/
#if !ILOS_ENABLED
static void
send_updateack(struct akes_nbr_entry *entry)
{
  prepare_update_command(AKES_UPDATEACK_IDENTIFIER, entry, AKES_NBR_PERMANENT);
  adaptivesec_send_command_frame();
}
#endif /* !ILOS_ENABLED */
/*---------------------------------------------------------------------------*/
static enum cmd_broker_result
on_command(uint8_t cmd_id, uint8_t *payload)
{
#if AKES_NBR_WITH_GROUP_KEYS && PACKETBUF_WITH_UNENCRYPTED_BYTES
  switch(cmd_id) {
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
#if !SECRDC_WITH_SECURE_PHASE_LOCK
  case AKES_ACK_IDENTIFIER:
#endif /* !SECRDC_WITH_SECURE_PHASE_LOCK */
    packetbuf_set_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES,
        packetbuf_datalen() - AES_128_KEY_LENGTH - ADAPTIVESEC_UNICAST_MIC_LEN);
    break;
  }
#endif /* AKES_NBR_WITH_GROUP_KEYS && PACKETBUF_WITH_UNENCRYPTED_BYTES */

  switch(cmd_id) {
  case AKES_HELLO_IDENTIFIER:
    return on_hello(payload);
  case AKES_HELLOACK_IDENTIFIER:
    return on_helloack(payload, 0);
  case AKES_HELLOACK_P_IDENTIFIER:
    return on_helloack(payload, 1);
  case AKES_ACK_IDENTIFIER:
    return on_ack(payload);
  case AKES_UPDATE_IDENTIFIER:
#if !ILOS_ENABLED
  case AKES_UPDATEACK_IDENTIFIER:
#endif /* !ILOS_ENABLED */
    return on_update(cmd_id, payload);
  default:
    return CMD_BROKER_UNCONSUMED;
  }
}
/*---------------------------------------------------------------------------*/
enum akes_nbr_status
akes_get_receiver_status(void)
{
  if(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE) != FRAME802154_CMDFRAME) {
    return AKES_NBR_PERMANENT;
  }

  switch(adaptivesec_get_cmd_id()) {
#if !AKES_NBR_WITH_PAIRWISE_KEYS
  case AKES_ACK_IDENTIFIER:
#endif /* !AKES_NBR_WITH_PAIRWISE_KEYS */
  case AKES_HELLOACK_IDENTIFIER:
  case AKES_HELLOACK_P_IDENTIFIER:
    return AKES_NBR_TENTATIVE;
  default:
    return AKES_NBR_PERMANENT;
  }
}
/*---------------------------------------------------------------------------*/
void
akes_init(void)
{
  leaky_bucket_init(&hello_bucket, MAX_CONSECUTIVE_HELLOS, MAX_HELLO_RATE);
  leaky_bucket_init(&helloack_bucket, MAX_CONSECUTIVE_HELLOACKS, MAX_HELLOACK_RATE);
  subscription.on_command = on_command;
  cmd_broker_subscribe(&subscription);
  akes_nbr_init();
  AKES_SCHEME.init();
  akes_delete_init();
  akes_trickle_start();
}
/*---------------------------------------------------------------------------*/
