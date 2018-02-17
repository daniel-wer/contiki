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
 *         A denial-of-sleep-resilient version of ContikiMAC.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "net/mac/contikimac/secrdc.h"
#include "net/mac/mac.h"
#include "net/netstack.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "net/mac/framer-802154.h"
#include "net/mac/contikimac/contikimac-framer.h"
#include "net/llsec/adaptivesec/potr.h"
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/llsec/adaptivesec/akes.h"
#include "net/llsec/adaptivesec/akes-nbr.h"
#include "net/llsec/ccm-star-packetbuf.h"
#include "net/nbr-table.h"
#include "lib/aes-128.h"
#include "net/nbr-table.h"
#ifdef LPM_CONF_ENABLE
#include "lpm.h"
#endif /* LPM_CONF_ENABLE */
#include "lib/random.h"
#include "lib/csprng.h"
#include "cpu/cc2538/dev/cc2538-rf-async.h"

#ifdef SECRDC_CONF_WITH_DOZING
#define WITH_DOZING SECRDC_CONF_WITH_DOZING
#else /* SECRDC_CONF_WITH_DOZING */
#define WITH_DOZING 1
#endif /* SECRDC_CONF_WITH_DOZING */

#ifdef SECRDC_CONF_RECEIVE_CALIBRATION_TIME
#define RECEIVE_CALIBRATION_TIME SECRDC_CONF_RECEIVE_CALIBRATION_TIME
#else /* SECRDC_CONF_RECEIVE_CALIBRATION_TIME */
#define RECEIVE_CALIBRATION_TIME (US_TO_RTIMERTICKS(192) + 1)
#endif /* SECRDC_CONF_RECEIVE_CALIBRATION_TIME */

#ifdef SECRDC_CONF_TRANSMIT_CALIBRATION_TIME
#define TRANSMIT_CALIBRATION_TIME SECRDC_CONF_TRANSMIT_CALIBRATION_TIME
#else /* SECRDC_CONF_TRANSMIT_CALIBRATION_TIME */
#define TRANSMIT_CALIBRATION_TIME (US_TO_RTIMERTICKS(192) + 1)
#endif /* SECRDC_CONF_TRANSMIT_CALIBRATION_TIME */

#ifdef SECRDC_CONF_INTER_BROADCAST_FRAME_CORRECTION
#define INTER_BROADCAST_FRAME_CORRECTION SECRDC_CONF_INTER_BROADCAST_FRAME_CORRECTION
#else /* SECRDC_CONF_INTER_BROADCAST_FRAME_CORRECTION */
#define INTER_BROADCAST_FRAME_CORRECTION 2 /* tick */
#endif /* SECRDC_CONF_INTER_BROADCAST_FRAME_CORRECTION */

#ifdef SECRDC_CONF_PHASE_LOCK_FREQ_TOLERANCE
#define PHASE_LOCK_FREQ_TOLERANCE SECRDC_CONF_PHASE_LOCK_FREQ_TOLERANCE
#else /* SECRDC_CONF_PHASE_LOCK_FREQ_TOLERANCE */
#define PHASE_LOCK_FREQ_TOLERANCE (1)
#endif /* SECRDC_CONF_PHASE_LOCK_FREQ_TOLERANCE */

#ifdef SECRDC_CONF_WITH_INTRA_COLLISION_AVOIDANCE
#define WITH_INTRA_COLLISION_AVOIDANCE SECRDC_CONF_WITH_INTRA_COLLISION_AVOIDANCE
#else /* SECRDC_CONF_WITH_INTRA_COLLISION_AVOIDANCE */
#define WITH_INTRA_COLLISION_AVOIDANCE 1
#endif /* SECRDC_CONF_WITH_INTRA_COLLISION_AVOIDANCE */

#ifdef SECRDC_CONF_WITH_INTER_COLLISION_AVOIDANCE
#define WITH_INTER_COLLISION_AVOIDANCE SECRDC_CONF_WITH_INTER_COLLISION_AVOIDANCE
#else /* SECRDC_CONF_WITH_INTER_COLLISION_AVOIDANCE */
#define WITH_INTER_COLLISION_AVOIDANCE 1
#endif /* SECRDC_CONF_WITH_INTER_COLLISION_AVOIDANCE */

#define WITH_COLLISION_AVOIDANCE (WITH_INTRA_COLLISION_AVOIDANCE || WITH_INTER_COLLISION_AVOIDANCE)

#ifdef SECRDC_CONF_WITH_AUTO_CCA
#define WITH_AUTO_CCA SECRDC_CONF_WITH_AUTO_CCA
#else /* SECRDC_CONF_WITH_AUTO_CCA */
#define WITH_AUTO_CCA 0
#endif /* SECRDC_CONF_WITH_AUTO_CCA */

#ifdef SECRDC_CONF_TXDONE_DELAY
#define TXDONE_DELAY SECRDC_CONF_TXDONE_DELAY
#else /* SECRDC_CONF_TXDONE_DELAY */
#define TXDONE_DELAY (0)
#endif /* SECRDC_CONF_TXDONE_DELAY */

#ifdef SECRDC_CONF_INTER_FRAMER_PERIOD_ADJUSTMENT
#define INTER_FRAMER_PERIOD_ADJUSTMENT SECRDC_CONF_INTER_FRAMER_PERIOD_ADJUSTMENT
#else /* SECRDC_CONF_INTER_FRAMER_PERIOD_ADJUSTMENT */
#define INTER_FRAMER_PERIOD_ADJUSTMENT (2) /* better transmit a tick too late than too early */
#endif /* SECRDC_CONF_INTER_FRAMER_PERIOD_ADJUSTMENT */

#ifdef SECRDC_CONF_LPM_SWITCHING
#define LPM_SWITCHING SECRDC_CONF_LPM_SWITCHING
#else /* SECRDC_CONF_LPM_SWITCHING */
#ifdef LPM_CONF_ENABLE
#define LPM_SWITCHING ((LPM_CONF_MAX_PM > 0) ? 5 /* ticks */ : 0)
#else /* LPM_CONF_ENABLE */
#define LPM_SWITCHING (0)
#endif /* LPM_CONF_ENABLE */
#endif /* SECRDC_CONF_LPM_SWITCHING */

#ifdef SECRDC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX
#define ACKNOWLEDGEMENT_WINDOW_MAX SECRDC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX
#else /* SECRDC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX */
#define ACKNOWLEDGEMENT_WINDOW_MAX US_TO_RTIMERTICKS(427)
#endif /* SECRDC_CONF_ACKNOWLEDGEMENT_WINDOW_MAX */

#define MAX_FRAME_LEN (127)
#define WAKEUP_INTERVAL (RTIMER_ARCH_SECOND / NETSTACK_RDC_CHANNEL_CHECK_RATE)
#define INTER_FRAME_PERIOD (US_TO_RTIMERTICKS(1068))
#define MAX_CCAS (2)
#define CCA_DURATION (US_TO_RTIMERTICKS(128) + 1)
#define MAX_NOISE (US_TO_RTIMERTICKS(4256) + 1)
#define SHR_DETECTION_TIME (US_TO_RTIMERTICKS(160) + 1)
#define INTER_CCA_PERIOD (INTER_FRAME_PERIOD - RECEIVE_CALIBRATION_TIME)
#define SILENCE_CHECK_PERIOD (US_TO_RTIMERTICKS(250))
#define DOZING_PERIOD (INTER_FRAME_PERIOD \
    - RECEIVE_CALIBRATION_TIME \
    - CCA_DURATION)
#define ACKNOWLEDGEMENT_WINDOW_MIN (US_TO_RTIMERTICKS(336))
#define ACKNOWLEDGEMENT_WINDOW (ACKNOWLEDGEMENT_WINDOW_MAX \
    - ACKNOWLEDGEMENT_WINDOW_MIN \
    + 1)
#define PHASE_LOCK_GUARD_TIME (SECRDC_WITH_SECURE_PHASE_LOCK \
    ? (2 /* some tolerance */ \
        + ACKNOWLEDGEMENT_WINDOW /* allow for pulse-delay attacks */) \
    : (US_TO_RTIMERTICKS(1000)))
#define FIFOP_THRESHOLD (POTR_ENABLED \
    ? (POTR_HEADER_LEN - POTR_OTP_LEN) \
    : (FRAMER_802154_MIN_BYTES_FOR_FILTERING))
#define INITIAL_FLOOR_NOISE (-85)
#define SIGNAL_NOISE_DIFF (3)
#define MAX_SIGNAL_VARIATION (3)
#define CCA_HYSTERESIS (12)
#define MAX_CACHED_RSSIS (64)

#if WITH_INTRA_COLLISION_AVOIDANCE
#define INTRA_COLLISION_AVOIDANCE_DURATION ((2 * (RECEIVE_CALIBRATION_TIME + CCA_DURATION)) + INTER_CCA_PERIOD)
#else /* WITH_INTRA_COLLISION_AVOIDANCE */
#define INTRA_COLLISION_AVOIDANCE_DURATION (0)
#endif /* WITH_INTRA_COLLISION_AVOIDANCE */

#if POTR_ENABLED
#if SECRDC_WITH_SECURE_PHASE_LOCK
#define ACKNOWLEDGEMENT_LEN (2 + ADAPTIVESEC_UNICAST_MIC_LEN)
#define HELLOACK_ACKNOWLEDGEMENT_LEN (1 + AKES_NBR_CHALLENGE_LEN)
#define ACK_ACKNOWLEDGEMENT_LEN (ACKNOWLEDGEMENT_LEN + ILOS_WAKE_UP_COUNTER_LEN)
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
#define ACKNOWLEDGEMENT_LEN 2
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
#else /* POTR_ENABLED */
#define ACKNOWLEDGEMENT_LEN 3
#endif /* POTR_ENABLED */

#if SECRDC_WITH_SECURE_PHASE_LOCK
#define EXPECTED_ACKNOWLEDGEMENT_LEN u.strobe.acknowledgement_len
#define MAX_ACKNOWLEDGEMENT_LEN MAX(MAX(ACKNOWLEDGEMENT_LEN, HELLOACK_ACKNOWLEDGEMENT_LEN), ACK_ACKNOWLEDGEMENT_LEN)
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
#define EXPECTED_ACKNOWLEDGEMENT_LEN ACKNOWLEDGEMENT_LEN
#define MAX_ACKNOWLEDGEMENT_LEN ACKNOWLEDGEMENT_LEN
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

enum cca_reason {
  TRANSMISSION_DETECTION,
  SILENCE_DETECTION,
  COLLISION_AVOIDANCE
};

struct buffered_frame {
  struct buffered_frame *next;
  struct queuebuf *qb;
  int allocated_qb;
  mac_callback_t sent;
  int transmissions;
  void *ptr;
  struct rdc_buf_list *tail;
#if SECRDC_WITH_ORIGINAL_PHASE_LOCK
  enum akes_nbr_status receiver_status;
#endif /* SECRDC_WITH_ORIGINAL_PHASE_LOCK */
};

static void prepare_radio_for_duty_cycle(void);
static void enable_shr_search(void);
static void disable_shr_search(void);
static void schedule_duty_cycle(rtimer_clock_t time);
static void duty_cycle_wrapper(struct rtimer *t, void *ptr);
static char duty_cycle(void);
static void on_sfd(void);
static void on_rtimer_freed(struct rtimer *rt, void *ptr);
static void on_fifop(void);
static void prepare_acknowledgement(void);
static void on_final_fifop(void);
#if SECRDC_WITH_SECURE_PHASE_LOCK
static void create_acknowledgement_mic(void);
static int received_authentic_unicast(void);
static int is_valid_ack(struct akes_nbr_entry *entry);
static int parse_unicast_frame(void);
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
static void on_txdone(void);
static void finish_duty_cycle(void);
#if SECRDC_WITH_PHASE_LOCK
static struct secrdc_phase *obtain_phase_lock_data(void);
#endif /* SECRDC_WITH_PHASE_LOCK */
static void strobe_soon(void);
static void schedule_strobe(rtimer_clock_t time);
static void strobe_wrapper(struct rtimer *rt, void *ptr);
static char strobe(void);
static int should_strobe_again(void);
static int transmit(void);
static int is_valid(uint8_t *acknowledgement);
static void on_strobed(void);
static void send_list(mac_callback_t sent,
    void *ptr,
    struct rdc_buf_list *list);
static void queue_frame(mac_callback_t sent,
    void *ptr,
    struct queuebuf *qb,
    struct rdc_buf_list *tail);

static union {
  struct {
    int cca_count;
    rtimer_clock_t silence_timeout;
    volatile int got_shr;
    volatile int waiting_for_shr;
    volatile int rtimer_freed;
    struct packetbuf local_packetbuf;
    struct packetbuf *actual_packetbuf;
    int shall_send_acknowledgement;
#if SECRDC_WITH_SECURE_PHASE_LOCK
    int read_and_parsed;
    int is_helloack;
    int is_ack;
    uint8_t acknowledgement[MAX_ACKNOWLEDGEMENT_LEN];
    uint8_t acknowledgement_len;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  } duty_cycle;

  struct {
    int is_broadcast;
    int result;
    rtimer_clock_t next_transmission;
    rtimer_clock_t timeout;
    struct buffered_frame *bf;
    int sent_once_more;
#if SECRDC_WITH_PHASE_LOCK
    struct secrdc_phase *phase;
#if SECRDC_WITH_SECURE_PHASE_LOCK
    uint8_t acknowledgement_key[AES_128_KEY_LENGTH];
    int is_helloack;
    int is_ack;
    uint8_t acknowledgement_len;
    rtimer_clock_t uncertainty;
    rtimer_clock_t t1[2];
#if ILOS_ENABLED
    rtimer_clock_t strobe_start;
#endif /* ILOS_ENABLED */
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
    rtimer_clock_t t0[2];
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
#endif /* SECRDC_WITH_PHASE_LOCK */
    uint8_t strobes;
#if SECRDC_WITH_SECURE_PHASE_LOCK
    uint8_t nonce[13];
    uint8_t shall_encrypt;
    uint8_t a_len;
    uint8_t m_len;
    uint8_t mic_len;
    uint8_t totlen;
    uint8_t unsecured_frame[MAX_FRAME_LEN];
    uint8_t key[AES_128_KEY_LENGTH];
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
    uint8_t seqno;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  } strobe;
} u;

static int8_t rssi_of_last_transmission;
#if WITH_AUTO_CCA
static int8_t last_rssis[MAX_CACHED_RSSIS];
static uint8_t last_rssi_index;
static int8_t floor_noise_mean;
#else /* WITH_AUTO_CCA */
static const int8_t floor_noise_mean = INITIAL_FLOOR_NOISE;
#endif /* WITH_AUTO_CCA */
static struct rtimer timer;
static rtimer_clock_t duty_cycle_next;
static struct pt pt;
static volatile int is_duty_cycling;
static volatile int is_strobing;
PROCESS(post_processing, "post processing");
MEMB(buffered_frames_memb, struct buffered_frame, QUEUEBUF_NUM);
LIST(buffered_frames_list);
#if SECRDC_WITH_SECURE_PHASE_LOCK
static volatile rtimer_clock_t sfd_timestamp;
static uint8_t last_random_number[AKES_NBR_CHALLENGE_LEN];
#if ILOS_ENABLED
static ilos_wake_up_counter_t my_wake_up_counter;
static rtimer_clock_t my_wake_up_counter_last_increment;
#endif /* ILOS_ENABLED */
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */

/*---------------------------------------------------------------------------*/
#if WITH_AUTO_CCA
static void
cache_rssi(int8_t rssi)
{
  if(++last_rssi_index == MAX_CACHED_RSSIS) {
    last_rssi_index = 0;
  }
  last_rssis[last_rssi_index] = rssi;
}
/*---------------------------------------------------------------------------*/
static void
update_floor_noise(void)
{
  int32_t sum;
  uint8_t i;

  sum = 0;
  for(i = 0; i < MAX_CACHED_RSSIS; i++) {
    sum += last_rssis[i];
  }
  floor_noise_mean = sum / MAX_CACHED_RSSIS;
}
#endif /* WITH_AUTO_CCA */
/*---------------------------------------------------------------------------*/
static int
channel_clear(enum cca_reason reason)
{
  int8_t rssi;

  rssi = NETSTACK_RADIO_ASYNC.get_rssi();
  switch(reason) {
  case TRANSMISSION_DETECTION:
    if(rssi < floor_noise_mean + SIGNAL_NOISE_DIFF) {
#if WITH_AUTO_CCA
      cache_rssi(rssi);
#endif /* WITH_AUTO_CCA */
      return 1;
    } else {
      rssi_of_last_transmission = rssi;
      return 0;
    }
  case SILENCE_DETECTION:
    return rssi <= rssi_of_last_transmission - SIGNAL_NOISE_DIFF;
#if WITH_COLLISION_AVOIDANCE
  case COLLISION_AVOIDANCE:
#if WITH_AUTO_CCA
    cache_rssi(rssi);
#endif /* WITH_AUTO_CCA */
    return rssi < floor_noise_mean + CCA_HYSTERESIS;
#endif /* WITH_COLLISION_AVOIDANCE */
  default:
    return 1;
  }
}
/*---------------------------------------------------------------------------*/
static rtimer_clock_t
shift_to_future(rtimer_clock_t time)
{
  /* TODO this assumes that WAKEUP_INTERVAL is a power of 2 */
  time = (RTIMER_NOW() & (~(WAKEUP_INTERVAL - 1)))
      | (time & (WAKEUP_INTERVAL - 1));
  while(!rtimer_is_schedulable(time, RTIMER_GUARD_TIME + 1)) {
    time += WAKEUP_INTERVAL;
  }

  return time;
}
/*---------------------------------------------------------------------------*/
static void
disable_and_reset_radio(void)
{
  NETSTACK_RADIO_ASYNC.off();
  NETSTACK_RADIO_ASYNC.flushrx();
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  PRINTF("secrdc: t_i = %lu\n", INTER_FRAME_PERIOD);
  PRINTF("secrdc: t_c = %lu\n", INTER_CCA_PERIOD);
  PRINTF("secrdc: t_w = %i\n", WAKEUP_INTERVAL);
#if SECRDC_WITH_SECURE_PHASE_LOCK
  PRINTF("secrdc: t_a = %lu\n", ACKNOWLEDGEMENT_WINDOW);
  PRINTF("secrdc: t_s = %lu\n", PHASE_LOCK_GUARD_TIME);
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  memb_init(&buffered_frames_memb);
  list_init(buffered_frames_list);
#if WITH_AUTO_CCA
  memset(last_rssis, INITIAL_FLOOR_NOISE, MAX_CACHED_RSSIS);
  floor_noise_mean = INITIAL_FLOOR_NOISE;
#endif /* WITH_AUTO_CCA */
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_TXDONE_CALLBACK, on_txdone, 0);
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_SFD_CALLBACK, on_sfd, 0);
  prepare_radio_for_duty_cycle();
  process_start(&post_processing, NULL);
  PT_INIT(&pt);
  duty_cycle_next = RTIMER_NOW() + WAKEUP_INTERVAL;
  schedule_duty_cycle(duty_cycle_next);
}
/*---------------------------------------------------------------------------*/
static void
prepare_radio_for_duty_cycle(void)
{
  NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK,
      on_fifop,
      FIFOP_THRESHOLD);
  disable_shr_search();
}
/*---------------------------------------------------------------------------*/
static void
enable_shr_search(void)
{
  NETSTACK_RADIO_ASYNC.set_value(RADIO_PARAM_SHR_SEARCH, 1);
}
/*---------------------------------------------------------------------------*/
static void
disable_shr_search(void)
{
  NETSTACK_RADIO_ASYNC.set_value(RADIO_PARAM_SHR_SEARCH, 0);
}
/*---------------------------------------------------------------------------*/
static void
schedule_duty_cycle(rtimer_clock_t time)
{
  if(rtimer_set(&timer, time, 1, duty_cycle_wrapper, NULL) != RTIMER_OK) {
    PRINTF("secrdc: rtimer_set failed\n");
  }
}
/*---------------------------------------------------------------------------*/
static void
duty_cycle_wrapper(struct rtimer *rt, void *ptr)
{
  duty_cycle();
}
/*---------------------------------------------------------------------------*/
static char
duty_cycle(void)
{
  PT_BEGIN(&pt);

  is_duty_cycling = 1;
#if ILOS_ENABLED
  my_wake_up_counter = secrdc_get_wake_up_counter(duty_cycle_next);
  my_wake_up_counter_last_increment = duty_cycle_next;
#endif /* ILOS_ENABLED */
#ifdef LPM_CONF_ENABLE
  lpm_set_max_pm(1);
#endif /* LPM_CONF_ENABLE */
  // TODOX reset_rx()
  reset_rx();
  /* CCAs */
  while(1) {
    NETSTACK_RADIO_ASYNC.on();
    if(channel_clear(TRANSMISSION_DETECTION)) {
      NETSTACK_RADIO_ASYNC.off();
      if(++u.duty_cycle.cca_count != MAX_CCAS) {
        schedule_duty_cycle(RTIMER_NOW() + INTER_CCA_PERIOD - LPM_SWITCHING);
        PT_YIELD(&pt);
        /* if we come from PM0, we will be too early */
        while(!rtimer_has_timed_out(timer.time));
        continue;
      }
    } else {
      u.duty_cycle.silence_timeout = RTIMER_NOW() + MAX_NOISE;
    }
    break;
  }

  /* fast-sleep optimization */
  if(u.duty_cycle.silence_timeout) {
    while(1) {

      /* look for silence period */
#if WITH_DOZING
      NETSTACK_RADIO_ASYNC.off();
      schedule_duty_cycle(RTIMER_NOW() + DOZING_PERIOD - LPM_SWITCHING);
      PT_YIELD(&pt);
      NETSTACK_RADIO_ASYNC.on();
#else /* WITH_DOZING */
      schedule_duty_cycle(RTIMER_NOW() + SILENCE_CHECK_PERIOD);
      PT_YIELD(&pt);
#endif /* WITH_DOZING */
      if(channel_clear(SILENCE_DETECTION)) {
        enable_shr_search();

        /* wait for SHR */
        u.duty_cycle.waiting_for_shr = 1;
        schedule_duty_cycle(RTIMER_NOW()
            + INTER_FRAME_PERIOD
            + SHR_DETECTION_TIME
            + 1 /* some tolerance */);
        PT_YIELD(&pt);
        u.duty_cycle.waiting_for_shr = 0;
        if(!u.duty_cycle.got_shr) {
          disable_and_reset_radio();
          PRINTF("secrdc: no SHR detected\n");
        }
        break;
      } else if(rtimer_has_timed_out(u.duty_cycle.silence_timeout)) {
        disable_and_reset_radio();
        PRINTF("secrdc: noise too long\n");
        break;
      }
    }
  }

  if(!u.duty_cycle.got_shr) {
    finish_duty_cycle();
    u.duty_cycle.rtimer_freed = 1;
  }
  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
/**
 * Here, we assume that rtimer and radio interrupts have equal priorities,
 * such that they do not preempt each other.
 */
static void
on_sfd(void)
{
  int8_t rssi;

#if SECRDC_WITH_SECURE_PHASE_LOCK
  rtimer_clock_t now;

  now = RTIMER_NOW();
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */

  if(is_duty_cycling && u.duty_cycle.waiting_for_shr) {

    /*
     * if the signal strength had dropped significantly,
     * we might have detected an SHR within radio noise.
     */
    rssi = NETSTACK_RADIO_ASYNC.get_rssi();
    if(rssi <= rssi_of_last_transmission - MAX_SIGNAL_VARIATION) {
      NETSTACK_RADIO_ASYNC.flushrx();
      return;
    }

#if SECRDC_WITH_SECURE_PHASE_LOCK
    sfd_timestamp = now;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
    u.duty_cycle.got_shr = 1;
    rtimer_run_next();
    rtimer_set(&timer, RTIMER_NOW() + RTIMER_GUARD_TIME, 1, on_rtimer_freed, NULL);
  } else if(is_strobing) {
#if SECRDC_WITH_SECURE_PHASE_LOCK
    sfd_timestamp = now;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  }
}
/*---------------------------------------------------------------------------*/
static void
on_rtimer_freed(struct rtimer *rt, void *ptr)
{
  u.duty_cycle.rtimer_freed = 1;
}
/*---------------------------------------------------------------------------*/
static void
enable_local_packetbuf(void)
{
  u.duty_cycle.actual_packetbuf = packetbuf;
  packetbuf = &u.duty_cycle.local_packetbuf;
}
/*---------------------------------------------------------------------------*/
static void
disable_local_packetbuf(void)
{
  packetbuf = u.duty_cycle.actual_packetbuf;
}
/*---------------------------------------------------------------------------*/
#if POTR_ENABLED
static int
is_anything_locked(void)
{
  return aes_128_locked || akes_nbr_locked || nbr_table_locked;
}
#endif /* !POTR_ENABLED */
/*---------------------------------------------------------------------------*/
static void
on_fifop(void)
{
  if(is_duty_cycling) {
    if(!u.duty_cycle.got_shr) {
      PRINTF("secrdc: FIFOP unexpected\n");
    } else {
      /* avoid that on_fifop is called twice if FIFOP_THRESHOLD is very low */
      NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK, NULL, 127);
      enable_local_packetbuf();
      if(0
#if POTR_ENABLED
          || is_anything_locked()
#endif /* !POTR_ENABLED */
          || (NETSTACK_RADIO_ASYNC.read_phy_header_and_set_datalen() < CONTIKIMAC_FRAMER_SHORTEST_PACKET_SIZE)
          || !NETSTACK_RADIO_ASYNC.read_payload(FIFOP_THRESHOLD)
#if POTR_ENABLED
          || (potr_parse_and_validate() == FRAMER_FAILED)
#else /* !POTR_ENABLED */
          || (framer_802154_filter() == FRAMER_FAILED)
#endif /* !POTR_ENABLED */
          ) {
        disable_and_reset_radio();
        PRINTF("secrdc: rejected frame of length %i\n", packetbuf_datalen());
        finish_duty_cycle();
      } else {
        u.duty_cycle.shall_send_acknowledgement = !packetbuf_holds_broadcast();
#if SECRDC_WITH_SECURE_PHASE_LOCK
        u.duty_cycle.is_helloack = potr_is_helloack();
        u.duty_cycle.is_ack = potr_is_ack();
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */

        if(u.duty_cycle.shall_send_acknowledgement) {
          prepare_acknowledgement();
        }
        NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK,
            on_final_fifop,
            NETSTACK_RADIO_ASYNC.remaining_payload_bytes() + RADIO_ASYNC_CHECKSUM_LEN);
      }
      disable_local_packetbuf();
    }
  }
}
/*---------------------------------------------------------------------------*/
static void
prepare_acknowledgement(void)
{
#if POTR_ENABLED
#if SECRDC_WITH_SECURE_PHASE_LOCK

  /* zero */
  memset(u.duty_cycle.acknowledgement, 0, MAX_ACKNOWLEDGEMENT_LEN);

  /* read strobe index */
  NETSTACK_RADIO_ASYNC.read_payload(1);

  /* create header */
  u.duty_cycle.acknowledgement[0] = POTR_FRAME_TYPE_ACKNOWLEDGEMENT;
  if(u.duty_cycle.is_helloack) {
    csprng_rand(last_random_number, AKES_NBR_CHALLENGE_LEN);
    memcpy(u.duty_cycle.acknowledgement + 1, last_random_number, AKES_NBR_CHALLENGE_LEN);
    NETSTACK_RADIO_ASYNC.prepare(u.duty_cycle.acknowledgement, HELLOACK_ACKNOWLEDGEMENT_LEN);
    return;
  } else {
    u.duty_cycle.acknowledgement[1] = secrdc_get_last_delta();
    if(u.duty_cycle.is_ack) {
#if ILOS_ENABLED
      ilos_write_wake_up_counter(u.duty_cycle.acknowledgement + 2, secrdc_get_wake_up_counter(RTIMER_NOW()));
#endif /* ILOS_ENABLED */
      u.duty_cycle.acknowledgement_len = ACK_ACKNOWLEDGEMENT_LEN;
    } else {
      u.duty_cycle.acknowledgement_len = ACKNOWLEDGEMENT_LEN;
      create_acknowledgement_mic();
    }
  }
  NETSTACK_RADIO_ASYNC.prepare(u.duty_cycle.acknowledgement, u.duty_cycle.acknowledgement_len);
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
  uint8_t acknowledgement[ACKNOWLEDGEMENT_LEN];
  acknowledgement[0] = POTR_FRAME_TYPE_ACKNOWLEDGEMENT;
  acknowledgement[1] = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1) & 0xFF;
  NETSTACK_RADIO_ASYNC.prepare(acknowledgement, ACKNOWLEDGEMENT_LEN);
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
#else /* POTR_ENABLED */
  uint8_t acknowledgement[ACKNOWLEDGEMENT_LEN];
  acknowledgement[0] = FRAME802154_ACKFRAME;
  acknowledgement[1] = 0;
  acknowledgement[2] = packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
  NETSTACK_RADIO_ASYNC.prepare(acknowledgement, ACKNOWLEDGEMENT_LEN);
#endif /* POTR_ENABLED */
}
/*---------------------------------------------------------------------------*/
static void
on_final_fifop(void)
{
  if(is_duty_cycling) {
    /* avoid that on_final_fifop is called twice */
    NETSTACK_RADIO_ASYNC.set_object(RADIO_PARAM_FIFOP_CALLBACK, NULL, 0);
    if(!u.duty_cycle.shall_send_acknowledgement
        || !(NETSTACK_RADIO_ASYNC.transmit() == RADIO_TX_OK)) {
      NETSTACK_RADIO_ASYNC.off();
      finish_duty_cycle();
    }
#if SECRDC_WITH_SECURE_PHASE_LOCK
    else if(!received_authentic_unicast()) {
      disable_and_reset_radio();
      PRINTF("secrdc: flushing unicast frame\n");
      finish_duty_cycle();
    } else if(u.duty_cycle.is_ack) {
      enable_local_packetbuf();
      create_acknowledgement_mic();
      NETSTACK_RADIO_ASYNC.reprepare(u.duty_cycle.acknowledgement_len - ADAPTIVESEC_UNICAST_MIC_LEN,
          u.duty_cycle.acknowledgement + u.duty_cycle.acknowledgement_len - ADAPTIVESEC_UNICAST_MIC_LEN,
          ADAPTIVESEC_UNICAST_MIC_LEN);
      disable_local_packetbuf();
    }
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  }
}
/*---------------------------------------------------------------------------*/
#if SECRDC_WITH_SECURE_PHASE_LOCK
static void
create_acknowledgement_mic(void)
{
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];

  AES_128_GET_LOCK();
  if(!u.duty_cycle.is_ack) {
    CCM_STAR.set_key(akes_nbr_get_sender_entry()->permanent->group_key);
  }
  ccm_star_packetbuf_set_nonce(nonce, 0
#if ILOS_ENABLED
      , NULL
#endif /* ILOS_ENABLED */
  );
  ccm_star_packetbuf_to_acknowledgement_nonce(nonce);
  CCM_STAR.aead(nonce,
      NULL, 0,
      u.duty_cycle.acknowledgement,
      u.duty_cycle.acknowledgement_len - ADAPTIVESEC_UNICAST_MIC_LEN,
      u.duty_cycle.acknowledgement + u.duty_cycle.acknowledgement_len - ADAPTIVESEC_UNICAST_MIC_LEN,
      ADAPTIVESEC_UNICAST_MIC_LEN,
      1);
  AES_128_RELEASE_LOCK();
}
/*---------------------------------------------------------------------------*/
static int
received_authentic_unicast(void)
{
  struct akes_nbr_entry *entry;

  if(u.duty_cycle.is_helloack) {
    /* HELLOACKs are parsed and verified later */
    return 1;
  }

  enable_local_packetbuf();

  u.duty_cycle.read_and_parsed = !is_anything_locked()
      && NETSTACK_RADIO_ASYNC.read_payload(NETSTACK_RADIO_ASYNC.remaining_payload_bytes())
      && parse_unicast_frame()
      && ((entry = akes_nbr_get_sender_entry()))
      && ((!u.duty_cycle.is_ack
          && entry->permanent
          && !ADAPTIVESEC_STRATEGY.verify(entry->permanent))
      || (u.duty_cycle.is_ack
          && is_valid_ack(entry)));

  disable_local_packetbuf();
  return u.duty_cycle.read_and_parsed;
}
/*---------------------------------------------------------------------------*/
static int
is_valid_ack(struct akes_nbr_entry *entry)
{
  uint8_t *payload;

  payload = packetbuf_dataptr();
  payload++;

#if ANTI_REPLAY_WITH_SUPPRESSION
  packetbuf_set_attr(PACKETBUF_ATTR_NEIGHBOR_INDEX, payload[AKES_NBR_CHALLENGE_LEN + 1 + 1]);
  anti_replay_parse_counter(payload + AKES_NBR_CHALLENGE_LEN + 1 + 1 + 1);
#endif /* ANTI_REPLAY_WITH_SUPPRESSION */
  packetbuf_set_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES,
      packetbuf_datalen() - AES_128_KEY_LENGTH - ADAPTIVESEC_UNICAST_MIC_LEN);

  if((payload[ILOS_WAKE_UP_COUNTER_LEN + AKES_NBR_CHALLENGE_LEN] != entry->tentative->meta->strobe_index)
      || memcmp(payload + ILOS_WAKE_UP_COUNTER_LEN, entry->tentative->meta->tail, AKES_NBR_CHALLENGE_LEN)
      || adaptivesec_verify(entry->tentative->tentative_pairwise_key
#if ILOS_ENABLED
          , NULL
#endif /* ILOS_ENABLED */
    )) {
    PRINTF("secrdc: Invalid ACK\n");
    akes_nbr_delete(entry, AKES_NBR_TENTATIVE);
    return 0;
  } else {
    return 1;
  }
}
/*---------------------------------------------------------------------------*/
static int
parse_unicast_frame(void)
{
  if(NETSTACK_FRAMER.parse() == FRAMER_FAILED) {
    return 0;
  }
#if LLSEC802154_USES_AUX_HEADER && POTR_ENABLED
  packetbuf_set_attr(PACKETBUF_ATTR_SECURITY_LEVEL, adaptivesec_get_sec_lvl());
#endif /* LLSEC802154_USES_AUX_HEADER && POTR_ENABLED */
  return 1;
}
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
static void
on_txdone(void)
{
  if(is_duty_cycling) {
    NETSTACK_RADIO_ASYNC.off();
    finish_duty_cycle();
  } else if(is_strobing) {
#if SECRDC_WITH_SECURE_PHASE_LOCK
    u.strobe.t1[0] = u.strobe.t1[1];
    u.strobe.t1[1] = RTIMER_NOW();
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
    strobe();
  }
}
/*---------------------------------------------------------------------------*/
static void
finish_duty_cycle(void)
{
  is_duty_cycling = 0;
  process_poll(&post_processing);
}
/*---------------------------------------------------------------------------*/
#if SECRDC_WITH_SECURE_PHASE_LOCK
uint8_t
secrdc_get_last_delta(void)
{
  return sfd_timestamp
      - duty_cycle_next
      - INTER_FRAME_PERIOD
      - SHR_DETECTION_TIME;
}
/*---------------------------------------------------------------------------*/
uint8_t
secrdc_get_last_strobe_index(void)
{
  return u.strobe.strobes;
}
/*---------------------------------------------------------------------------*/
uint8_t *
secrdc_get_last_random_number(void)
{
  return last_random_number;
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t
secrdc_get_last_but_one_t1(void)
{
  return u.strobe.t1[0];
}
/*---------------------------------------------------------------------------*/
#if ILOS_ENABLED
rtimer_clock_t
secrdc_get_last_wake_up_time(void)
{
  return duty_cycle_next;
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t
secrdc_get_next_strobe_start(void)
{
  return u.strobe.strobe_start;
}
/*---------------------------------------------------------------------------*/
ilos_wake_up_counter_t
secrdc_get_wake_up_counter(rtimer_clock_t t)
{
  ilos_wake_up_counter_t result;

  result = my_wake_up_counter;
  result.u32 += rtimer_delta(my_wake_up_counter_last_increment, t) >> SECRDC_WAKEUP_INTERVAL_BITS;

  return result;
}
#endif /* ILOS_ENABLED */
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(post_processing, ev, data)
{
  int just_received_broadcast;
  int prepare_result;

  PROCESS_BEGIN();

  while(1) {
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
    while(!u.duty_cycle.rtimer_freed);

    just_received_broadcast = 0;

    /* read received frame */
    if(NETSTACK_RADIO_ASYNC.pending_packet()
#if SECRDC_WITH_SECURE_PHASE_LOCK
        || u.duty_cycle.read_and_parsed
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
        ) {
      enable_local_packetbuf();
#if SECRDC_WITH_SECURE_PHASE_LOCK
      if(!u.duty_cycle.read_and_parsed
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
      if(1
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
          && ((!NETSTACK_RADIO_ASYNC.read_payload(NETSTACK_RADIO_ASYNC.remaining_payload_bytes())
              || (NETSTACK_FRAMER.parse() == FRAMER_FAILED)))) {
        PRINTF("secrdc: something went wrong while reading\n");
      } else {
        NETSTACK_RADIO_ASYNC.read_footer();
        just_received_broadcast = packetbuf_holds_broadcast();
        NETSTACK_MAC.input();
      }
      disable_local_packetbuf();
      NETSTACK_RADIO_ASYNC.flushrx();
    }

    /* send queued frames */
    if(!just_received_broadcast) {
      while(list_head(buffered_frames_list)) {
        enable_shr_search();
        memset(&u.strobe, 0, sizeof(u.strobe));
        u.strobe.bf = list_head(buffered_frames_list);
        queuebuf_to_packetbuf(u.strobe.bf->qb);
        u.strobe.is_broadcast = packetbuf_holds_broadcast();
        // TODOX strobe starts, if(packetbuf attribute = our_attribute) reset_timer
        if (packetbuf_attr(PACKETBUF_ATTR_TIME_TYPE) > 0) {
          reset_tx();
        }

#if ILOS_ENABLED
        if(u.strobe.is_broadcast) {
          u.strobe.strobe_start = shift_to_future(duty_cycle_next)
              - (WAKEUP_INTERVAL / 2)
              - LPM_SWITCHING
              - INTRA_COLLISION_AVOIDANCE_DURATION
              - TRANSMIT_CALIBRATION_TIME;
          if(!(secrdc_get_wake_up_counter(u.strobe.strobe_start).u32 & 1)) {
            u.strobe.strobe_start += WAKEUP_INTERVAL;
          }
          while(!rtimer_is_schedulable(u.strobe.strobe_start, ILOS_MIN_TIME_TO_STROBE + 1)) {
            u.strobe.strobe_start += 2 * WAKEUP_INTERVAL;
          }
        } else if(potr_is_helloack()) {
          ilos_write_wake_up_counter(((uint8_t *)packetbuf_dataptr()) + 1, secrdc_get_wake_up_counter(RTIMER_NOW()));
          u.strobe.is_helloack = 1;
          u.strobe.acknowledgement_len = HELLOACK_ACKNOWLEDGEMENT_LEN;
          u.strobe.strobe_start = RTIMER_NOW() + ILOS_MIN_TIME_TO_STROBE;
        } else if(potr_is_ack()) {
          ilos_write_wake_up_counter(((uint8_t *)packetbuf_dataptr()) + 1, secrdc_get_wake_up_counter(RTIMER_NOW()));
          akes_nbr_copy_key(u.strobe.acknowledgement_key, akes_nbr_get_receiver_entry()->tentative->tentative_pairwise_key);
          u.strobe.is_ack = 1;
          u.strobe.acknowledgement_len = ACK_ACKNOWLEDGEMENT_LEN;
          u.strobe.phase = obtain_phase_lock_data();
          if(!u.strobe.phase) {
            u.strobe.result = MAC_TX_ERR_FATAL;
            on_strobed();
            continue;
          }
          u.strobe.strobe_start = RTIMER_NOW() + ILOS_MIN_TIME_TO_STROBE;
        } else {
          akes_nbr_copy_key(u.strobe.acknowledgement_key, adaptivesec_group_key);
          u.strobe.acknowledgement_len = ACKNOWLEDGEMENT_LEN;
          u.strobe.phase = obtain_phase_lock_data();
          if(!u.strobe.phase) {
            u.strobe.result = MAC_TX_ERR_FATAL;
            on_strobed();
            continue;
          }

          u.strobe.uncertainty = PHASE_LOCK_GUARD_TIME
              + (PHASE_LOCK_FREQ_TOLERANCE
              * ((rtimer_delta(u.strobe.phase->t, RTIMER_NOW()) / RTIMER_ARCH_SECOND) + 1));
          if(u.strobe.uncertainty >= (WAKEUP_INTERVAL / 2)) {
            u.strobe.result = MAC_TX_ERR_FATAL;
            on_strobed();
            continue;
          }

          u.strobe.strobe_start = shift_to_future(u.strobe.phase->t
              - LPM_SWITCHING
              - INTRA_COLLISION_AVOIDANCE_DURATION
              - TRANSMIT_CALIBRATION_TIME
              - u.strobe.uncertainty);

          while(!rtimer_is_schedulable(u.strobe.strobe_start, ILOS_MIN_TIME_TO_STROBE + 1)) {
            u.strobe.strobe_start += WAKEUP_INTERVAL;
          }
        }
#endif /* ILOS_ENABLED */

        /* create frame */
#if !POTR_ENABLED
        packetbuf_set_attr(PACKETBUF_ATTR_MAC_ACK, 1);
#endif /* !POTR_ENABLED */
        if(NETSTACK_FRAMER.create() == FRAMER_FAILED) {
          PRINTF("secrdc: NETSTACK_FRAMER.create failed\n");
          u.strobe.result = MAC_TX_ERR_FATAL;
          on_strobed();
          continue;
        }

        /* is this a broadcast? */
#if !SECRDC_WITH_SECURE_PHASE_LOCK
#if POTR_ENABLED
        u.strobe.seqno = packetbuf_attr(PACKETBUF_ATTR_FRAME_COUNTER_BYTES_0_1) & 0xFF;
#else /* POTR_ENABLED */
        u.strobe.seqno = packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO);
#endif /* POTR_ENABLED */
#endif /* !SECRDC_WITH_SECURE_PHASE_LOCK */

        /* move frame to radio */
        prepare_result = NETSTACK_RADIO_ASYNC.prepare(packetbuf_hdrptr(), packetbuf_totlen());
        if(prepare_result != RADIO_TX_OK) {
          PRINTF("secrdc: NETSTACK_RADIO_ASYNC.prepare failed with %i\n", prepare_result);
          u.strobe.result = mac_to_mac_result(prepare_result);
          on_strobed();
          continue;
        }

        /* starting to strobe */
#if ILOS_ENABLED
        if(!rtimer_is_schedulable(u.strobe.strobe_start, RTIMER_GUARD_TIME + 1)) {
          PRINTF("secrdc: strobe starts too early\n");
          u.strobe.result = MAC_TX_ERR_FATAL;
          on_strobed();
          continue;
        }
        schedule_strobe(u.strobe.strobe_start);
#elif SECRDC_WITH_PHASE_LOCK
        if(u.strobe.is_broadcast) {
          /* strobe broadcast frames immediately */
          strobe_soon();
#if SECRDC_WITH_SECURE_PHASE_LOCK
        } else if(potr_is_helloack()) {
          u.strobe.is_helloack = 1;
          u.strobe.acknowledgement_len = HELLOACK_ACKNOWLEDGEMENT_LEN;
          strobe_soon();
        } else if(potr_is_ack()) {
          u.strobe.is_ack = 1;
          akes_nbr_copy_key(u.strobe.acknowledgement_key, akes_nbr_get_receiver_entry()->tentative->tentative_pairwise_key);
          u.strobe.acknowledgement_len = ACK_ACKNOWLEDGEMENT_LEN;
          u.strobe.phase = obtain_phase_lock_data();
          if(!u.strobe.phase) {
            u.strobe.result = MAC_TX_ERR_FATAL;
            on_strobed();
            continue;
          }
          strobe_soon();
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
        } else {
#if SECRDC_WITH_SECURE_PHASE_LOCK
          akes_nbr_copy_key(u.strobe.acknowledgement_key, adaptivesec_group_key);
          u.strobe.acknowledgement_len = ACKNOWLEDGEMENT_LEN;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
          u.strobe.phase = obtain_phase_lock_data();
          if(!u.strobe.phase) {
            u.strobe.result = MAC_TX_ERR_FATAL;
            on_strobed();
            continue;
          }
#if SECRDC_WITH_SECURE_PHASE_LOCK
          u.strobe.uncertainty = PHASE_LOCK_GUARD_TIME
              + (PHASE_LOCK_FREQ_TOLERANCE
              * ((rtimer_delta(u.strobe.phase->t, RTIMER_NOW()) / RTIMER_ARCH_SECOND) + 1));
          if(u.strobe.uncertainty >= (WAKEUP_INTERVAL / 2)) {
            /* uncertainty too high */
            u.strobe.uncertainty = 0;
            strobe_soon();
          } else {
            is_strobing = 1;
            schedule_strobe(shift_to_future(u.strobe.phase->t
                - LPM_SWITCHING
                - INTRA_COLLISION_AVOIDANCE_DURATION
                - TRANSMIT_CALIBRATION_TIME
                - u.strobe.uncertainty));
          }
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
          if(!u.strobe.phase->t) {
            /* no phase-lock information stored, yet */
            strobe_soon();
          } else {
            schedule_strobe(shift_to_future(u.strobe.phase->t
                  - LPM_SWITCHING
                  - INTRA_COLLISION_AVOIDANCE_DURATION
                  - TRANSMIT_CALIBRATION_TIME
                  - PHASE_LOCK_GUARD_TIME));
          }
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
        }
#else /* SECRDC_WITH_PHASE_LOCK */
        strobe_soon();
#endif /* SECRDC_WITH_PHASE_LOCK */

        /* process strobe result */
        PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);
        u.strobe.bf->transmissions++;
        on_strobed();
      }
    }
#ifdef LPM_CONF_ENABLE
    lpm_set_max_pm(LPM_CONF_MAX_PM);
#endif /* LPM_CONF_ENABLE */

    /* prepare next duty cycle */
#if WITH_AUTO_CCA
    update_floor_noise();
#endif /* WITH_AUTO_CCA */
    prepare_radio_for_duty_cycle();
    memset(&u.duty_cycle, 0, sizeof(u.duty_cycle));
    duty_cycle_next = shift_to_future(duty_cycle_next);
    schedule_duty_cycle(duty_cycle_next);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
#if SECRDC_WITH_SECURE_PHASE_LOCK
void
secrdc_cache_unsecured_frame(uint8_t *key
#if ILOS_ENABLED
, struct secrdc_phase *phase
#endif /* ILOS_ENABLED */
)
{
  ccm_star_packetbuf_set_nonce(u.strobe.nonce, 1
#if ILOS_ENABLED
      , phase
#endif /* ILOS_ENABLED */
  );
  u.strobe.shall_encrypt = adaptivesec_get_sec_lvl() & (1 << 2);
  if(u.strobe.shall_encrypt) {
    u.strobe.a_len = packetbuf_hdrlen() + packetbuf_attr(PACKETBUF_ATTR_UNENCRYPTED_BYTES);
    u.strobe.m_len = packetbuf_totlen() - u.strobe.a_len;
  } else {
    u.strobe.a_len = packetbuf_totlen();
    u.strobe.m_len = 0;
  }
  u.strobe.mic_len = adaptivesec_mic_len();
  u.strobe.totlen = packetbuf_totlen();
  memcpy(u.strobe.unsecured_frame, packetbuf_hdrptr(), packetbuf_totlen());
  akes_nbr_copy_key(u.strobe.key, key);
}
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
#if SECRDC_WITH_PHASE_LOCK
static struct secrdc_phase *
obtain_phase_lock_data(void)
{
  struct akes_nbr_entry *entry;
  struct akes_nbr *nbr;

  entry = akes_nbr_get_receiver_entry();
  if(!entry) {
    PRINTF("secrdc: no entry found\n");
    return NULL;
  }
#if SECRDC_WITH_SECURE_PHASE_LOCK
  nbr = entry->permanent;
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
  nbr = entry->refs[u.strobe.bf->receiver_status];
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  if(!nbr) {
    PRINTF("secrdc: could not obtain phase-lock data\n");
    return NULL;
  }
  return &nbr->phase;
}
#endif /* SECRDC_WITH_PHASE_LOCK */
/*---------------------------------------------------------------------------*/
static void
strobe_soon(void)
{
  schedule_strobe(RTIMER_NOW() + RTIMER_GUARD_TIME);
}
/*---------------------------------------------------------------------------*/
static void
schedule_strobe(rtimer_clock_t time)
{
  if(rtimer_set(&timer, time, 1, strobe_wrapper, NULL) != RTIMER_OK) {
    PRINTF("secrdc: rtimer_set failed\n");
  }
}
/*---------------------------------------------------------------------------*/
static void
strobe_wrapper(struct rtimer *rt, void *ptr)
{
  strobe();
}
/*---------------------------------------------------------------------------*/
static char
strobe(void)
{
  uint8_t acknowledgement[MAX_ACKNOWLEDGEMENT_LEN];

  PT_BEGIN(&pt);

  is_strobing = 1;

#if WITH_INTRA_COLLISION_AVOIDANCE
  /* enable RX to make a CCA before transmitting */
  u.strobe.next_transmission = RTIMER_NOW() + INTRA_COLLISION_AVOIDANCE_DURATION;
  NETSTACK_RADIO_ASYNC.on();
#else /* WITH_INTRA_COLLISION_AVOIDANCE */
  u.strobe.next_transmission = RTIMER_NOW();
#endif /* WITH_INTRA_COLLISION_AVOIDANCE */

#if SECRDC_WITH_SECURE_PHASE_LOCK
  if(u.strobe.uncertainty) {
    u.strobe.timeout = shift_to_future(u.strobe.phase->t + u.strobe.uncertainty);
    /* if we come from PM0, we will be too early */
    while(!rtimer_has_timed_out(timer.time));
  } else
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  {
    u.strobe.timeout = RTIMER_NOW() + WAKEUP_INTERVAL;
  }
  while(1) {
    if(!u.strobe.strobes) {
#if WITH_INTRA_COLLISION_AVOIDANCE
      if(!channel_clear(COLLISION_AVOIDANCE)) {
        PRINTF("secrdc: collision\n");
        u.strobe.result = MAC_TX_COLLISION;
        break;
      }
      NETSTACK_RADIO_ASYNC.off();
      /* do second CCA before starting a burst */
      schedule_strobe(RTIMER_NOW() + INTER_CCA_PERIOD - LPM_SWITCHING);
      PT_YIELD(&pt);
      /* if we come from PM0, we will be too early */
      while(!rtimer_has_timed_out(timer.time));
      NETSTACK_RADIO_ASYNC.on();
      if(!channel_clear(COLLISION_AVOIDANCE)) {
        PRINTF("secrdc: collision\n");
        u.strobe.result = MAC_TX_COLLISION;
        break;
      }
#endif /* WITH_INTRA_COLLISION_AVOIDANCE */
#ifdef LPM_CONF_ENABLE
      lpm_set_max_pm(0);
#endif /* LPM_CONF_ENABLE */
    } else {
#if WITH_INTER_COLLISION_AVOIDANCE
    if(!channel_clear(COLLISION_AVOIDANCE)) {
      PRINTF("secrdc: collision\n");
      u.strobe.result = MAC_TX_COLLISION;
      break;
    }
#endif /* WITH_INTER_COLLISION_AVOIDANCE */
    }

    /* busy waiting for better timing */
    while(!rtimer_has_timed_out(u.strobe.next_transmission));

    if(transmit() != RADIO_TX_OK) {
      PRINTF("secrdc: NETSTACK_RADIO_ASYNC.transmit failed\n");
      u.strobe.result = MAC_TX_ERR;
      break;
    }
    PT_YIELD(&pt);
    u.strobe.next_transmission = RTIMER_NOW()
        - TXDONE_DELAY
        + INTER_FRAME_PERIOD
        - TRANSMIT_CALIBRATION_TIME
        + INTER_FRAMER_PERIOD_ADJUSTMENT;

    if(u.strobe.is_broadcast || !u.strobe.strobes /* little tweak */) {
      if(!should_strobe_again()) {
        u.strobe.result = MAC_TX_OK;
        break;
      }
      NETSTACK_RADIO_ASYNC.off();
      schedule_strobe(u.strobe.next_transmission
#if WITH_INTER_COLLISION_AVOIDANCE
        - RECEIVE_CALIBRATION_TIME
        - CCA_DURATION
#endif /* WITH_INTER_COLLISION_AVOIDANCE */
        - 2 /* the rtimer may wake us up too late otherwise */);
      PT_YIELD(&pt);
#if WITH_INTER_COLLISION_AVOIDANCE
      NETSTACK_RADIO_ASYNC.on();
#endif /* WITH_INTER_COLLISION_AVOIDANCE */
    } else {
      /* wait for acknowledgement */
      schedule_strobe(RTIMER_NOW() + ACKNOWLEDGEMENT_WINDOW_MAX);
      PT_YIELD(&pt);
      if(NETSTACK_RADIO_ASYNC.receiving_packet() || NETSTACK_RADIO_ASYNC.pending_packet()) {
        if(NETSTACK_RADIO_ASYNC.read_phy_header() != EXPECTED_ACKNOWLEDGEMENT_LEN) {
          PRINTF("secrdc: unexpected frame\n");
          u.strobe.result = MAC_TX_COLLISION;
          break;
        }

        /* read acknowledgement */
        NETSTACK_RADIO_ASYNC.read_raw(acknowledgement, EXPECTED_ACKNOWLEDGEMENT_LEN);
        NETSTACK_RADIO_ASYNC.flushrx();
        if(is_valid(acknowledgement)) {
          u.strobe.result = MAC_TX_OK;
#if SECRDC_WITH_PHASE_LOCK
#if SECRDC_WITH_SECURE_PHASE_LOCK
          if(u.strobe.is_helloack) {
            memcpy(last_random_number, acknowledgement + 1, AKES_NBR_CHALLENGE_LEN);
            break;
          }
#if ILOS_ENABLED
          if(u.strobe.is_ack) {
            u.strobe.phase->his_wake_up_counter_at_t = ilos_parse_wake_up_counter(acknowledgement + 2);
          } else {
            u.strobe.phase->his_wake_up_counter_at_t = ilos_parse_wake_up_counter(u.strobe.nonce + 9);
            u.strobe.phase->his_wake_up_counter_at_t.u32 -= 0x40000000;
          }
#endif /* ILOS_ENABLED */
          u.strobe.phase->t = u.strobe.t1[0] - acknowledgement[1];
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
          u.strobe.phase->t = u.strobe.t0[0];
          if(!u.strobe.phase->t) {
            /* zero is reserved for uninitialized phase-lock data */
            u.strobe.phase->t = -WAKEUP_INTERVAL;
          }
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
#endif /* SECRDC_WITH_PHASE_LOCK */
#ifndef SECRDC_CONF_INFINITE_STROBE
          break;
#endif /* SECRDC_CONF_INFINITE_STROBE */
        }
      }

      /* schedule next transmission */
      if(!should_strobe_again()) {
        u.strobe.result = MAC_TX_NOACK;
        break;
      }
      if(!rtimer_is_schedulable(u.strobe.next_transmission - 3, RTIMER_GUARD_TIME + 1)) {
        strobe_soon();
      } else {
        schedule_strobe(u.strobe.next_transmission - 3 /* the rtimer may wake us up too late otherwise */);
      }
      PT_YIELD(&pt);
    }
    u.strobe.strobes++;
  }

  disable_and_reset_radio();
  is_strobing = 0;
  process_poll(&post_processing);
  PT_END(&pt);
}
/*---------------------------------------------------------------------------*/
static int
should_strobe_again(void)
{
#if SECRDC_WITH_SECURE_PHASE_LOCK
  if(u.strobe.strobes == 0xFF) {
    PRINTF("secrdc: strobe index reached maximum\n");
    return 0;
  }
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  return rtimer_smaller_or_equal(u.strobe.next_transmission + TRANSMIT_CALIBRATION_TIME, u.strobe.timeout)
      || !u.strobe.sent_once_more++;
}
/*---------------------------------------------------------------------------*/
static int
transmit(void)
{
  int result;
#if SECRDC_WITH_SECURE_PHASE_LOCK
  uint8_t secured_frame[MAX_FRAME_LEN];
  uint8_t *m;
  uint8_t offset;
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */

#if SECRDC_WITH_ORIGINAL_PHASE_LOCK
  u.strobe.t0[0] = u.strobe.t0[1];
  u.strobe.t0[1] = RTIMER_NOW();
#endif /* SECRDC_WITH_ORIGINAL_PHASE_LOCK */
  result = NETSTACK_RADIO_ASYNC.transmit();

#if SECRDC_WITH_SECURE_PHASE_LOCK
  if(result != RADIO_TX_OK) {
    return result;
  }

  if(u.strobe.strobes && u.strobe.is_broadcast) {
    return result;
  }

  if(aes_128_locked) {
    return RADIO_TX_ERR;
  }

  if(!u.strobe.is_broadcast) {
    /* set strobe index */
    u.strobe.unsecured_frame[POTR_HEADER_LEN] = u.strobe.strobes;
    u.strobe.nonce[8] = u.strobe.strobes;
    NETSTACK_RADIO_ASYNC.reprepare(POTR_HEADER_LEN, &u.strobe.strobes, 1);
  }

  memcpy(secured_frame, u.strobe.unsecured_frame, u.strobe.totlen);
  m = u.strobe.shall_encrypt ? (secured_frame + u.strobe.a_len) : NULL;
  AES_128_GET_LOCK();
  CCM_STAR.set_key(u.strobe.key);
  CCM_STAR.aead(u.strobe.nonce,
      m, u.strobe.m_len,
      secured_frame, u.strobe.a_len,
      secured_frame + u.strobe.totlen, u.strobe.mic_len,
      1);
  AES_128_RELEASE_LOCK();
  offset = potr_length_of(u.strobe.unsecured_frame[0]) + CONTIKIMAC_FRAMER_HEADER_LEN;
  NETSTACK_RADIO_ASYNC.reprepare(offset,
      secured_frame + offset,
      u.strobe.totlen + u.strobe.mic_len - offset);
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
  return result;
}
/*---------------------------------------------------------------------------*/
static int
is_valid(uint8_t *acknowledgement)
{
#if SECRDC_WITH_SECURE_PHASE_LOCK
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];
  uint8_t expected_mic[ADAPTIVESEC_UNICAST_MIC_LEN];
  rtimer_clock_t diff;

  diff = rtimer_delta(u.strobe.t1[1], sfd_timestamp);
  if((diff < ACKNOWLEDGEMENT_WINDOW_MIN)
      || (diff > ACKNOWLEDGEMENT_WINDOW_MAX)) {
    PRINTF("secrdc: acknowledgement frame wasn't timely\n");
    return 0;
  }
  if(u.strobe.is_helloack) {
    return 1;
  }
  if(aes_128_locked) {
    PRINTF("secrdc: could not validate acknowledgement frame\n");
    return 0;
  }

  memcpy(nonce, u.strobe.nonce, CCM_STAR_NONCE_LENGTH);
  AES_128_GET_LOCK();
  CCM_STAR.set_key(u.strobe.acknowledgement_key);
  ccm_star_packetbuf_to_acknowledgement_nonce(nonce);
  CCM_STAR.aead(nonce,
      NULL, 0,
      acknowledgement, EXPECTED_ACKNOWLEDGEMENT_LEN - ADAPTIVESEC_UNICAST_MIC_LEN,
      expected_mic, ADAPTIVESEC_UNICAST_MIC_LEN,
      1);
  AES_128_RELEASE_LOCK();
  if(memcmp(expected_mic, acknowledgement + EXPECTED_ACKNOWLEDGEMENT_LEN - ADAPTIVESEC_UNICAST_MIC_LEN, ADAPTIVESEC_UNICAST_MIC_LEN)) {
    PRINTF("secrdc: inauthentic acknowledgement frame\n");
    return 0;
  }
  return 1;
#else /* SECRDC_WITH_SECURE_PHASE_LOCK */
  return u.strobe.seqno == acknowledgement[ACKNOWLEDGEMENT_LEN - 1];
#endif /* SECRDC_WITH_SECURE_PHASE_LOCK */
}
/*---------------------------------------------------------------------------*/
static void
on_strobed(void)
{
#if DEBUG
  if(!u.strobe.is_broadcast) {
    PRINTF("secrdc: strobed %i times with %s\n",
        u.strobe.strobes + 1,
        (u.strobe.result == MAC_TX_OK) ? "success" : "error");
  }
#endif /* DEBUG */
  queuebuf_to_packetbuf(u.strobe.bf->qb);
  if(u.strobe.bf->allocated_qb) {
    queuebuf_free(u.strobe.bf->qb);
  }
  // TODOX strobe finished
/*   if (packetbuf_attr(PACKETBUF_ATTR_TIME_TYPE) > 0 && u.strobe.result == MAC_TX_OK) {
    switch (packetbuf_attr(PACKETBUF_ATTR_TIME_TYPE)) {
      case 1:
        printf("Ticks/Strobes for sending AKES UPDATE: %u %u\n", get_tx(), u.strobe.strobes + 1);
        break;
      case 2:
        printf("Ticks/Strobes for sending RPL DAO: %u %u\n", get_tx(), u.strobe.strobes + 1);
        break;
      case 3:
        printf("Ticks/Strobes for sending Key Revocation Response: %u %u\n", get_tx(), u.strobe.strobes + 1);
        break;
    }
  } */
  mac_call_sent_callback(u.strobe.bf->sent,
      u.strobe.bf->ptr,
      u.strobe.result,
      u.strobe.bf->transmissions);
  if((u.strobe.result == MAC_TX_OK) && u.strobe.bf->tail) {
    send_list(u.strobe.bf->sent, u.strobe.bf->ptr, u.strobe.bf->tail);
  }
  list_remove(buffered_frames_list, u.strobe.bf);
  memb_free(&buffered_frames_memb, u.strobe.bf);
}
/*---------------------------------------------------------------------------*/
static void
send(mac_callback_t sent, void *ptr)
{
  queue_frame(sent, ptr, NULL, NULL);
}
/*---------------------------------------------------------------------------*/
/* TODO burst support */
static void
send_list(mac_callback_t sent, void *ptr, struct rdc_buf_list *list)
{
  queue_frame(sent, ptr, list->buf, list_item_next(list));
}
/*---------------------------------------------------------------------------*/
static void
queue_frame(mac_callback_t sent,
    void *ptr,
    struct queuebuf *qb,
    struct rdc_buf_list *tail)
{
  struct buffered_frame *bf;

  bf = memb_alloc(&buffered_frames_memb);
  if(!bf) {
    PRINTF("secrdc: buffer is full\n");
    mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
    return;
  }
  if(!qb) {
    bf->qb = queuebuf_new_from_packetbuf();
    if(!bf->qb) {
      PRINTF("secrdc: queubuf is full\n");
      memb_free(&buffered_frames_memb, bf);
      mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 0);
      return;
    }
    bf->allocated_qb = 1;
  } else {
    bf->qb = qb;
    bf->allocated_qb = 0;
  }

  bf->ptr = ptr;
  bf->sent = sent;
  bf->transmissions = 0;
  bf->tail = tail;
#if SECRDC_WITH_ORIGINAL_PHASE_LOCK
  bf->receiver_status = akes_get_receiver_status();
#endif /* SECRDC_WITH_ORIGINAL_PHASE_LOCK */
  list_add(buffered_frames_list, bf);
}
/*---------------------------------------------------------------------------*/
static void
input(void)
{
  /* we operate in polling mode throughout */
}
/*---------------------------------------------------------------------------*/
static int
on(void)
{
  /* TODO implement if needed */
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
off(int keep_radio_on)
{
  /* TODO implement if needed  */
  return 1;
}
/*---------------------------------------------------------------------------*/
static unsigned short
channel_check_interval(void)
{
  return CLOCK_SECOND / NETSTACK_RDC_CHANNEL_CHECK_RATE;
}
/*---------------------------------------------------------------------------*/
const struct rdc_driver secrdc_driver = {
  "secrdc",
  init,
  send,
  send_list,
  input,
  on,
  off,
  channel_check_interval,
};
/*---------------------------------------------------------------------------*/
