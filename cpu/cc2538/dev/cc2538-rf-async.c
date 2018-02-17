/*
 * Copyright (c) 2012, Texas Instruments Incorporated - http://www.ti.com/
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
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *         Asynchronous RADIO driver.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#include "dev/radio-async.h"
#include "sys/clock.h"
#include "sys/rtimer.h"
#include "net/packetbuf.h"
#include "net/linkaddr.h"
#include "net/netstack.h"
#include "dev/cc2538-rf.h"
#include "dev/udma.h"
#include "dev/rfcore.h"
#include "dev/sys-ctrl.h"
#include "reg.h"
#include <string.h>
#include "dev/cc2538-rf-async.h"

#define CRC_BIT_MASK 0x80
#define LQI_BIT_MASK 0x7F
#define RSSI_OFFSET 73
#define UDMA_TX_FLAGS (UDMA_CHCTL_ARBSIZE_128 \
    | UDMA_CHCTL_XFERMODE_AUTO \
    | UDMA_CHCTL_SRCSIZE_8 \
    | UDMA_CHCTL_DSTSIZE_8 \
    | UDMA_CHCTL_SRCINC_8 \
    | UDMA_CHCTL_DSTINC_NONE)

#define DEBUG 0
#include <stdio.h>
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

static int pending_packet(void);
static void on(void);
static void off(void);

static uint8_t frame[1 + CC2538_RF_MAX_PACKET_LEN];
static volatile uint8_t read_bytes;
static volatile int in_rx_mode;
static volatile int in_tx_mode;
static volatile radio_sfd_callback_t sfd_callback;
static volatile radio_fifop_callback_t fifop_callback;
static volatile radio_txdone_callback_t txdone_callback;

/*---------------------------------------------------------------------------*/
static void
flushrx(void)
{
  CC2538_RF_CSP_ISFLUSHRX();
  read_bytes = 0;
}
/*---------------------------------------------------------------------------*/
static uint8_t
read_phy_header(void)
{
  uint8_t len;

  len = REG(RFCORE_SFR_RFDATA);

  /* ignore reserved bit */
  len &= ~(1 << 7);

#if RADIO_ASYNC_WITH_CHECKSUM
  if(len < RADIO_ASYNC_CHECKSUM_LEN) {
    PRINTF("cc2538-rf-async: frame too short\n");
    return 0;
  }
#endif /* RADIO_ASYNC_WITH_CHECKSUM */

  return len - RADIO_ASYNC_CHECKSUM_LEN;
}
/*---------------------------------------------------------------------------*/
static uint8_t
read_phy_header_and_set_datalen(void)
{
  uint8_t len;

  len = read_phy_header();
  packetbuf_set_datalen(len);
  return len;
}
/*---------------------------------------------------------------------------*/
static void
read_raw(uint8_t *buf, uint8_t bytes)
{
  uint8_t i;

  while(REG(RFCORE_XREG_RXFIFOCNT) < bytes);
  for(i = 0; i < bytes; i++) {
    buf[i] = REG(RFCORE_SFR_RFDATA);
  }
}
/*---------------------------------------------------------------------------*/
static int
read_payload(uint8_t bytes)
{
  read_raw(((uint8_t *)packetbuf_hdrptr()) + read_bytes, bytes);
  read_bytes += bytes;
  return 1;
}
/*---------------------------------------------------------------------------*/
static uint8_t
remaining_payload_bytes(void)
{
  return packetbuf_totlen() - read_bytes;
}
/*---------------------------------------------------------------------------*/
static int
read_footer(void)
{
#if RADIO_ASYNC_WITH_CHECKSUM
  uint8_t crc_corr;
  int8_t rssi;

  rssi = ((int8_t)REG(RFCORE_SFR_RFDATA)) - RSSI_OFFSET;
  crc_corr = REG(RFCORE_SFR_RFDATA);

  packetbuf_set_attr(PACKETBUF_ATTR_RSSI, rssi);
  packetbuf_set_attr(PACKETBUF_ATTR_LINK_QUALITY, crc_corr & LQI_BIT_MASK);

  if(!(crc_corr & CRC_BIT_MASK)) {
    PRINTF("cc2538-rf-async: invalid CRC\n");
    return 0;
  }
#endif /* RADIO_ASYNC_WITH_CHECKSUM */
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
set_shr_search(int enable)
{
  if(enable) {
    REG(RFCORE_XREG_FRMCTRL0) &= ~RFCORE_XREG_FRMCTRL0_RX_MODE;
  } else {
    REG(RFCORE_XREG_FRMCTRL0) |= RFCORE_XREG_FRMCTRL0_RX_MODE;
  }
}
/*---------------------------------------------------------------------------*/
static void
set_loop(int enable)
{
  if(enable) {
    REG(RFCORE_XREG_FRMCTRL0) |= RFCORE_XREG_FRMCTRL0_TX_MODE_LOOP;
  } else {
    /* TODO */
  }
}
/*---------------------------------------------------------------------------*/
static int
is_tx_active(void)
{
  return REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_TX_ACTIVE;
}
/*---------------------------------------------------------------------------*/
static void
wait_for_rssi(void)
{
  while(!(REG(RFCORE_XREG_RSSISTAT) & RFCORE_XREG_RSSISTAT_RSSI_VALID));
}
/*---------------------------------------------------------------------------*/
static int8_t
get_rssi(void)
{
  int8_t rssi;

  wait_for_rssi();
  rssi = REG(RFCORE_XREG_RSSI);
  rssi -= RSSI_OFFSET;

  return rssi;
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  /* Enable clock for the RF Core while Running, in Sleep and Deep Sleep */
  REG(SYS_CTRL_RCGCRFC) = 1;
  REG(SYS_CTRL_SCGCRFC) = 1;
  REG(SYS_CTRL_DCGCRFC) = 1;

  /* See Section "Register Settings Update" in the User's Guide */
  REG(RFCORE_XREG_AGCCTRL1) = 0x15;
  REG(RFCORE_XREG_TXFILTCFG) = 0x09;
  REG(ANA_REGS_IVCTRL) = 0x0B;
  REG(RFCORE_XREG_FSCAL1) = 0x01;

#if RADIO_ASYNC_WITH_CHECKSUM
  /* Note: the default value of FRMCTRL0 in the User's Guide is wrong */
  REG(RFCORE_XREG_FRMCTRL0) = RFCORE_XREG_FRMCTRL0_AUTOCRC;
#endif /* RADIO_ASYNC_WITH_CHECKSUM */

  /* Disable source address matching and AUTOPEND */
  REG(RFCORE_XREG_SRCMATCH) = 0;

  /* Set TX Power */
  REG(RFCORE_XREG_TXPOWER) = CC2538_RF_TX_POWER;

  /* Set channel */
  REG(RFCORE_XREG_FREQCTRL) = (CC2538_RF_CHANNEL_MIN
      + (CC2538_RF_CHANNEL - CC2538_RF_CHANNEL_MIN)
      * CC2538_RF_CHANNEL_SPACING);

  /* Disable frame filtering */
  REG(RFCORE_XREG_FRMFILT0) &= ~RFCORE_XREG_FRMFILT0_FRAME_FILTER_EN;

  /* Configure DMA */
  udma_channel_mask_set(CC2538_RF_CONF_TX_DMA_CHAN);
  udma_set_channel_dst(CC2538_RF_CONF_TX_DMA_CHAN, RFCORE_SFR_RFDATA);

  /* Configure interrupts */
  REG(RFCORE_XREG_RFIRQM1) |= RFCORE_XREG_RFIRQM1_TXDONE;
  NVIC_EnableIRQ(RF_TX_RX_IRQn);
#if DEBUG
  REG(RFCORE_XREG_RFERRM) = RFCORE_XREG_RFERRM_RFERRM;
  NVIC_EnableIRQ(RF_ERR_IRQn);
#endif /* DEBUG */

  flushrx();
}
/*---------------------------------------------------------------------------*/
static void
reprepare(uint8_t offset, uint8_t *src, uint8_t len)
{
  uint8_t i;

  for(i = 0; i < len; i++) {
    REG(RFCORE_FFSM_TX_FIFO + 4 * (1 + offset + i)) = src[i];
  }
}
/*---------------------------------------------------------------------------*/
static int
prepare(const void *payload, unsigned short payload_len)
{
  CC2538_RF_CSP_ISFLUSHTX();

  if(payload_len + RADIO_ASYNC_CHECKSUM_LEN > CC2538_RF_MAX_PACKET_LEN) {
    PRINTF("cc2538-rf-async: too much payload\n");
    return RADIO_TX_ERR;
  }

  frame[0] = payload_len + RADIO_ASYNC_CHECKSUM_LEN;
  memcpy(frame + 1, payload, payload_len);

  udma_set_channel_src(CC2538_RF_CONF_TX_DMA_CHAN,
      (uint32_t)(frame) + payload_len);
  udma_set_channel_control_word(CC2538_RF_CONF_TX_DMA_CHAN,
      UDMA_TX_FLAGS | udma_xfer_size(payload_len + 1));
  udma_channel_enable(CC2538_RF_CONF_TX_DMA_CHAN);
  udma_channel_sw_request(CC2538_RF_CONF_TX_DMA_CHAN);

  return RADIO_TX_OK;
}
/*---------------------------------------------------------------------------*/
rtimer_clock_t tx_start;
rtimer_clock_t rx_start;
rtimer_clock_t rx_acc = 0;
rtimer_clock_t tx_acc = 0;
rtimer_clock_t get_rx(void) { return rx_acc; }
void reset_rx(void) { rx_acc = 0; }
rtimer_clock_t get_tx(void) { return tx_acc; }
void reset_tx(void) { tx_acc = 0; }
static int
transmit(void)
{
  if (in_rx_mode) {
    rx_acc += RTIMER_NOW() - rx_start;
  }
  in_rx_mode = 0;
  in_tx_mode = 1;
  tx_start = RTIMER_NOW();
  CC2538_RF_CSP_ISTXON();
  if(!is_tx_active()) {
    PRINTF("cc2538-rf-async: TX was never active\n");
    CC2538_RF_CSP_ISFLUSHTX();
    return RADIO_TX_ERR;
  }

  return RADIO_TX_OK;
}
/*---------------------------------------------------------------------------*/
static int
read(void)
{
  if(!pending_packet()
      || !read_phy_header_and_set_datalen()
      || !read_payload(packetbuf_datalen())
      || !read_footer()) {
    flushrx();
    return 0;
  }
  flushrx();
  return 1;
}
/*---------------------------------------------------------------------------*/
static int
receiving_packet(void)
{
  return !is_tx_active()
      && (REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_SFD);
}
/*---------------------------------------------------------------------------*/
static int
pending_packet(void)
{
  return REG(RFCORE_XREG_FSMSTAT1) & RFCORE_XREG_FSMSTAT1_FIFOP;
}
/*---------------------------------------------------------------------------*/
static void
on(void)
{
  if(in_rx_mode) {
    PRINTF("cc2538-rf-async: already on\n");
    return;
  }

  rx_start = RTIMER_NOW();
  CC2538_RF_CSP_ISRXON();
  in_rx_mode = 1;
}
/*---------------------------------------------------------------------------*/
static void
off(void)
{
  if(!in_rx_mode && !in_tx_mode) {
    PRINTF("cc2538-rf-async: already off\n");
    return;
  }
  if (in_rx_mode) {
    rx_acc += RTIMER_NOW() - rx_start;
  }
  if (in_tx_mode) {
    tx_acc += RTIMER_NOW() - tx_start;
  }

  CC2538_RF_CSP_ISRFOFF();
  in_rx_mode = 0;
  in_tx_mode = 0;
}
/*---------------------------------------------------------------------------*/
static radio_result_t
get_value(radio_param_t param, radio_value_t *value)
{
  if(!value) {
    return RADIO_RESULT_INVALID_VALUE;
  }

  switch(param) {
  case RADIO_PARAM_IQ_LSBS:
    wait_for_rssi();
    *value = (radio_value_t)REG(RFCORE_XREG_RFRND);
    return RADIO_RESULT_OK;
  default:
    return RADIO_RESULT_NOT_SUPPORTED;
  }
}
/*---------------------------------------------------------------------------*/
static radio_result_t
set_value(radio_param_t param, radio_value_t value)
{
  switch(param) {
  case RADIO_PARAM_SHR_SEARCH:
    set_shr_search(value);
    return RADIO_RESULT_OK;
  case RADIO_PARAM_TX_MODE:
    if(value & RADIO_TX_MODE_SEND_ON_CCA) {
      return RADIO_RESULT_INVALID_VALUE;
    }
    set_loop(value & RADIO_TX_MODE_LOOP);
    return RADIO_RESULT_OK;
  default:
    return RADIO_RESULT_NOT_SUPPORTED;
  }
}
/*---------------------------------------------------------------------------*/
static radio_result_t
get_object(radio_param_t param, void *dest, size_t size)
{
  return RADIO_RESULT_NOT_SUPPORTED;
}
/*---------------------------------------------------------------------------*/
static radio_result_t
set_object(radio_param_t param, const void *src, size_t size)
{
  if(param == RADIO_PARAM_FIFOP_CALLBACK) {
    fifop_callback = (radio_fifop_callback_t) src;
    if(!size) {
      REG(RFCORE_XREG_RFIRQM0) &= ~RFCORE_XREG_RFIRQM0_FIFOP;
      return RADIO_RESULT_OK;
    }
    REG(RFCORE_XREG_FIFOPCTRL) = size;
    REG(RFCORE_XREG_RFIRQM0) |= RFCORE_XREG_RFIRQM0_FIFOP;
    return RADIO_RESULT_OK;
  } else if(param == RADIO_PARAM_SFD_CALLBACK) {
    sfd_callback = (radio_sfd_callback_t) src;
    if(sfd_callback) {
      REG(RFCORE_XREG_RFIRQM0) |= RFCORE_XREG_RFIRQM0_SFD;
    } else {
      REG(RFCORE_XREG_RFIRQM0) &= ~RFCORE_XREG_RFIRQM0_SFD;
    }
    return RADIO_RESULT_OK;
  } else if(param == RADIO_PARAM_TXDONE_CALLBACK) {
    txdone_callback = (radio_txdone_callback_t) src;
    return RADIO_RESULT_OK;
  }
  return RADIO_RESULT_NOT_SUPPORTED;
}
/*---------------------------------------------------------------------------*/
void
cc2538_rf_async_rxtx_isr(void)
{
  if(REG(RFCORE_SFR_RFIRQF0) & RFCORE_XREG_RFIRQM0_SFD) {
    REG(RFCORE_SFR_RFIRQF0) &= ~RFCORE_XREG_RFIRQM0_SFD;
    if(sfd_callback) {
      sfd_callback();
    }
  }
  if(REG(RFCORE_SFR_RFIRQF0) & RFCORE_XREG_RFIRQM0_FIFOP) {
    REG(RFCORE_SFR_RFIRQF0) &= ~RFCORE_XREG_RFIRQM0_FIFOP;
    if(fifop_callback) {
      fifop_callback();
    }
  }
  if(REG(RFCORE_SFR_RFIRQF1) & RFCORE_XREG_RFIRQM1_TXDONE) {
    REG(RFCORE_SFR_RFIRQF1) &= ~RFCORE_XREG_RFIRQM1_TXDONE;
    if(in_tx_mode) {
      in_tx_mode = 0;
      in_rx_mode = 1;
      tx_acc += RTIMER_NOW() - tx_start;
      rx_start = RTIMER_NOW();
    }
    if(txdone_callback) {
      txdone_callback();
    }
  }
}
/*---------------------------------------------------------------------------*/
void
cc2538_rf_async_error_isr(void)
{
  PRINTF("cc2538-rf-async: error 0x%08lx occurred\n", REG(RFCORE_SFR_RFERRF));
  REG(RFCORE_SFR_RFERRF) = 0;
}
/*---------------------------------------------------------------------------*/
const struct radio_async_driver cc2538_rf_async_driver = {
  init,
  prepare,
  transmit,
  read,
  receiving_packet,
  pending_packet,
  on,
  off,
  get_value,
  set_value,
  get_object,
  set_object,
  flushrx,
  read_phy_header,
  read_phy_header_and_set_datalen,
  read_raw,
  read_payload,
  remaining_payload_bytes,
  read_footer,
  get_rssi,
  reprepare
};
/*---------------------------------------------------------------------------*/

/** @} */
