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
 *         Header file for the asynchronous radio API
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef RADIO_ASYNC_H_
#define RADIO_ASYNC_H_

#include "contiki.h"
#include "dev/radio.h"

struct radio_async_driver {
  void (* init)(void);
  int (* prepare)(const void *payload, unsigned short payload_len);
  int (* transmit)(void);
  int (* read)(void);
  int (* receiving_packet)(void);
  int (* pending_packet)(void);
  void (* on)(void);
  void (* off)(void);
  radio_result_t (* get_value)(radio_param_t param, radio_value_t *value);
  radio_result_t (* set_value)(radio_param_t param, radio_value_t value);
  radio_result_t (* get_object)(radio_param_t param, void *dest, size_t size);
  radio_result_t (* set_object)(radio_param_t param, const void *src, size_t size);
  void (* flushrx)(void);
  uint8_t (* read_phy_header)(void);
  uint8_t (* read_phy_header_and_set_datalen)(void);
  void (* read_raw)(uint8_t *buf, uint8_t bytes);
  int (* read_payload)(uint8_t bytes);
  uint8_t (* remaining_payload_bytes)(void);
  int (* read_footer)(void);
  int8_t (* get_rssi)(void);
  void (* reprepare)(uint8_t offset, uint8_t *src, uint8_t len);
};

#endif /* RADIO_ASYNC_H_ */
