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
 *      Key revocation resource.
 * \author
 *      Daniel Werner <daniel.werner@student.hpi.de>
 */

#include <string.h>
#include <math.h>
#include "rest-engine.h"
#include "er-coap.h"
#include "lib/aes-128.h"
#include "net/llsec/adaptivesec/akes.h"
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/llsec/adaptivesec/akes-update.h"

#if KEY_REVOCATION_ENABLED

#define BASE_STATION_KEY { 0x00 , 0x01 , 0x02 , 0x03 , \
                           0x04 , 0x05 , 0x06 , 0x07 , \
                           0x08 , 0x09 , 0x0A , 0x0B , \
                           0x0C , 0x0D , 0x0E , 0x0F }

static uint8_t base_station_key[AES_128_KEY_LENGTH] = BASE_STATION_KEY;

/* 1-digit response code */
#define RESPONSE_LEN 1
uint8_t message[RESPONSE_LEN + ADAPTIVESEC_UNICAST_MIC_LEN];

// TODO persist and restore mid across and after reboots
uint16_t saved_mid = 1337;

#define ENCRYPTED_COMMUNICATION 1

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

/*---------------------------------------------------------------------------*/
uint8_t *
int_to_char(int x, uint8_t* results) {
  if (x == 0) {
    results[0] = '0';
    return &results[1];
  }
  /* Avoid log10() which is not present */
  int num_digits = 0;
  int temp;
  for(temp = x; temp > 0;)
  {
      temp /= 10;
      num_digits++;
  }
  num_digits--;
  int end = num_digits;
  while(x > 0) {
    results[num_digits] = (x % 10) + '0';
    x /= 10;
    num_digits--;
  }
  return &results[end+1];
}
/*---------------------------------------------------------------------------*/
void
aead(uint8_t *payload, uint8_t payload_len, uint8_t *nonce, uint8_t *mic, int forward)
{
  uint8_t a;
  uint8_t a_len;

  /* TODO authenticate the whole CoAP header */
  a_len = 0;

  AES_128_GET_LOCK();
  CCM_STAR.set_key(base_station_key);
  CCM_STAR.aead(nonce,
      payload, payload_len,
      &a, a_len,
      mic, ADAPTIVESEC_UNICAST_MIC_LEN,
      forward);
  AES_128_RELEASE_LOCK();
}
/*---------------------------------------------------------------------------*/
int
aead_verify(uint8_t *payload, uint8_t payload_len, uint8_t *nonce)
{
  uint8_t generated_mic[ADAPTIVESEC_UNICAST_MIC_LEN];
  aead(payload, MAX(payload_len - ADAPTIVESEC_UNICAST_MIC_LEN, 0), nonce, generated_mic, 0);

  return memcmp(generated_mic,
      payload + payload_len - ADAPTIVESEC_UNICAST_MIC_LEN,
      ADAPTIVESEC_UNICAST_MIC_LEN);
}
/*---------------------------------------------------------------------------*/
void
prepare_response(void *response, int revocation_status, unsigned int rest_status)
{
  message[0] = revocation_status + '0';
  int message_len = RESPONSE_LEN;
#if ENCRYPTED_COMMUNICATION
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];
  memset(nonce, 255, CCM_STAR_NONCE_LENGTH);

  uint16_t mid = ((coap_packet_t *) response)->mid;
  int type = ((coap_packet_t *) response)->type;
  uint8_t *nonce_cur_ptr = int_to_char(mid, nonce);
  int_to_char(type, nonce_cur_ptr);

  aead(message, RESPONSE_LEN, nonce, message + RESPONSE_LEN, 1);
  message_len += ADAPTIVESEC_UNICAST_MIC_LEN;
#endif /* ENCRYPTED_COMMUNICATION */

  REST.set_response_status(response, rest_status);
  REST.set_response_payload(response, message, message_len);
}
/*---------------------------------------------------------------------------*/
static void
res_post_handler(void *request,
    void *response,
    uint8_t *buffer,
    uint16_t preferred_size,
    int32_t *offset)
{
  uint8_t payload[REST_MAX_CHUNK_SIZE];
  const uint8_t *temp_ptr;
  int payload_len = REST.get_request_payload(request, &temp_ptr);
  memcpy(payload, temp_ptr, payload_len);

#if ENCRYPTED_COMMUNICATION
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];
  memset(nonce, 255, CCM_STAR_NONCE_LENGTH);

  /* Build nonce from coap message id and message type */
  uint16_t mid = ((coap_packet_t *) request)->mid;
  int type = ((coap_packet_t *) request)->type;
  uint8_t *nonce_cur_ptr = int_to_char(mid, nonce);
  int_to_char(type, nonce_cur_ptr);

  if (aead_verify(payload, payload_len, nonce)) {
    PRINTF("key-rev: Wrong MIC for revocation message.\n");
#if DEBUG
    /* TODO Do not send a response to avoid energy depletion attacks.
    Currently there is no way to send no response in er-coap! */
    prepare_response(response, ERROR_INCORRECT_FORMAT, REST.status.BAD_REQUEST);
#endif /* DEBUG */
    return;
  };
  /* Subtract the length of the MIC */
  payload_len -= ADAPTIVESEC_UNICAST_MIC_LEN;
#endif /* ENCRYPTED_COMMUNICATION */

  uint16_t cur_mid = ((coap_packet_t *) request)->mid;
  PRINTF("key-rev: Message ID is %d\n", cur_mid);
  PRINTF("key-rev: Saved Message ID is %d\n", saved_mid);

  if (cur_mid <= saved_mid) {
    PRINTF("key-rev: Message ID that was sent is not fresh.\n");
#if DEBUG
    /* TODO Do not send a response to avoid energy depletion attacks.
    Currently there is no way to send no response in er-coap! */
    prepare_response(response, ERROR_INCORRECT_FORMAT, REST.status.BAD_REQUEST);
#endif /* DEBUG */
    return;
  }

  saved_mid = cur_mid;

  if (payload_len < LINKADDR_SIZE) {
    PRINTF("key-rev: Node id to revoke has incorrect length, expected %d but was %d.\n", LINKADDR_SIZE, payload_len);
    prepare_response(response, ERROR_INCORRECT_FORMAT, REST.status.BAD_REQUEST);
    return;
  }

  linkaddr_t node_addr;
  memcpy(node_addr.u8, payload, LINKADDR_SIZE);

  PRINTF("key-rev: Received POST revoking node with id: ");
  int i;
  for(i = 0; i < LINKADDR_SIZE; i++) {
    PRINTF("%02X", node_addr.u8[i]);
  }
  PRINTF("\n");

  int secret_len = payload_len - LINKADDR_SIZE;
  PRINTF("key-rev: Length of new shared secret is %d\n", secret_len);

  int add_to_nrl = 1;
  if (secret_len > 0) {
    uint8_t *secret_ptr = payload + LINKADDR_SIZE;
    add_to_nrl &= AKES_SCHEME.update_secret_with_sender(&node_addr, secret_ptr, secret_len);
  }

  int status = akes_revoke_node(&node_addr, add_to_nrl);
  prepare_response(response, status, REST.status.OK);
}
/*---------------------------------------------------------------------------*/
RESOURCE(res_key_revocation,
    "title=\"Key\"",
    NULL,
    res_post_handler,
    NULL,
    NULL);
/*---------------------------------------------------------------------------*/
#endif /* KEY_REVOCATION_ENABLED */