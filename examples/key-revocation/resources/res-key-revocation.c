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

#define BASE_STATION_KEY { 0x00 , 0x01 , 0x02 , 0x03 , \
                           0x04 , 0x05 , 0x06 , 0x07 , \
                           0x08 , 0x09 , 0x0A , 0x0B , \
                           0x0C , 0x0D , 0x0E , 0x0F }

static uint8_t baseStationKey[AES_128_KEY_LENGTH] = BASE_STATION_KEY;

// Encrypted Key Revocation Response = "|encrypted response payload|CCM*-MIC|"
// Key Revocation Response Payload = "|response code|"
// 1-digit response code
#define RESPONSE_LEN 1
uint8_t message[RESPONSE_LEN + ADAPTIVESEC_UNICAST_MIC_LEN];

#define MAX_COUNTER_DIFF 5
#define ENCRYPTED_COMMUNICATION 1

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

#if KEY_REVOCATION_ENABLED
/*---------------------------------------------------------------------------*/
int charToInt(const uint8_t *p) {
    int x = 0;
    while (*p >= '0' && *p <= '9') {
        x = (x*10) + (*p - '0');
        ++p;
    }
    return x;
}
/*---------------------------------------------------------------------------*/
uint8_t *intToChar(int x, uint8_t* results) {
  if (x == 0) {
    results[0] = '0';
    return &results[1];
  }
  int i = (int) log10((double) x);
  int end = i;
  while(x > 0) {
    results[i] = (x % 10) + '0';
    x /= 10;
    i--;
  }
  return &results[end+1];
}
/*---------------------------------------------------------------------------*/
static void
res_get_handler(void *request,
    void *response,
    uint8_t *buffer,
    uint16_t preferred_size,
    int32_t *offset)
{
  unsigned int accept;
  const char *queryString;
  const char *msg = "Supporting content-types text/plain and application/json";

  accept = -1;
  REST.get_header_accept(request, &accept);
  int debugQueryLen = REST.get_query_variable(request, "debug", &queryString);

  PRINTF("[KeyRev]: Received GET request asking for this debug value: %.*s\n", debugQueryLen, queryString);

  // Print in hex
  // int pos;
  // for(pos = 0; pos < MIN(AES_128_KEY_LENGTH, REST_MAX_CHUNK_SIZE); pos++) {
  //   buf_ptr += sprintf(buf_ptr, "%02X", adaptivesec_group_key[pos]);
  // }

  if(accept == -1 || accept == REST.type.TEXT_PLAIN) {
    REST.set_header_content_type(response, REST.type.TEXT_PLAIN);

    if(strncmp(queryString, "broadcastKey", debugQueryLen) == 0) {
#if AKES_NBR_WITH_GROUP_KEYS
      REST.set_response_payload(response, adaptivesec_group_key, AES_128_KEY_LENGTH);
#endif /* AKES_NBR_WITH_GROUP_KEYS */
    } else if(strncmp(queryString, "neighborCount", debugQueryLen) == 0) {
      const uint8_t neighborCount = akes_nbr_count(AKES_NBR_PERMANENT) + akes_nbr_count(AKES_NBR_TENTATIVE);
      char neighborCountStr[4];
      int neighbor_count_str_len = sprintf(neighborCountStr, "%d", neighborCount);
      REST.set_response_payload(response, neighborCountStr, neighbor_count_str_len);
    } else {
      PRINTF("[KeyRev]: Unknown debug parameter.\n");
    }
  } else {
    PRINTF("[KeyRev]: Got request with unsupported Content-Type.\n");
    REST.set_response_status(response, REST.status.NOT_ACCEPTABLE);
    REST.set_response_payload(response, msg, strlen(msg));
  }
}
/*---------------------------------------------------------------------------*/
void aead(uint8_t *payload, uint8_t payload_len, uint8_t *nonce, uint8_t *mic, int forward)
{
  uint8_t a;
  uint8_t a_len;

  // Eventually the data the nonce is derived from, will be in a
  a_len = 0;

  AES_128_GET_LOCK();
  CCM_STAR.set_key(baseStationKey);
  CCM_STAR.aead(nonce,
      payload, payload_len,
      &a, a_len,
      mic, ADAPTIVESEC_UNICAST_MIC_LEN,
      forward);
  AES_128_RELEASE_LOCK();
}
/*---------------------------------------------------------------------------*/
int aead_verify(uint8_t *payload, uint8_t payload_len, uint8_t *nonce)
{
  uint8_t generated_mic[ADAPTIVESEC_UNICAST_MIC_LEN];
  aead(payload, MAX(payload_len - ADAPTIVESEC_UNICAST_MIC_LEN, 0), nonce, generated_mic, 0);

  return memcmp(generated_mic,
      payload + payload_len - ADAPTIVESEC_UNICAST_MIC_LEN,
      ADAPTIVESEC_UNICAST_MIC_LEN);
}
/*---------------------------------------------------------------------------*/
void prepare_response(void *response, int revocationStatus, unsigned int restStatus)
{
  message[0] = revocationStatus + '0';
#if ENCRYPTED_COMMUNICATION
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];
  memset(nonce, 255, CCM_STAR_NONCE_LENGTH);

  uint16_t mid = ((coap_packet_t *) response)->mid;
  int type = ((coap_packet_t *) response)->type;
  uint8_t *nonce_cur_ptr = intToChar(mid, nonce);
  intToChar(type, nonce_cur_ptr);

  // PRINTF("[KeyRev]: Nonce: ");
  // int j;
  // for(j = 0; j < CCM_STAR_NONCE_LENGTH; j++) {
  //   PRINTF("%02X", nonce[j]);
  // }
  // PRINTF("\n");

  aead(message, RESPONSE_LEN, nonce, message + RESPONSE_LEN, 1);
#endif /* ENCRYPTED_COMMUNICATION */

  REST.set_response_status(response, restStatus);
  REST.set_response_payload(response, message, RESPONSE_LEN + ADAPTIVESEC_UNICAST_MIC_LEN);
}
/*---------------------------------------------------------------------------*/
static void
res_post_handler(void *request,
    void *response,
    uint8_t *buffer,
    uint16_t preferred_size,
    int32_t *offset)
{
  // Encrypted Data Payload = "|encrypted key revocation payload|CCM*-MIC|"
  // Key Revocation Payload = "|node id| |new shared secret|"

  uint8_t payload[REST_MAX_CHUNK_SIZE];
  const uint8_t *temp_ptr;
  int payloadLen = REST.get_request_payload(request, &temp_ptr);
  memcpy(payload, temp_ptr, payloadLen);

#if ENCRYPTED_COMMUNICATION
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];
  memset(nonce, 255, CCM_STAR_NONCE_LENGTH);

  // Build nonce from coap message id and message type
  uint16_t mid = ((coap_packet_t *) request)->mid;
  int type = ((coap_packet_t *) request)->type;
  uint8_t *nonce_cur_ptr = intToChar(mid, nonce);
  intToChar(type, nonce_cur_ptr);

  if (aead_verify(payload, payloadLen, nonce)) {
    PRINTF("[KeyRev]: Wrong MIC for revocation message.\n");
    prepare_response(response, ERROR_INCORRECT_FORMAT, REST.status.BAD_REQUEST);
    return;
  };
  // Subtract the length of the MIC
  payloadLen -= ADAPTIVESEC_UNICAST_MIC_LEN;
#endif /* ENCRYPTED_COMMUNICATION */

  int parsedChars = 0;
  uint8_t *secretPtr = NULL;
  uint8_t curChar;
  while (parsedChars < payloadLen) {
    curChar = *(payload + parsedChars);
    if ((char) curChar == ' ') {
      if (secretPtr == NULL) {
        secretPtr = payload + parsedChars + 1;
        break;
      }
    }
    parsedChars++;
  }

  if (secretPtr == NULL) {
    PRINTF("[KeyRev]: Incorrect format of revocation message.\n");
    prepare_response(response, ERROR_INCORRECT_FORMAT, REST.status.BAD_REQUEST);
    return;
  }

  // TODO persist and restore counter
  uint16_t savedMid = 1337;
  uint16_t curMid = ((coap_packet_t *) request)->mid;
  PRINTF("[KeyRev]: Message id is %d\n", curMid);
  PRINTF("[KeyRev]: Saved message id is %d\n", savedMid);

  if (ABS(curMid - savedMid) > MAX_COUNTER_DIFF) {
    PRINTF("[KeyRev]: Timestamp that was sent is not fresh.\n");
    prepare_response(response, ERROR_INCORRECT_FORMAT, REST.status.BAD_REQUEST);
    return;
  }

  int nodeIdLen = (secretPtr - payload - 1);
  if (nodeIdLen != LINKADDR_SIZE) {
    PRINTF("[KeyRev]: Node id to revoke has incorrect length, expected %d but was %d.\n", LINKADDR_SIZE, nodeIdLen);
    prepare_response(response, ERROR_INCORRECT_FORMAT, REST.status.BAD_REQUEST);
    return;
  }

  linkaddr_t node_addr;
  memcpy(node_addr.u8, payload, LINKADDR_SIZE);

  PRINTF("[KeyRev]: Received POST revoking node with id: ");
  int i;
  for(i = 0; i < LINKADDR_SIZE; i++) {
    PRINTF("%02X", node_addr.u8[i]);
  }
  PRINTF("\n");

  int secretLen = payloadLen - (secretPtr - payload);
  PRINTF("[KeyRev]: Length of new shared secret is %d\n", secretLen);

  AKES_SCHEME.update_secret_with_sender(&node_addr, secretPtr, secretLen);

  int status = akes_revoke_node(&node_addr);
  prepare_response(response, status, REST.status.OK);
}
/*---------------------------------------------------------------------------*/
RESOURCE(res_key_revocation,
    "title=\"Key\"",
    res_get_handler,
    res_post_handler,
    NULL,
    NULL);
/*---------------------------------------------------------------------------*/
#endif /* KEY_REVOCATION_ENABLED */