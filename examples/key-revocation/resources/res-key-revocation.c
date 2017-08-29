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
#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/llsec/adaptivesec/akes-update.h"

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

#if KEY_REVOCATION_ENABLED
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
      sprintf(neighborCountStr, "%d", neighborCount);
      REST.set_response_payload(response, neighborCountStr, 4);
    } else {
      PRINTF("[KeyRev]: Unknown debug parameter.");
    }
  } else {
    REST.set_response_status(response, REST.status.NOT_ACCEPTABLE);
    REST.set_response_payload(response, msg, strlen(msg));
  }
}
/*---------------------------------------------------------------------------*/
static void
res_post_handler(void *request,
    void *response,
    uint8_t *buffer,
    uint16_t preferred_size,
    int32_t *offset)
{
  const char *revokedNodeIdString;
  int revokedNodeIdLen = REST.get_post_variable(request, "node", &revokedNodeIdString);
  if(revokedNodeIdLen > 0) {
    if(revokedNodeIdLen != LINKADDR_SIZE) {
      PRINTF("[KeyRev]: Node id to revoke has incorrect length, expected %d but was %d.\n", LINKADDR_SIZE, revokedNodeIdLen);
      return;
    }
    uint8_t nodeId[LINKADDR_SIZE];
    memcpy(nodeId, revokedNodeIdString, LINKADDR_SIZE);

    PRINTF("[KeyRev]: Received POST revoking node with id: ");
    int i;
    for(i = 0; i < LINKADDR_SIZE; i++) {
      PRINTF("%02X", nodeId[i]);
    }
    PRINTF("\n");

    akes_revoke_node(nodeId);
  }

#if AKES_NBR_WITH_GROUP_KEYS
  PRINTF("[KeyRev]: Received POST to update group keys.\n");
  akes_update_group_key();

#else
  PRINTF("[KeyRev]: Received POST to update group keys, but AKES_NBR_WITH_GROUP_KEYS is not defined.\n");
#endif /* AKES_NBR_WITH_GROUP_KEYS is not defined */
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