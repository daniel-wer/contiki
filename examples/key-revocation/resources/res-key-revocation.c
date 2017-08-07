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

#include "contiki.h"

#ifdef KEY_REVOCATION_ENABLED

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

/*---------------------------------------------------------------------------*/
static void
res_get_handler(void *request,
    void *response,
    uint8_t *buffer,
    uint16_t preferred_size,
    int32_t *offset)
{
  unsigned int accept;
  const char *msg = "Supporting content-types text/plain and application/json";

  accept = -1;
  REST.get_header_accept(request, &accept);

#if AKES_NBR_WITH_GROUP_KEYS
  PRINTF("[KeyRev] Broadcast key:");
  int i;
  for(i = 0; i < AES_128_KEY_LENGTH; i++) {
    PRINTF("%x", adaptivesec_group_key[i]);
  }
  PRINTF("\n");
#endif /* AKES_NBR_WITH_GROUP_KEYS */

  if(accept == -1 || accept == REST.type.TEXT_PLAIN) {
    REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
    REST.set_response_payload(response, adaptivesec_group_key, AES_128_KEY_LENGTH);
  } else if(accept == REST.type.APPLICATION_JSON) {
    REST.set_header_content_type(response, REST.type.APPLICATION_JSON);
    int pos;
    char* buf_ptr = buffer;
    buf_ptr += snprintf(buf_ptr, REST_MAX_CHUNK_SIZE, "{'Key':'");
    // for(pos = 0; pos < MIN(AES_128_KEY_LENGTH, REST_MAX_CHUNK_SIZE); pos++) {
    //   buf_ptr += sprintf(buf_ptr, "%02X", adaptivesec_group_key[pos]);
    // }
    memcpy(buf_ptr, adaptivesec_group_key, AES_128_KEY_LENGTH);
    buf_ptr += AES_128_KEY_LENGTH;
    snprintf(buf_ptr, REST_MAX_CHUNK_SIZE - (buf_ptr - (char *)buffer), "'}");
    REST.set_response_payload(response, buffer, strlen((char *)buffer));
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
  PRINTF("[KeyRev]: Received POST to update group keys.\n");
  akes_update_group_key();
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