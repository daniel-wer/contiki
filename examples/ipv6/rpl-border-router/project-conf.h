/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
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
 */

#ifndef PROJECT_ROUTER_CONF_H_
#define PROJECT_ROUTER_CONF_H_

#ifndef WITH_NON_STORING
#define WITH_NON_STORING 0 /* Set this to run with non-storing mode */
#endif /* WITH_NON_STORING */

#if WITH_NON_STORING
#undef RPL_NS_CONF_LINK_NUM
#define RPL_NS_CONF_LINK_NUM 40 /* Number of links maintained at the root */
#undef UIP_CONF_MAX_ROUTES
#define UIP_CONF_MAX_ROUTES 0 /* No need for routes */
#undef RPL_CONF_MOP
#define RPL_CONF_MOP RPL_MOP_NON_STORING /* Mode of operation*/
#endif /* WITH_NON_STORING */

#ifndef UIP_FALLBACK_INTERFACE
#define UIP_FALLBACK_INTERFACE rpl_interface
#endif

#ifndef QUEUEBUF_CONF_NUM
#define QUEUEBUF_CONF_NUM          4
#endif

#ifndef UIP_CONF_BUFFER_SIZE
#define UIP_CONF_BUFFER_SIZE    140
#endif

#ifndef UIP_CONF_RECEIVE_WINDOW
#define UIP_CONF_RECEIVE_WINDOW  60
#endif

#ifndef WEBSERVER_CONF_CFS_CONNS
#define WEBSERVER_CONF_CFS_CONNS 2
#endif

/* SLIP does not work otherwise */
#undef LPM_CONF_MAX_PM
#define LPM_CONF_MAX_PM 0

#if 0
/* enable the software implementation of AES-128 */
#undef AES_128_CONF
#define AES_128_CONF aes_128_driver
#endif

/* configure RDC layer */
#if 1
#include "cpu/cc2538/dev/cc2538-rf-async-autoconf.h"
#include "net/mac/contikimac/secrdc-autoconf.h"
#elif 0
#undef CONTIKIMAC_CONF_COMPOWER
#define CONTIKIMAC_CONF_COMPOWER 0
#undef RDC_CONF_HARDWARE_CSMA
#define RDC_CONF_HARDWARE_CSMA 1
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC contikimac_driver
#else
#undef NETSTACK_CONF_RDC
#define NETSTACK_CONF_RDC nullrdc_driver
#endif

/* configure MAC layer */
#if 1
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC csma_driver
#undef CSMA_CONF_MAX_FRAME_RETRIES
#define CSMA_CONF_MAX_FRAME_RETRIES 3
#undef CSMA_CONF_MAX_NEIGHBOR_QUEUES
#define CSMA_CONF_MAX_NEIGHBOR_QUEUES 5
#else
#undef NETSTACK_CONF_MAC
#define NETSTACK_CONF_MAC nullmac_driver
#endif

/* configure LLSEC layer */
#if 1
#undef ADAPTIVESEC_CONF_UNICAST_SEC_LVL
#define ADAPTIVESEC_CONF_UNICAST_SEC_LVL 2
#undef ADAPTIVESEC_CONF_BROADCAST_SEC_LVL
#define ADAPTIVESEC_CONF_BROADCAST_SEC_LVL 2
#undef LLSEC802154_CONF_USES_AUX_HEADER
#define LLSEC802154_CONF_USES_AUX_HEADER 0
#undef NBR_TABLE_CONF_MAX_NEIGHBORS
#define NBR_TABLE_CONF_MAX_NEIGHBORS 14
#if 0
#include "net/llsec/adaptivesec/coresec-autoconf.h"
#else
#include "net/llsec/adaptivesec/noncoresec-autoconf.h"
#endif
#if 1
#include "net/llsec/adaptivesec/potr-autoconf.h"
#if 1
#include "net/mac/contikimac/ilos-autoconf.h"
#endif
#endif
#endif

/* configure FRAMERs */
#include "net/mac/contikimac/framer-autoconf.h"

/* set a seeder */
#undef CSPRNG_CONF_SEEDER
#define CSPRNG_CONF_SEEDER iq_seeder

/* disable TCP and UDP */
#undef UIP_CONF_TCP
#define UIP_CONF_TCP 0
#undef UIP_CONF_UDP
#define UIP_CONF_UDP 0

#endif /* PROJECT_ROUTER_CONF_H_ */
