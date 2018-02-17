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
 *         Updates group key and re-distributes it to all neighbors
 * \author
 *         Daniel Werner <daniel.werner@student.hpi.de>
 */

#include "net/llsec/adaptivesec/adaptivesec.h"
#include "net/llsec/adaptivesec/akes-update.h"
#include "net/llsec/adaptivesec/akes.h"
#include "net/llsec/adaptivesec/nrl.h"
#include "net/rpl/rpl.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

#if KEY_REVOCATION_ENABLED
#if AKES_NBR_WITH_GROUP_KEYS
void
akes_print_group_key(void)
{
  PRINTF("key-rev: Broadcast key:");
  int i;
  for(i = 0; i < AES_128_KEY_LENGTH; i++) {
    PRINTF("%x", adaptivesec_group_key[i]);
  }
  PRINTF("\n");
}
/*---------------------------------------------------------------------------*/
void
akes_update_group_key(void)
{
  struct akes_nbr_entry *next;

  akes_print_group_key();

  adaptivesec_group_key_init();
  PRINTF("key-rev: Renew broadcast key\n");
  
  akes_print_group_key();

  PRINTF("key-rev: Number of permanent neighbors is %d\n", akes_nbr_count(AKES_NBR_PERMANENT));
  PRINTF("key-rev: Number of tentative neighbors is %d\n", akes_nbr_count(AKES_NBR_TENTATIVE));
  next = akes_nbr_head();
  while(next) {
    if(!next->permanent) {
      next = akes_nbr_next(next);
      continue;
    }

    /* Send UPDATE */
    akes_send_update(next);
    PRINTF("key-rev: Sent UPDATE\n");
    next = akes_nbr_next(next);
  }
}
#endif /* AKES_NBR_WITH_GROUP_KEYS */
/*---------------------------------------------------------------------------*/
int
akes_revoke_node(const linkaddr_t *addr, int add_to_nrl)
{
  if (add_to_nrl) {
    PRINTF("key-rev: Shared secret was not updated. Add node id to Node Revocation List.\n");
    if (nrl_revoke(addr) < 0) {
      return ERROR_NRL_FULL;
    }
  }

  struct akes_nbr_entry *entry;
  entry = akes_nbr_get_entry(addr);

  if(entry) {
    /* Remove compromised node from AKES neighbor table */
    enum akes_nbr_status status;
    if (entry->tentative) {
      status = AKES_NBR_TENTATIVE;
    } else if(entry->permanent) {
      status = AKES_NBR_PERMANENT;
    } else {
      PRINTF("key-rev: Neighbor is neither tentative nor permanent. This should never happen!\n");
      return ERROR;
    }
    akes_nbr_delete(entry, status);

    /* Possibly remove compromised node from rpl_parents table */
    rpl_dag_t *dag = rpl_get_any_dag();
    rpl_parent_t *p;
    rpl_parent_t *any_parent;
    p = nbr_table_head(rpl_parents);
    while(p != NULL) {
      const linkaddr_t *lladdr = rpl_get_parent_lladdr(p);
      if(dag == p->dag && linkaddr_cmp(lladdr, addr) != 0) {
        int is_preferred_parent = p == dag->preferred_parent;
        rpl_remove_parent(p);
        if (is_preferred_parent) {
          /* If the deleted parent was the preferred parent, trigger the selection of a new preferred parent ...*/
          any_parent = nbr_table_head(rpl_parents);
          rpl_select_dag(dag->instance, any_parent);
          /* ... and send a DAO to the border router to inform it of the route change*/
          dao_output(dag->preferred_parent, dag->instance->default_lifetime);
        }
        break;
      }
      p = nbr_table_next(rpl_parents, p);
    }
  } else {
    PRINTF("key-rev: Node that should be revoked is not a neighbor.\n");
    return SUCCESS;
  }

#if AKES_NBR_WITH_GROUP_KEYS
  PRINTF("key-rev: Update group session key as a neighbor node was compromised.\n");
  akes_update_group_key();
  PRINTF("key-rev: Group session key update completed.\n");

#else
  PRINTF("key-rev: AKES_NBR_WITH_GROUP_KEYS is not defined, so there is no need to update the group session key.\n");
#endif /* AKES_NBR_WITH_GROUP_KEYS */

  return SUCCESS;
}
/*---------------------------------------------------------------------------*/
#endif /* KEY_REVOCATION_ENABLED */