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
 *         Persisted Node Revocation List (NRL).
 * \author
 *         Daniel Werner <daniel.werner@student.hpi.de>
 */

#include <stdint.h>
#include "cfs/cfs.h"
#include "net/llsec/adaptivesec/nrl.h"

#ifdef REVOCATION_LIST_LENGTH_CONF
#define REVOCATION_LIST_LENGTH REVOCATION_LIST_LENGTH_CONF
#else /* REVOCATION_LIST_LENGTH_CONF */
#define REVOCATION_LIST_LENGTH 50
#endif /* REVOCATION_LIST_LENGTH_CONF */

#ifdef PERSIST_REVOCATION_LIST_CONF
#define PERSIST_REVOCATION_LIST PERSIST_REVOCATION_LIST_CONF
#else /* PERSIST_REVOCATION_LIST_CONF */
#define PERSIST_REVOCATION_LIST 1
#endif /* PERSIST_REVOCATION_LIST_CONF */

#define FILENAME "node_revocation_list"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

#if KEY_REVOCATION_ENABLED
static linkaddr_t nrl[REVOCATION_LIST_LENGTH];
static uint16_t nrl_length = 0;


int
nrl_is_revoked(const linkaddr_t *addr)
{
  int i;
  for(i = 0; i < nrl_length; i++) {
    if(memcmp(&nrl[i], addr, LINKADDR_SIZE) == 0) {
      return 1;
    }
  }
  return 0;
}

int
nrl_revoke(const linkaddr_t *addr)
{
  if(nrl_length < REVOCATION_LIST_LENGTH) {
    memcpy(&nrl[nrl_length], addr, LINKADDR_SIZE);
#if PERSIST_REVOCATION_LIST
    int fd, bytes_written;

    fd = cfs_open(FILENAME, CFS_WRITE | CFS_APPEND);
    if(fd < 0) {
      PRINTF("nrl: Failed to open file %s\n", FILENAME);
      return -1;
    }

    const char new_line = '\n';
    bytes_written = cfs_write(fd, addr, LINKADDR_SIZE);
    bytes_written += cfs_write(fd, &new_line, 1);
    if(bytes_written < LINKADDR_SIZE + 1) {
      PRINTF("nrl: Failed to write to file %s\n", FILENAME);
      cfs_close(fd);
      return -1;
    }

    cfs_close(fd);
#endif /* PERSIST_REVOCATION_LIST */
    return ++nrl_length;
  } else {
    PRINTF("nrl: NRL contains %d entries and is full.\n", nrl_length);
    return -1;
  }
}

void
nrl_clear(void)
{
  nrl_length = 0;
#if PERSIST_REVOCATION_LIST
  cfs_remove(FILENAME);
#endif /* PERSIST_REVOCATION_LIST */
}

void
nrl_init(void)
{
#if PERSIST_REVOCATION_LIST
  int fd, bytes_read;

  fd = cfs_open(FILENAME, CFS_READ | CFS_WRITE);
  if(fd < 0) {
    PRINTF("nrl: Failed to open file %s\n", FILENAME);
    return;
  }

  while(nrl_length < REVOCATION_LIST_LENGTH) {
    bytes_read = cfs_read(fd, &nrl[nrl_length], LINKADDR_SIZE);
    if(bytes_read < LINKADDR_SIZE) {
      break;
    } else {
      nrl_length++;
      /* Seek to next line */
      cfs_seek(fd, 1, CFS_SEEK_CUR);
    }
  }
  PRINTF("nrl: Read %d entries from the persisted NRL.\n", nrl_length);

  cfs_close(fd);

#endif /* PERSIST_REVOCATION_LIST */
}
#endif /* KEY_REVOCATION_ENABLED */