/*--------------------------------------------------------------------
Copyright (c) 2021 EMQ Technologies Co., Ltd. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-------------------------------------------------------------------*/

#ifndef __QUICER_QUEUE_H_
#define __QUICER_QUEUE_H_

#include "quicer_internal.h"
#include <erl_nif.h>
#include <msquic.h>
#include <quic_platform.h>
#include <stdbool.h>

// for allocator tagging. @todo move to common header
#define QUICER_ACCEPTOR '00rQ'          // Qr00 - QUICER ACCEPTOR
#define QUICER_SND_BUFF '10rQ'          // Qr01 - QUICER SEND BUFFER
#define QUICER_OWNER_MON '20rQ'         // Qr02 - QUICER OWNER MON
#define QUICER_CREDENTIAL_CONFIG '30rQ' // Qr03 QUICER_CREDENTIAL_CONFIG_HELPER
#define QUICER_OPT_BUFF '40rQ'          // Qr04 - QUICER OPT
#define QUICER_SETTINGS '50rQ'          // Qr05 - QUICER CONNECTION SETTINGS
#define QUICER_TLS_SECRETS                                                    \
  '60rQ'                       // Qr06 - QUICER TLS SECRETS for SSLKeyLogFile
#define QUICER_TRACE '70rQ'    // Qr07 - QUICER TRACE, unimportant
#define QUICER_SEND_CTX '80rQ' // Qr08 - QUICER STREAM SEND CONTEXT
#define QUICER_DGRAM_SEND_CTX '90rQ'   // Qr09 - QUICER DGRAM SEND CONTEXT
#define QUICER_CERTIFICATE_FILE 'A0rQ' // Qr0a QUICER_CERTIFICATE_FILE
#define QUICER_CERTIFICATE_FILE_PROTECTED                                     \
  'B0rQ' // 'Qr0b'  QUICER_CERTIFICATE_FILE_PROTECTED
#define QUICER_RESUME_TICKET 'C0rQ' // 'Qr0c'  QUICER_RESUME_TICKET
#define QUICER_CACERTFILE 'D0rQ'    // 'Qr0d'  QUICER_CACERTFILE

typedef enum ACCEPTOR_RECV_MODE
{
  ACCEPTOR_RECV_MODE_PASSIVE,
  ACCEPTOR_RECV_MODE_ACTIVE,
  ACCEPTOR_RECV_MODE_ONCE,
  ACCEPTOR_RECV_MODE_MULTI
} ACCEPTOR_RECV_MODE;

typedef struct ACCEPTOR
{
  CXPLAT_LIST_ENTRY Link;
  ErlNifPid Pid;
  ACCEPTOR_RECV_MODE active;
  uint16_t active_count; /* counter for active_n */
  QUIC_SETTINGS Settings;
  void *reserved1;
  void *reserved2;
  void *reserved3;
} ACCEPTOR;

typedef struct AcceptorsQueue
{
  CXPLAT_LIST_ENTRY List; // list of acceptors
  ErlNifMutex *Lock;
} QUICER_ACCEPTOR_QUEUE;

QUICER_ACCEPTOR_QUEUE *AcceptorQueueNew();
void AcceptorQueueDestroy(QUICER_ACCEPTOR_QUEUE *q);
void AcceptorsQueueInit(QUICER_ACCEPTOR_QUEUE *q);
void AcceptorEnqueue(QUICER_ACCEPTOR_QUEUE *q, ACCEPTOR *a);
ACCEPTOR *AcceptorDequeue(QUICER_ACCEPTOR_QUEUE *q);
ACCEPTOR *AcceptorAlloc();
void AcceptorDestroy(ACCEPTOR *acc);

bool set_owner_recv_mode(ACCEPTOR *owner, ErlNifEnv *env, ERL_NIF_TERM active);

#endif // __QUICER_QUEUE_H_
