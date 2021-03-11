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

// @fixme
#ifndef QUIC_PLATFORM_LINUX
#define QUIC_PLATFORM_LINUX 1
#endif

#include <erl_nif.h>
#include <quic_platform.h>
#include <stdbool.h>

// for allocator tagging. @todo move to common header
#define QUICER_ACCEPTOR '00rQ'  // Qr00 - QUICER ACCEPTOR
#define QUICER_SND_BUFF '10rQ'  // Qr01 - QUICER SEND BUFFER
#define QUICER_OWNER_MON '20rQ' // Qr02 - QUICER OWNER MON
#define QUICER_CREDENTIAL_CONFIG_HELPER                                       \
  '30rQ'                       // QUICER_CREDENTIAL_CONFIG_HELPER
#define QUICER_OPT_BUFF '40rQ' // Qr02 - QUICER OPT

typedef struct ACCEPTOR
{
  QUIC_LIST_ENTRY Link;
  ErlNifPid Pid;
} ACCEPTOR;

typedef struct AcceptorsQueue
{
  QUIC_LIST_ENTRY List; // list of acceptors
  ErlNifMutex *Lock;
} QUICER_ACCEPTOR_QUEUE;

QUICER_ACCEPTOR_QUEUE *AcceptorQueueNew();
void AcceptorQueueDestroy(QUICER_ACCEPTOR_QUEUE *q);
void AcceptorsQueueInit(QUICER_ACCEPTOR_QUEUE *q);
void AcceptorEnqueue(QUICER_ACCEPTOR_QUEUE *q, ACCEPTOR *a);
ACCEPTOR *AcceptorDequeue(QUICER_ACCEPTOR_QUEUE *q);
ACCEPTOR *AcceptorAlloc();

//@todo add Acceptor cleanups.

#endif // __QUICER_QUEUE_H_
