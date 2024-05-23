/*--------------------------------------------------------------------
Copyright (c) 2024 EMQ Technologies Co., Ltd. All Rights Reserved.

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
#ifndef QUICER_OWNER_QUEUE_H_
#define QUICER_OWNER_QUEUE_H_

#include <erl_nif.h>

// clang-format off
#include <quicer_internal.h>
#include <msquic.h>
#include <quic_platform.h>
// clang-format on

#define QUICER_OWNER_SIGNAL 'E0rQ' // 'Er0d'  QUICER_OWNER_SIGNAL

// Owner Signal Queue
typedef struct OWNER_SIGNAL_QUEUE
{
  ErlNifEnv *env;
  CXPLAT_LIST_ENTRY List;
} OWNER_SIGNAL_QUEUE;

typedef struct OWNER_SIGNAL
{
  CXPLAT_LIST_ENTRY Link;
  ERL_NIF_TERM msg;        // resides in `env` of OWNER_SIGNAL_QUEUE
  ERL_NIF_TERM orig_owner; // owner when msg is generated
} OWNER_SIGNAL;

OWNER_SIGNAL_QUEUE *OwnerSignalQueueNew();
OWNER_SIGNAL *OwnerSignalAlloc();
void OwnerSignalQueueInit(OWNER_SIGNAL_QUEUE *queue);
void OwnerSignalQueueDestroy(OWNER_SIGNAL_QUEUE *queue);
void OwnerSignalFree(OWNER_SIGNAL *sig);
void OwnerSignalEnqueue(_In_ OWNER_SIGNAL_QUEUE *queue,
                        _In_ OWNER_SIGNAL *sig);
OWNER_SIGNAL *OwnerSignalDequeue(_In_ OWNER_SIGNAL_QUEUE *queue);

#endif // QUICER_OWNER_QUEUE_H_
