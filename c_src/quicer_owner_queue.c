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
#include "quicer_owner_queue.h"

OWNER_SIGNAL_QUEUE *
OwnerSignalQueueNew()
{
  OWNER_SIGNAL_QUEUE *sig
      = CxPlatAlloc(sizeof(OWNER_SIGNAL_QUEUE), QUICER_OWNER_SIGNAL);
  return sig;
}

void
OwnerSignalQueueInit(OWNER_SIGNAL_QUEUE *queue)
{
  queue->env = enif_alloc_env();
  CxPlatListInitializeHead(&queue->List);
}

void
OwnerSignalQueueDestroy(OWNER_SIGNAL_QUEUE *queue)
{
  CXPLAT_DBG_ASSERT(CxPlatListIsEmpty(&queue->List));
  enif_free_env(queue->env);
  CxPlatFree(queue, QUICER_OWNER_SIGNAL);
}

OWNER_SIGNAL *
OwnerSignalAlloc()
{
  OWNER_SIGNAL *sig = CxPlatAlloc(sizeof(OWNER_SIGNAL), QUICER_OWNER_SIGNAL);
  return sig;
}

void
OwnerSignalFree(OWNER_SIGNAL *sig)
{
  CXPLAT_FREE(sig, QUICER_OWNER_SIGNAL);
}

void
OwnerSignalEnqueue(_In_ OWNER_SIGNAL_QUEUE *queue, _In_ OWNER_SIGNAL *sig)
{
  CxPlatListInsertTail(&queue->List, &sig->Link);
}

OWNER_SIGNAL *
OwnerSignalDequeue(_In_ OWNER_SIGNAL_QUEUE *queue)
{
  OWNER_SIGNAL *sig;
  if (CxPlatListIsEmpty(&queue->List))
    {
      sig = NULL;
    }
  else
    {
      sig = CXPLAT_CONTAINING_RECORD(
          CxPlatListRemoveHead(&queue->List), OWNER_SIGNAL, Link);
    }

  return sig;
}
