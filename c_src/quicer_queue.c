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

#include "quicer_queue.h"

static QUICER_ACCEPTOR_QUEUE *AcceptorQueueAlloc();

//@todo add assertions
void
AcceptorQueueInit(QUICER_ACCEPTOR_QUEUE *q)
{
  q->Lock = enif_mutex_create("quicer:acceptQ");
  enif_mutex_lock(q->Lock);
  CxPlatListInitializeHead(&q->List);
  enif_mutex_unlock(q->Lock);
}

QUICER_ACCEPTOR_QUEUE *
AcceptorQueueNew()
{
  QUICER_ACCEPTOR_QUEUE *q = AcceptorQueueAlloc();
  if (!q)
    {
      return NULL;
    }
  AcceptorQueueInit(q);
  return q;
}

// remember to hold ctx lock
void
AcceptorQueueDestroy(QUICER_ACCEPTOR_QUEUE *q)
{
  enif_mutex_lock(q->Lock);
  while (!CxPlatListIsEmpty(&q->List))
    {
      CxPlatListRemoveHead(&q->List);
    }
  enif_mutex_unlock(q->Lock);
  free(q);
}

//@todo add assertions
void
AcceptorEnqueue(QUICER_ACCEPTOR_QUEUE *q, ACCEPTOR *a)
{
  // @todo try lock less
  enif_mutex_lock(q->Lock);
  CxPlatListInsertTail(&q->List, &a->Link);
  enif_mutex_unlock(q->Lock);
}

//@todo add assertions
ACCEPTOR *
AcceptorDequeue(QUICER_ACCEPTOR_QUEUE *q)
{
  ACCEPTOR *acceptor = NULL;
  enif_mutex_lock(q->Lock);
  if (!CxPlatListIsEmpty(&q->List))
    {
      acceptor = CXPLAT_CONTAINING_RECORD(
          CxPlatListRemoveHead(&q->List), ACCEPTOR, Link);
    }
  else
    {
      //@todo add tracepoint
      acceptor = NULL;
    }
  enif_mutex_unlock(q->Lock);
  return acceptor;
}

static QUICER_ACCEPTOR_QUEUE *
AcceptorQueueAlloc()
{
  return (QUICER_ACCEPTOR_QUEUE *)CXPLAT_ALLOC_NONPAGED(
      sizeof(QUICER_ACCEPTOR_QUEUE), QUICER_ACCEPTOR);
}

ACCEPTOR *
AcceptorAlloc()
{
  return CXPLAT_ALLOC_NONPAGED(sizeof(ACCEPTOR), QUICER_ACCEPTOR);
}

void
AcceptorDestroy(ACCEPTOR *acc)
{
  return CXPLAT_FREE(acc, QUICER_ACCEPTOR);
}

///_* Emacs
///====================================================================
/// Local Variables:
/// allout-layout: t
/// c-indent-level: 2
/// End:
