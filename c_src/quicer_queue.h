#ifndef __QUICER_QUEUE_H_
#define __QUICER_QUEUE_H_

// @fixme
#ifndef QUIC_PLATFORM_LINUX
#define QUIC_PLATFORM_LINUX 1
#endif

#include <erl_nif.h>
#include <quic_platform.h>
#include <stdbool.h>

// for allocator tagging.
#define QUICER_ACCEPTOR '00rQ'  // Qr00 - QUICER ACCEPTOR
#define QUICER_SND_BUFF '10rQ'  // Qr01 - QUICER SEND BUFFER
#define QUICER_OWNER_MON '20rQ' // Qr02 - QUICER OWNER MON

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
