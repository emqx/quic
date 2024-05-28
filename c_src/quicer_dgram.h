/*--------------------------------------------------------------------
Copyright (c) 2021-2024 EMQ Technologies Co., Ltd. All Rights Reserved.

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

#ifndef __QUICER_DGRAM_H_
#define __QUICER_DGRAM_H_

#include "quicer_nif.h"

ERL_NIF_TERM send_dgram(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

void handle_dgram_send_state_event(QuicerConnCTX *c_ctx,
                                   QUIC_CONNECTION_EVENT *Event);
void handle_dgram_state_changed_event(QuicerConnCTX *c_ctx,
                                      QUIC_CONNECTION_EVENT *Event);

void handle_dgram_recv_event(QuicerConnCTX *c_ctx,
                             QUIC_CONNECTION_EVENT *Event);

#endif // __QUICER_DGRAM_H_
