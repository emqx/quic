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

#ifndef __QUICER_LISTENER_H_
#define __QUICER_LISTENER_H_

#include "quicer_internal.h"
#include "quicer_nif.h"

QUIC_STATUS ServerListenerCallback(HQUIC Listener,
                                   void *Context,
                                   QUIC_LISTENER_EVENT *Event);

ERL_NIF_TERM listen2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM
close_listener1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#endif // __QUICER_LISTENER_H_
