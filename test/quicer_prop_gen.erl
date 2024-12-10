%%--------------------------------------------------------------------
%% Copyright (c) 2024 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(quicer_prop_gen).

-export([
    valid_client_conn_opts/0,
    valid_server_listen_opts/0,
    valid_stream_shutdown_flags/0,
    valid_stream_start_flags/0,
    valid_stream_handle/0,
    valid_started_connection_handle/0,
    valid_opened_connection_handle/0,
    valid_connection_handle/0,
    valid_listen_on/0,
    valid_listen_opts/0,
    valid_listen_handle/0,
    valid_global_handle/0,
    valid_reg_handle/0,
    valid_handle/0,
    valid_csend_stream_opts/0,
    valid_quicer_settings/0,
    pid/0,
    data/0,
    quicer_send_flags/0,
    latin1_string/0
]).

-include_lib("proper/include/proper.hrl").
-include_lib("quicer/include/quicer_types.hrl").

-include("prop_quic_types.hrl").

valid_handle() ->
    oneof([
        valid_connection_handle(),
        valid_stream_handle(),
        valid_listen_handle(),
        valid_reg_handle(),
        valid_global_handle()
    ]).

%% @doc pid of process that dies randomly within 0-1000(ms)
pid() ->
    ?LET(
        LiveTimeMs,
        range(0, 1000),
        spawn(fun() -> timer:sleep(LiveTimeMs) end)
    ).

data() ->
    oneof([binary(), list(binary())]).

quicer_send_flags() ->
    ?LET(
        Flags,
        [send_flags()],
        begin
            lists:foldl(
                fun(F, Acc) ->
                    Acc bor F
                end,
                0,
                Flags
            )
        end
    ).

%% valid reg handle
valid_reg_handle() ->
    ?SUCHTHAT(
        Handle,
        ?LET(
            {Name, Profile},
            {reg_name(), registration_profile()},
            begin
                case quicer_nif:new_registration(Name, Profile) of
                    {ok, Handle} ->
                        #prop_handle{
                            type = reg,
                            name = Name,
                            handle = Handle,
                            destructor = fun() ->
                                quicer_nif:close_registration(Handle)
                            end
                        };
                    {error, _} ->
                        error
                end
            end
        ),
        Handle =/= error
    ).

reg_name() ->
    % latin1_string()
    ?LET(
        Rand,
        integer(),
        begin
            "foo" ++ integer_to_list(Rand)
        end
    ).

valid_global_handle() ->
    ?LET(_H, integer(), #prop_handle{
        type = global,
        handle = quic_global,
        destructor = fun() -> ok end
    }).

valid_listen_handle() ->
    ?SUCHTHAT(
        Ret,
        ?LET(
            {On, Opts},
            {valid_listen_on(), valid_listen_opts()},
            begin
                case quicer_nif:listen(On, maps:from_list(Opts)) of
                    {ok, Handle} ->
                        #prop_handle{
                            type = listener,
                            name = "noname",
                            handle = Handle,
                            destructor = fun() ->
                                quicer_nif:close_listener(Handle)
                            end
                        };
                    _E ->
                        ct:pal("listen failed: ~p", [_E]),
                        error
                end
            end
        ),
        Ret =/= error
    ).

valid_listen_opts() ->
    ?LET(
        Opts,
        quicer_listen_opts(),
        begin
            lists:foldl(
                fun proplists:delete/2,
                Opts ++ valid_server_listen_opts(),
                [
                    password,
                    %% flaky per machine sysconf
                    stream_recv_buffer_default
                ]
            )
        end
    ).

valid_listen_on() ->
    ?LET(
        Port,
        range(1025, 65536),
        begin
            case gen_udp:open(Port, [{reuseaddr, true}]) of
                {ok, S} ->
                    ok = gen_udp:close(S),
                    Port;
                _ ->
                    quicer_test_lib:select_free_port(quic)
            end
        end
    ).

%% @doc valid conn handle in different states (opened, started, closed)
valid_connection_handle() ->
    oneof([
        valid_opened_connection_handle(),
        valid_started_connection_handle()
    ]).

valid_opened_connection_handle() ->
    ?LET(
        _Rand,
        integer(),
        begin
            {ok, Handle} = quicer_nif:open_connection(),
            #prop_handle{
                type = conn,
                name = "noname",
                handle = Handle,
                destructor = fun() ->
                    quicer_nif:async_shutdown_connection(Handle, 0, 0)
                end
            }
        end
    ).

valid_started_connection_handle() ->
    ensure_dummy_listener(?DUMMY_PORT),
    ?LET(
        _Rand,
        integer(),
        begin
            {ok, Handle} = quicer_nif:async_connect(
                "localhost", ?DUMMY_PORT, maps:from_list(valid_client_conn_opts())
            ),
            #prop_handle{
                type = conn,
                name = "noname",
                handle = Handle,
                destructor = fun() ->
                    quicer_nif:async_shutdown_connection(Handle, 0, 0)
                end
            }
        end
    ).

valid_stream_handle() ->
    ensure_dummy_listener(?DUMMY_PORT),
    ?SUCHTHAT(
        Conn,
        ?LET(
            _Rand,
            integer(),
            begin
                {ok, Conn} = quicer_nif:async_connect(
                    "localhost", ?DUMMY_PORT, maps:from_list(valid_client_conn_opts())
                ),
                receive
                    {quic, connected, Conn, _} ->
                        {ok, Stream} = quicer_nif:start_stream(Conn, #{active => 1}),
                        #prop_handle{
                            type = stream,
                            name = "noname",
                            handle = Stream,
                            destructor =
                                fun() ->
                                    quicer_nif:async_shutdown_connection(Conn, 0, 0)
                                end
                        }
                after 100 ->
                    %% @FIXME
                    error
                end
            end
        ),
        Conn =/= error
    ).

valid_stream_start_flags() ->
    ?valid_flags(stream_start_flag()).

valid_stream_shutdown_flags() ->
    ?valid_flags(stream_shutdown_flags()).

latin1_string() -> ?SUCHTHAT(S, string(), io_lib:printable_latin1_list(S)).

%% @doc Server listen opts must work
valid_server_listen_opts() ->
    [
        {alpn, ["proper"]},
        {cacertfile, "./msquic/submodules/openssl/test/certs/rootCA.pem"},
        {certfile, "./msquic/submodules/openssl/test/certs/servercert.pem"},
        {keyfile, "./msquic/submodules/openssl/test/certs/serverkey.pem"}
    ].

valid_client_conn_opts() ->
    [
        {alpn, ["proper"]},
        {cacertfile, "./msquic/submodules/openssl/test/certs/rootCA.pem"},
        {certfile, "./msquic/submodules/openssl/test/certs/servercert.pem"},
        {keyfile, "./msquic/submodules/openssl/test/certs/serverkey.pem"}
    ].

valid_csend_stream_opts() ->
    ?LET(
        Opts,
        quicer_stream_opts(),
        maps:without(
            [start_flag],
            maps:from_list([{active, true} | Opts])
        )
    ).

%% @see msquic/src/core/settings.c
valid_quicer_settings() ->
    ?SUCHTHAT(
        Opts,
        ?LET(Q, list(quicer_setting_with_range()), Q),
        %% Conds below from msquic/src/core/settings.c
        quicer_setting_val_is_power_2(stream_recv_window_default, Opts) andalso
            quicer_setting_val_is_power_2(stream_recv_window_bidi_local_default, Opts) andalso
            quicer_setting_val_is_power_2(stream_recv_window_bidi_remote_default, Opts) andalso
            quicer_setting_val_is_power_2(stream_recv_window_unidi_default, Opts) andalso
            (proplists:get_value(maximum_mtu, Opts, 1500) >
                proplists:get_value(minimum_mtu, Opts, 1248))
    ).

-spec ensure_dummy_listener(non_neg_integer()) -> _.
ensure_dummy_listener(Port) ->
    case is_pid(whereis(?dummy_listener)) of
        false ->
            spawn_dummy_listener(Port);
        true ->
            ok
    end.

spawn_dummy_listener(Port) ->
    Parent = self(),
    spawn(fun() ->
        register(?dummy_listener, self()),
        {ok, L} = quicer_nif:listen(Port, maps:from_list(valid_server_listen_opts())),
        spawn_acceptors(L, 4),
        Parent ! ready,
        receive
            finish -> ok
        end
    end),
    receive
        ready ->
            ok
    end.

spawn_acceptors(_, 0) ->
    ok;
spawn_acceptors(L, N) ->
    spawn_link(fun() ->
        acceptor_loop(L)
    end),
    spawn_acceptors(L, N - 1).

acceptor_loop(L) ->
    case quicer:accept(L, #{active => true}) of
        {ok, Conn} ->
            spawn(fun() ->
                _ = quicer:handshake(Conn),
                timer:sleep(100),
                quicer:async_shutdown_connection(Conn, 0, 0)
            end),
            acceptor_loop(L);
        _ ->
            acceptor_loop(L)
    end.

-spec quicer_setting_val_is_power_2(atom(), proplists:proplist()) -> boolean().
quicer_setting_val_is_power_2(Key, Opts) ->
    is_pow_2(maps:get(Key, maps:from_list(Opts), 2)).
is_pow_2(N) when is_integer(N), N > 0 ->
    (N band (N - 1)) == 0;
is_pow_2(_) ->
    false.
