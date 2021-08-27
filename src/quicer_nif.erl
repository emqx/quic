%%--------------------------------------------------------------------
%% Copyright (c) 2020-2021 EMQ Technologies Co., Ltd. All Rights Reserved.
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
-module(quicer_nif).
-export([ open_lib/0
        , close_lib/0
        , reg_open/0
        , reg_close/0
        , listen/2
        , close_listener/1
        , async_connect/3
        , async_accept/2
        , async_handshake/1
        , async_close_connection/3
        , async_accept_stream/2
        , start_stream/2
        , send/3
        , recv/2
        , async_close_stream/3
        , sockname/1
        , getopt/3
        , setopt/3
        , controlling_process/2
        ]).

-export([ get_conn_rid/1
        , get_stream_rid/1
        ]).

-on_load(init/0).

-include_lib("kernel/include/file.hrl").
-include("quicer.hrl").

-type atom_reason() :: atom().
-type app_errno() :: non_neg_integer().
-type hostname() :: string().

-type listener_handler()   :: reference().
-type connection_handler() :: reference().
-type stream_handler()     :: reference().
-type conf_handler()       :: reference().
-type reg_handler()        :: reference().
-type global_handler()     :: undefined.

-type handler() ::
        global_handler()     |
        listener_handler()   |
        connection_handler() |
        stream_handler()     |
        conf_handler()       |
        reg_handler().

-type listen_on() :: inet:port_number() | string().
-type listen_opts() :: map(). %% @TODO expand

-type conn_opts() :: map(). %% @TODO expand
-type conn_close_flag() :: ?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE |
                           ?QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT.
-type acceptor_opts() :: map(). %% @TODO expand

-type stream_opts() :: map(). %% @TODO expand
-type stream_close_flags() :: ?QUIC_STREAM_SHUTDOWN_FLAG_NONE |
                              ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL |
                              ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                              ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE |
                              ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT |
                              ?QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE. %% @TODO add xor

-type send_flags() :: non_neg_integer(). %% is sync send or not

-type optname() ::
        optname_global()        |
        optname_conn()          |
        optname_stream()        |
        optname_reg()           |
        optname_configuration() |
        optname_tls().
                                                              %% | GET | SET|
-type optname_conn() ::   %% with connection_handler()
        %% /* Parameters for QUIC_PARAM_LEVEL_CONNECTION. */|
        param_conn_quic_version                   |           %% |  X  |    |
        param_conn_local_address                  |           %% |  X  |    | @TODO
        param_conn_remote_address                 |           %% |  X  |  X | @TODO
        param_conn_ideal_processor                |           %% |  X  |    | @TODO
        param_conn_settings                       |           %% |  X  |  X | @TODO
        param_conn_statistics                     |           %% |  X  |    |
        param_conn_statistics_plat                |           %% |  X  |    | @TODO
        param_conn_share_udp_binding              |           %% |  X  |  X | @TODO
        param_conn_local_bidi_stream_count        |           %% |  X  |    | @TODO
        param_conn_local_unidi_stream_count       |           %% |  X  |    | @TODO
        param_conn_max_stream_ids                 |           %% |  X  |    | @TODO
        param_conn_close_reason_phrase            |           %% |  X  |  X | @TODO
        param_conn_stream_scheduling_scheme       |           %% |  X  |  X | @TODO
        param_conn_datagram_receive_enabled       |           %% |  X  |  X | @TODO
        param_conn_datagram_send_enabled          |           %% |  X  |    | @TODO
        param_conn_disable_1rtt_encryption        |           %% |  X  |  X | @TODO
        param_conn_resumption_ticket              |           %% |     |  X | @TODO
        param_conn_peer_certificate_valid.                    %% |     |  X | @TODO

-type optname_tls()   ::  %% with connection_handler()
        param_tls_schannel_context_attribute_w    |           %% |  X  |    | @TODO
        param_tls_handshake_info                  |           %% |  X  |  X | @TODO
        param_tls_negotiated_alpn.                            %% |  X  |    | @TODO

-type optname_stream() ::
        active                                    |           %% |  X  |  X | @TODO GET
        controlling_process                       |           %% |     |    | @TODO GET SET
        param_stream_id                           |           %% |     |  X | @TODO
        param_stream_0rtt_length                  |           %% |  X  |    | @TODO
        param_stream_ideal_send_buffer_size.                  %% |  X  |    | @TODO

-type optname_global() ::                                     %% with `undefined' handler
        param_global_retry_memory_percent |                   %% |  X  | X  | @TODO
        param_global_supported_versions   |                   %% |  X  |    | @TODO
        param_global_load_balacing_mode   |                   %% |  X  | X  | @TODO
        param_global_perf_counters        |                   %% |  X  |    | @TODO
        param_global_settings             |                   %% |  X  | X  | @TODO
        param_global_version.                                 %% |  X  |    | @TODO

-type optname_reg() :: param_registration_cid_prefix.        %% |  X  |  X  | @TODO

-type optname_configuration() ::                             %% with config_handler()
        param_configuration_settings        |                %% |  X  |  X  | @TODO
        param_configuration_ticket_keys.                     %% |     |  X  | @TODO

-type conn_settings() :: [{conn_settings_key(), non_neg_integer()}].
-type conn_settings_key() ::
        max_bytes_per_key                  |
        handshake_idle_timeout_ms          |
        idle_timeout_ms                    |
        tls_client_max_send_buffer         |
        tls_server_max_send_buffer         |
        stream_recv_window_default         |
        stream_recv_buffer_default         |
        conn_flow_control_window           |
        max_worker_queue_delay_us          |
        max_stateless_operations           |
        initial_window_packets             |
        send_idle_timeout_ms               |
        initial_rtt_ms                     |
        max_ack_delay_ms                   |
        disconnect_timeout_ms              |
        keep_alive_interval_ms             |
        peer_bidi_stream_count             |
        peer_unidi_stream_count            |
        retry_memory_limit                 |
        load_balancing_mode                |
        max_operations_per_drain           |
        send_buffering_enabled             |
        pacing_enabled                     |
        migration_enabled                  |
        datagram_receive_enabled           |
        server_resumption_level            |
        version_negotiation_ext_enabled    |
        desired_versions_list              |
        desired_versions_list_length.


init() ->
  NifName = "libquicer_nif",
  {ok, Niflib} = locate_lib(code:priv_dir(quicer), NifName),
  ok = erlang:load_nif(Niflib, 0).

open_lib() ->
  LibFile = case locate_lib(code:priv_dir(quicer), "libmsquic.lttng.so") of
              {ok, File} ->
                File;
              {error, _} ->
                code:priv_dir(quicer)
            end,
  open_lib(LibFile).

open_lib(_LttngLib) ->
  erlang:nif_error(nif_library_not_loaded).

close_lib() ->
  erlang:nif_error(nif_library_not_loaded).

reg_open() ->
  erlang:nif_error(nif_library_not_loaded).

reg_close() ->
  erlang:nif_error(nif_library_not_loaded).

-spec listen(listen_on(), listen_opts()) ->
        {ok, listener_handler()} |
        {error, listener_open_error,  atom_reason()} |
        {error, listener_start_error, atom_reason()}.
listen(_ListenOn, _Options) ->
  erlang:nif_error(nif_library_not_loaded).

-spec close_listener(listener_handler()) -> ok.
close_listener(_Listener) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_connect(hostname(), inet:port_number(), conn_opts()) ->
        {ok, connection_handler()} |
        {error, conn_open_error | config_error | conn_start_error}.
async_connect(_Host, _Port, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_accept(listener_handler(), acceptor_opts()) ->
        {ok, listener_handler()} |
        {error, badarg | parm_error | not_enough_mem | badpid}.
async_accept(_Listener, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_handshake(connection_handler()) ->
        ok | {error, badarg | atom_reason()}.
async_handshake(_Connection) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_close_connection(connection_handler(), conn_close_flag(), app_errno()) ->
        ok | {error, badarg}.
async_close_connection(_Conn, _Flags, _ErrorCode) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_accept_stream(connection_handler(), stream_opts()) ->
        {ok, connection_handler()} |
        {error, badarg | internal_error | bad_pid | owner_dead}.
async_accept_stream(_Conn, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

-spec start_stream(connection_handler(), stream_opts()) ->
        {ok, stream_handler()} |
        {error, badarg | internal_error | bad_pid | owner_dead} |
        {error, stream_open_error, atom_reason()} |
        {error, stream_start_error, atom_reason()}.
start_stream(_Conn, _Opts) ->
  erlang:nif_error(nif_library_not_loaded).

-spec send(stream_handler(), binary(), send_flags()) ->
        {ok, BytesSent :: pos_integer()}          |
        {error, badarg | not_enough_mem | closed} |
        {error, stream_send_error, atom_reason()}.
send(_Stream, _Data, _Flags) ->
  erlang:nif_error(nif_library_not_loaded).

-spec recv(stream_handler(), non_neg_integer()) ->
        {ok, binary()}     |
        {error, not_ready} |
        {error, badarg | einval}.
recv(_Stream, _Len) ->
  erlang:nif_error(nif_library_not_loaded).

-spec async_close_stream(stream_handler(), stream_close_flags(), app_errno()) ->
        ok |
        {error, badarg | atom_reason()}.
async_close_stream(_Stream, _Flags, _ErrorCode) ->
  erlang:nif_error(nif_library_not_loaded).

-spec sockname(connection_handler() | stream_handler()) ->
        {ok, {inet:ip_address(), inet:port_number()}} |
        {error, badarg | sockname_error}.
sockname(_Conn) ->
  erlang:nif_error(nif_library_not_loaded).

-spec getopt(handler(), optname(), boolean()) ->
        {ok, binary()} | %% when IsRaw
        {ok, conn_settings()}   | %% when optname = param_conn_settings
        {error, badarg | parm_error | internal_error | not_enough_mem} |
        {error, atom_reason()}.

getopt(_Handle, _Optname, _IsRaw) ->
  erlang:nif_error(nif_library_not_loaded).

-spec setopt(handler(), optname(), any()) ->
        ok |
        {error, badarg | parm_error | internal_error | not_enough_mem} |
        {error, atom_reason()}.
setopt(_Handle, _Opt, _Value) ->
  erlang:nif_error(nif_library_not_loaded).

-spec get_conn_rid(connection_handler()) ->
        {ok, non_neg_integer()} |
        {error, badarg | internal_error}.
get_conn_rid(_Handle) ->
  erlang:nif_error(nif_library_not_loaded).

-spec get_stream_rid(stream_handler()) ->
        {ok, non_neg_integer()} |
        {error, badarg | internal_error}.
get_stream_rid(_Handle) ->
  erlang:nif_error(nif_library_not_loaded).

-spec controlling_process(connection_handler() | stream_handler(), pid()) ->
        ok |
        {error, badarg | owner_dead | not_owner}.
controlling_process(_H, _P) ->
  erlang:nif_error(nif_library_not_loaded).

%% Internals
-spec locate_lib(file:name(), file:name()) ->
        {ok, file:filename()} | {error, not_found}.
locate_lib(PrivDir, LibName) ->
  case file:read_file_info(PrivDir) of
    {ok, #file_info{type = directory}} ->
      {ok, filename:join(PrivDir, LibName)};
    {error, enotdir} -> %% maybe escript,
      Escript = filename:dirname(filename:dirname(PrivDir)),
      case file:read_file_info(Escript) of
        {ok, #file_info{type = regular}} ->
          %% try locate the file in same dir of escript
          {ok, filename:join(filename:dirname(Escript), LibName)};
        _ ->
          {error, not_found}
      end
  end.
