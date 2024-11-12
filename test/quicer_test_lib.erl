%%--------------------------------------------------------------------
%% Copyright (c) 2020-2024 EMQ Technologies Co., Ltd. All Rights Reserved.
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

-module(quicer_test_lib).
-include_lib("kernel/include/file.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    gen_ca/2,
    gen_host_cert/3,
    gen_host_cert/4,
    generate_tls_certs/1,
    tls_server_key_password/0,
    receive_all/0,
    recv_term_from_stream/1,
    encode_stream_term/1,
    select_free_port/1,
    flush/1,
    ensure_server_exit_normal/1,
    ensure_server_exit_normal/2,

    report_active_connections/0,
    report_active_connections/1,

    report_unhandled_messages/0
]).

%% Default opts
-export([
    default_listen_opts/1,
    default_conn_opts/0,
    default_stream_opts/0
]).

%% cleanups
-export([
    reset_global_reg/0,
    shutdown_all_listeners/0,
    cleanup_msquic/0
]).

%% ct helper
-export([all_tcs/1]).

-define(MAGIC_HEADER, 4294967293).

-define(SERVER_KEY_PASSWORD, "sErve7r8Key$!").

-spec default_listen_opts(proplists:proplist()) -> proplists:proplist().
default_listen_opts(Config) ->
    DataDir = ?config(data_dir, Config),
    [
        {verify, none},
        {certfile, filename:join(DataDir, "server.pem")},
        {keyfile, filename:join(DataDir, "server.key")},
        {alpn, ["sample"]},
        {idle_timeout_ms, 10000},
        % QUIC_SERVER_RESUME_AND_ZERORTT
        {server_resumption_level, 2},
        {peer_bidi_stream_count, 10},
        {peer_unidi_stream_count, 0}
        | Config
    ].

-spec default_conn_opts() -> proplists:proplist().
default_conn_opts() ->
    [
        {verify, none},
        {alpn, ["sample"]},
        %% {sslkeylogfile, "/tmp/SSLKEYLOGFILE"},
        {idle_timeout_ms, 5000}
    ].

-spec default_stream_opts() -> proplists:proplist().
default_stream_opts() ->
    [].

%% select a random port picked by OS
%% @doc get unused port from OS
-spec select_free_port(tcp | udp | ssl | quic) -> inets:port_number().
select_free_port(tcp) ->
    select_free_port(gen_tcp, listen);
select_free_port(udp) ->
    select_free_port(gen_udp, open);
select_free_port(ssl) ->
    select_free_port(tcp);
select_free_port(quic) ->
    select_free_port(udp).

select_free_port(GenModule, Fun) when
    GenModule == gen_tcp orelse
        GenModule == gen_udp
->
    {ok, S} = GenModule:Fun(0, [{reuseaddr, true}]),
    {ok, Port} = inet:port(S),
    ok = GenModule:close(S),
    case os:type() of
        {unix, darwin} ->
            %% in MacOS, still get address_in_use after close port
            timer:sleep(500);
        _ ->
            skip
    end,
    ct:pal("Select free OS port: ~p", [Port]),
    Port.

%% @doc recv erlang term from stream
-spec recv_term_from_stream(quicer:stream_handle()) -> term().
recv_term_from_stream(Stream) ->
    {ok, <<?MAGIC_HEADER:32/unsigned, Len:64/unsigned>>} = quicer:recv(Stream, 12),
    {ok, Payload} = quicer:recv(Stream, Len),
    binary_to_term(Payload).

%% @doc wrap one erlang term for transfer on the quic stream
-spec encode_stream_term(term()) -> binary().
encode_stream_term(Payload) when not is_binary(Payload) ->
    encode_stream_term(term_to_binary(Payload));
encode_stream_term(Payload) when is_binary(Payload) ->
    Len = byte_size(Payload),
    <<?MAGIC_HEADER:32/unsigned, Len:64/unsigned, Payload/binary>>.

receive_all() ->
    receive_all([]).

receive_all(Res) ->
    receive
        X ->
            receive_all([X | Res])
    after 0 ->
        lists:reverse(Res)
    end.

%% @doc get all test cases for ct all callback
-spec all_tcs(module()) -> [atom()].
all_tcs(Module) ->
    [
        F
     || {F, 1} <- Module:module_info(exports),
        nomatch =/= string:prefix(atom_to_list(F), "tc_")
    ].

gen_ca(Path, Name) ->
    %% Generate ca.pem and ca.key which will be used to generate certs
    %% for hosts server and clients
    ECKeyFile = eckey_name(Path),
    filelib:ensure_dir(ECKeyFile),
    os:cmd("openssl ecparam -name secp256r1 > " ++ ECKeyFile),
    Cmd = lists:flatten(
        io_lib:format(
            "openssl req -new -x509 -nodes "
            "-newkey ec:~s "
            "-keyout ~s -out ~s -days 3650 "
            %"-addext basicConstraints=CA:TRUE "
            "-subj \"/C=SE/O=TEST CA\"",
            [
                ECKeyFile,
                ca_key_name(Path, Name),
                ca_cert_name(Path, Name)
            ]
        )
    ),
    os:cmd(Cmd).

ca_cert_name(Path, Name) ->
    filename(Path, "~s.pem", [Name]).
ca_key_name(Path, Name) ->
    filename(Path, "~s.key", [Name]).

eckey_name(Path) ->
    filename(Path, "ec.key", []).

gen_host_cert(H, CaName, Path) ->
    gen_host_cert(H, CaName, Path, #{}).

gen_host_cert(H, CaName, Path, Opts) ->
    ECKeyFile = eckey_name(Path),
    CN = str(H),
    HKey = filename(Path, "~s.key", [H]),
    HCSR = filename(Path, "~s.csr", [H]),
    HCSR2 = filename(Path, "~s.csr", [H]),
    HPEM = filename(Path, "~s.pem", [H]),
    HPEM2 = filename(Path, "~s_renewed.pem", [H]),
    HEXT = filename(Path, "~s.extfile", [H]),
    PasswordArg =
        case maps:get(password, Opts, undefined) of
            undefined ->
                " -nodes ";
            Password ->
                io_lib:format(" -passout pass:'~s' ", [Password])
        end,

    create_file(
        HEXT,
        "keyUsage=digitalSignature,keyAgreement,keyCertSign\n"
        "basicConstraints=CA:TRUE \n"
        "~s \n"
        "subjectAltName=DNS:~s\n",
        [maps:get(ext, Opts, ""), CN]
    ),

    CSR_Cmd = csr_cmd(PasswordArg, ECKeyFile, HKey, HCSR, CN),
    CSR_Cmd2 = csr_cmd(PasswordArg, ECKeyFile, HKey, HCSR2, CN),

    CERT_Cmd = cert_sign_cmd(
        HEXT, HCSR, ca_cert_name(Path, CaName), ca_key_name(Path, CaName), HPEM
    ),
    %% 2nd cert for testing renewed cert.
    CERT_Cmd2 = cert_sign_cmd(
        HEXT, HCSR2, ca_cert_name(Path, CaName), ca_key_name(Path, CaName), HPEM2
    ),
    ct:pal(os:cmd(CSR_Cmd)),
    ct:pal(os:cmd(CSR_Cmd2)),
    ct:pal(os:cmd(CERT_Cmd)),
    ct:pal(os:cmd(CERT_Cmd2)),
    file:delete(HEXT).

cert_sign_cmd(ExtFile, CSRFile, CACert, CAKey, OutputCert) ->
    lists:flatten(
        io_lib:format(
            "openssl x509 -req "
            "-extfile ~s "
            "-in ~s -CA ~s -CAkey ~s -CAcreateserial "
            "-out ~s -days 500",
            [
                ExtFile,
                CSRFile,
                CACert,
                CAKey,
                OutputCert
            ]
        )
    ).

csr_cmd(PasswordArg, ECKeyFile, HKey, HCSR, CN) ->
    lists:flatten(
        io_lib:format(
            "openssl req -new ~s -newkey ec:~s "
            "-keyout ~s -out ~s "
            "-addext \"subjectAltName=DNS:~s\" "
            "-addext basicConstraints=CA:TRUE "
            "-addext keyUsage=digitalSignature,keyAgreement,keyCertSign "
            "-subj \"/C=SE/O=TEST/CN=~s\"",
            [PasswordArg, ECKeyFile, HKey, HCSR, CN, CN]
        )
    ).

filename(Path, F, A) ->
    filename:join(Path, str(io_lib:format(F, A))).

str(Arg) ->
    binary_to_list(iolist_to_binary(Arg)).

create_file(Filename, Fmt, Args) ->
    filelib:ensure_dir(Filename),
    {ok, F} = file:open(Filename, [write]),
    try
        io:format(F, Fmt, Args)
    after
        file:close(F)
    end,
    ok.

-spec tls_server_key_password() -> string().
tls_server_key_password() ->
    ?SERVER_KEY_PASSWORD.

%% @doc Generate TLS cert chain for tests
generate_tls_certs(Config) ->
    DataDir = ?config(data_dir, Config),
    ?assertNotEqual(undefined, DataDir),

    %% Legacy certs
    gen_ca(DataDir, "ca"),
    gen_host_cert("server", "ca", DataDir),
    gen_host_cert("client", "ca", DataDir),
    gen_ca(DataDir, "other-ca"),
    gen_host_cert("other-client", "other-ca", DataDir),
    gen_host_cert("other-server", "other-ca", DataDir),
    gen_host_cert("server-password", "ca", DataDir, #{password => ?SERVER_KEY_PASSWORD}),

    %% New certs for TLS chain tests
    gen_ca(DataDir, "root"),
    gen_host_cert("intermediate1", "root", DataDir),
    gen_host_cert("intermediate2", "root", DataDir),
    gen_host_cert("server1", "intermediate1", DataDir),
    gen_host_cert("client1", "intermediate1", DataDir),
    gen_host_cert("server2", "intermediate2", DataDir),
    gen_host_cert("client2", "intermediate2", DataDir),

    %% Build bundles below
    os:cmd(
        io_lib:format("cat ~p ~p ~p > ~p", [
            filename:join(DataDir, "client2.pem"),
            filename:join(DataDir, "intermediate2.pem"),
            filename:join(DataDir, "root.pem"),
            filename:join(DataDir, "client2-complete-bundle.pem")
        ])
    ),
    os:cmd(
        io_lib:format("cat ~p ~p > ~p", [
            filename:join(DataDir, "client2.pem"),
            filename:join(DataDir, "intermediate2.pem"),
            filename:join(DataDir, "client2-intermediate2-bundle.pem")
        ])
    ),
    os:cmd(
        io_lib:format("cat ~p ~p > ~p", [
            filename:join(DataDir, "client2.pem"),
            filename:join(DataDir, "root.pem"),
            filename:join(DataDir, "client2-root-bundle.pem")
        ])
    ),
    os:cmd(
        io_lib:format("cat ~p ~p > ~p", [
            filename:join(DataDir, "server1.pem"),
            filename:join(DataDir, "intermediate1.pem"),
            filename:join(DataDir, "server1-intermediate1-bundle.pem")
        ])
    ),
    os:cmd(
        io_lib:format("cat ~p ~p > ~p", [
            filename:join(DataDir, "intermediate1.pem"),
            filename:join(DataDir, "server1.pem"),
            filename:join(DataDir, "intermediate1-server1-bundle.pem")
        ])
    ),
    os:cmd(
        io_lib:format("cat ~p ~p > ~p", [
            filename:join(DataDir, "intermediate1_renewed.pem"),
            filename:join(DataDir, "root.pem"),
            filename:join(DataDir, "intermediate1_renewed-root-bundle.pem")
        ])
    ),
    os:cmd(
        io_lib:format("cat ~p ~p > ~p", [
            filename:join(DataDir, "intermediate2.pem"),
            filename:join(DataDir, "intermediate2_renewed.pem"),
            filename:join(DataDir, "intermediate2_renewed_old-bundle.pem")
        ])
    ),
    os:cmd(
        io_lib:format("cat ~p ~p > ~p", [
            filename:join(DataDir, "intermediate1.pem"),
            filename:join(DataDir, "root.pem"),
            filename:join(DataDir, "intermediate1-root-bundle.pem")
        ])
    ),
    os:cmd(
        io_lib:format("cat ~p ~p ~p > ~p", [
            filename:join(DataDir, "root.pem"),
            filename:join(DataDir, "intermediate2.pem"),
            filename:join(DataDir, "intermediate1.pem"),
            filename:join(DataDir, "all-CAcerts-bundle.pem")
        ])
    ),
    os:cmd(
        io_lib:format("cat ~p ~p > ~p", [
            filename:join(DataDir, "intermediate2.pem"),
            filename:join(DataDir, "intermediate1.pem"),
            filename:join(DataDir, "two-intermediates-bundle.pem")
        ])
    ).

-spec flush([term()]) -> [term()].
flush(Acc) ->
    receive
        Other ->
            flush([Other | Acc])
    after 0 ->
        lists:reverse(Acc)
    end.

-spec ensure_server_exit_normal(reference()) -> ok.
ensure_server_exit_normal(MonRef) ->
    ensure_server_exit_normal(MonRef, 5000).
ensure_server_exit_normal(MonRef, Timeout) ->
    receive
        {'DOWN', MonRef, process, _, normal} ->
            ok;
        {'DOWN', MonRef, process, _, Other} ->
            ct:fail("server exits abnormally ~p ", [Other])
    after Timeout ->
        ct:fail("server still running", [])
    end.

-spec report_active_connections() -> _.
report_active_connections() ->
    report_active_connections(fun ct:comment/2).
report_active_connections(LogFun) ->
    erlang:garbage_collect(),
    {ok, Cnts} = quicer:perf_counters(),
    ActiveStrms = proplists:get_value(strm_active, Cnts),
    ActiveConns = proplists:get_value(conn_active, Cnts),
    0 =/= (ActiveStrms + ActiveConns) andalso
        LogFun("active conns: ~p, strms: ~p", [ActiveConns, ActiveStrms]).

-spec report_unhandled_messages() -> ok.
report_unhandled_messages() ->
    Unhandled = quicer_test_lib:receive_all(),
    Unhandled =/= [] andalso
        ct:comment("What left in the message queue: ~p", [Unhandled]).

-spec cleanup_msquic() -> ok.
cleanup_msquic() ->
    shutdown_all_listeners(),
    reset_global_reg(),
    ok.

reset_global_reg() ->
  case quicer:get_listeners() of
    [] ->
      ok;
    Other ->
        ct:pal("Warn: Listeners not cleaned up: ~p", [Other]),
        lists:foreach(
            fun(L) -> quicer:close_listener(L) end, Other
        )
  end,
  case quicer:get_registration_refcnt(global) of
    1 ->
        ok;
    N ->
      ct:pal("Warn: Global registration refcnt not 1: ~p", [N])
  end,
  quicer:reg_close(),
  retry_reg_open().

retry_reg_open() ->
  case quicer:reg_open() of
    ok ->
      ok;
    {error, status} = E ->
      %% Lib is closed.
      E;
    {error, Reason} ->
      ct:pal("Failed to open global registration: ~p, retry....", [Reason]),
      timer:sleep(50),
      retry_reg_open()
  end.

shutdown_all_listeners() ->
    lists:foreach(
        fun({{Id, _ListenOn}, _Pid}) ->
            quicer:terminate_listener(Id)
        end,
        quicer:listeners()
     ).
    %lists:map(fun(L) -> quicer:close_listener(L) end, quicer:get_listeners()).

%%%_* Emacs ====================================================================
%%% Local Variables:
%%% erlang-indent-level: 2
%%% End:
