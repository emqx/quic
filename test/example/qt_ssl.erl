-module(qt_ssl).

-export([s/0, c/0]).
-export([check_processes/0, certs/0, perf/3]).

-include("../../include/quicer.hrl").

%% Usage: run qt_ssl:s() in one window, and qt_ssl:c() in another window.
%% Playaround with the client and do things like:

%% Start server as: erl -pa ../../_build/default/lib/quicer/ebin -s qt_ssl s
%% Start the client as:
%% $ erl -pa ../../_build/default/lib/quicer/ebin
%% Erlang/OTP 25 [erts-13.0.4] [source] [64-bit] [smp:12:12] [ds:12:12:10] [async-threads:1] [jit:ns]
%%
%% Eshell V13.0.4  (abort with ^G)
%% 2> qt_ssl:c().
%% -->



%% 1> qt_ssl:c().
%% --> connect.
%% Connection # 1
%% etc  ... similar to qt.erl


%% This variant of qt.erl is meant to be used to compare quic vs OTP SSL
%% It can be used to compare for speed and memory consumption

%% The server


s() ->
  application:ensure_all_started(ssl),
  Port = 4567,
  LOptions = [{certfile , "./server.pem"},
              {keyfile , "./server.key"},
              {verify , verify_none},
              {reuseaddr, true},
              {active, false},
              {packet, 4},
              binary
             ],
  proc_lib:spawn_link(fun() ->
                          {ok, L} = ssl:listen(Port, LOptions),
                          listener(L)
                      end).


listener(L) ->
  Top = self(),
  P = proc_lib:spawn_link(
        fun() ->
            acceptor(Top, L)
        end),
  receive {P, more} -> ok end,
  listener(L).



acceptor(Top, L) ->
  io:format("Call accept ~p\n", [self()]),
  {ok, Sock} = ssl:transport_accept(L),
  _ = ssl:handshake(Sock),

  Top ! {self(), more},

  io:format("accept -> ~p\n",[Sock]),
  H = proc_lib:spawn_link(
        fun() -> stream_owner(Sock) end),
  ok = ssl:controlling_process(Sock, H),
  H ! continue,
  acceptor(Top, L).


stream_owner(Sock) ->
  receive
    continue ->
      ok
  end,
  ok = ssl:setopts(Sock, [{active, 20}]),
  case server_negotiate(Sock) of
    {ok, CNo} ->
      io:format("Enter recv_ping for ~p\n",[CNo]),

      recv_ping(Sock, 1, CNo),
      io:format("Leaving stream_Owner \n",[]);
    Err ->
      io:format("server negotiate ~p~n", [Err])
  end.


recv_ping(S, N, CNo) ->
  receive
    {ssl_passive, S} ->
      io:format("Setting active 20\n",[]),
      ok = ssl:setopts(S, [{active, 20}]),
      recv_ping(S, N, CNo);
    {ssl, S, <<"perf", SZ:32, NN:32>>} ->
      ssl:setopts(S, [{active, false}]),
      ok = ssl:send(S, <<"ok">>),
      io:format("enter perf loop \n",[]),
      perf_loop(S, SZ, NN),
      recv_ping(S, N, CNo);

    {ssl, S, <<"ping">>} ->
      io:format("Got ping ~p from ~p\n",[N, CNo]),
      ok = ssl:send(S, <<"pong">>),
      recv_ping(S, N+1, CNo);
    {ssl, S, <<"die">>} ->
      io:format("Got die from ~p\n",[CNo]),
      die;
    {ssl_closed, S} ->
      io:format("Got close stream from ~p\n",[CNo]),
      closed
  end.


perf_loop(_, _, 0) ->
  ok;
perf_loop(S, Sz, N) ->
  {ok, Bin} = ssl:recv(S, Sz),
  ok = ssl:send(S, Bin),
  perf_loop(S, Sz, N-1).


send_ping(0, _) ->
  ok;
send_ping(N, S) ->
  ok = ssl:send(S, <<"ping">>),
  rec_pong(N, S).
rec_pong(N, S) ->
  receive
    {ssl, S, <<"pong">>} ->
      io:format("Got pong ~p\n",[N]),
      send_ping(N-1, S);
    {ssl_passive, S} ->
      io:format("Setting active 30 \n",[]),
      ok = ssl:setopts(S, [{active, 30}]),
      rec_pong(N, S);
    {ssl_closed, S} ->
      closed
  end.


%% The client


c_opts() ->
    [binary, {verify, verify_none}, {packet, 4}].



c() ->
  application:ensure_all_started(ssl),
  client([], 1).
client(Conns, CNo) ->
  Port = 4567,
  case io:read("--> ") of
    {ok, connect} ->
      %% connect one

      case ssl:connect("localhost", Port, c_opts()) of
        {ok, Conn} ->
          ok = ssl:setopts(Conn, [{active, 20}]),
          ok = client_negotiate(Conn, CNo),
          io:format("Connection # ~p~n", [CNo]),
          client([{Conn, CNo} | Conns], CNo+1);
        Err ->
          io:format("Failed to connect ~p~n", [Err]),
          client(Conns, CNo)
      end;
    {ok, {connect, N}} ->
      %% create N connections
      CC = lists:zf(
             fun(NN) ->
                 case ssl:connect(
                        "localhost", Port, c_opts()) of
                   {ok, Conn} ->
                     ok = ssl:setopts(Conn, [{active, 20}]),
                     ok = client_negotiate(Conn, NN),
                     io:format("Connection # ~p~n", [NN]),
                     {true, {Conn, NN}};
                   Err ->
                     io:format("NN = ~p -> ~p~n", [NN, Err]),
                     false
                 end
             end, lists:seq(CNo, CNo+N-1)),
      client(CC ++ Conns, CNo+N);

    {ok, {mping, N}} ->
      %% Do N pings on all connections
      lists:foreach(fun({Conn, _}) ->
                        Ret = send_ping(N, Conn),
                        io:format("~p~n", [Ret])
                    end, Conns),
      client(Conns, CNo);


    {ok, {close_connection, CNumber}} ->
      {value, {Conn, CNumber}} = lists:keysearch(CNumber, 2, Conns),
      io:format("closing connection -> ",[]),
      Ret = ssl:close(Conn),
      io:format("~p \n",[Ret]),
      client(lists:keydelete(CNumber, 2, Conns), CNo);

    {ok, {ping, CNumber}} ->
      %% Send ping on stream SNumber
      {value, {Conn, CNumber}} = lists:keysearch(CNumber, 2, Conns),
      Ret = send_ping(1, Conn),
      io:format("~p~n", [Ret]),
      client(Conns, CNo);
    {ok, {ping, CNumber, N}} ->
      %% Send N pings on stream SNumber
      {value, {Conn, CNumber}} = lists:keysearch(CNumber, 2, Conns),
      Ret = send_ping(N, Conn),
      io:format("~p~n", [Ret]),
      client(Conns, CNo);

    {ok, {die, CNumber}} ->
      %% Force other end of stream to die without closing stream
      {value, {Conn, CNumber}} = lists:keysearch(CNumber, 2, Conns),
      Ret = ssl:send(Conn, <<"die">>),
      io:format("~p~n", [Ret]),
      client(Conns, CNo);


   {ok, {perf, NumPacks, PackSz}} ->
      %% create a connection + stream, and measure speed
      %% sending NumPacks, of size PackSz


      {ok, S} = ssl:connect("localhost", Port, c_opts()),

      ok = client_negotiate(S, CNo),
      ok = ssl:setopts(S, [{active, false}]),
      {T, ok} = timer:tc(qt_ssl, perf, [S, NumPacks, pack(PackSz)]),
      io:format("T = ~p milli~n", [T div 1000]),
      client(Conns, CNo);

    {ok, print} ->
      io:format("Conns = ~p~n", [Conns]),
      client(Conns, CNo);
    {ok, flush} ->
      C2 = flush(Conns),
      client(C2, CNo);
    {ok, exit} ->
      exit(normal);
    Err ->
      io:format("ERR ~p~n", [Err]),
      client(Conns, CNo)
  end.


pack(N) ->
  list_to_binary(
    lists:map(fun(_) ->
                  18
              end, lists:seq(1, N))).

%%
client_negotiate(S, CNo) ->
  Data = <<CNo:32>>,
  case ssl:send(S, Data) of
    ok ->
      io:format("Sent negotiate data \n",[]),
      receive
        {ssl, S, <<"dataok">>} ->
          ok;
        {ssl_closed, S} ->
          closed
      end;
    Err ->
      Err
  end.

server_negotiate(S) ->
  receive
    {ssl,S,<<CNo:32>>} ->
      ok = ssl:send(S, <<"dataok">>),
      {ok, CNo};
    Other ->
      {error, Other}
  end.

flush(Conns) ->
  receive
    {ssl_closed, S} ->
      {value, {S, CNumber}} = lists:keysearch(S, 1, Conns),
      io:format("Sock ~p closed \n",[CNumber]),
      flush(lists:keydelete(S, 1, Conns))
  after 10 ->
      Conns
  end.

perf(S, N, Packet) ->
  io:format("enter perf \n",[]),
  Sz = size(Packet),
  ok = ssl:send(S, <<"perf", Sz:32, N:32>>),
  {ok, <<"ok">>} = ssl:recv(S, 2),
  io:format("enter perf2 \n",[]),
  perf2(S, N, Sz, Packet).

perf2(_S, 0, _, _) ->
  ok;
perf2(S, N, Sz, Packet) ->
  ok = ssl:send(S, Packet),
  {ok, Bin} = ssl:recv(S, Sz),
  Sz = size(Bin),
  perf2(S, N-1, Sz, Packet).



check_processes() ->
  L2 = lists:zf(fun(Pid) ->
                    case process_info(Pid, messages) of
                      {messages, []} ->
                        false;
                      {messages, _} = Messages ->
                        CST = process_info(Pid, current_stacktrace),
                        {true, {Pid, Messages, CST}}
                    end
                end, processes()),
  case L2 of
    [] ->
      ok_procs;
    Bad ->
      {error, lists:flatten(io_lib:format("~p~n", [Bad]))}
  end.


certs() ->
  DataDir = ".",
    _ = quicer_test_lib:gen_ca(DataDir, "ca"),
  _ = quicer_test_lib:gen_host_cert("server", "ca", DataDir),
  _ = quicer_test_lib:gen_host_cert("client", "ca", DataDir),
  _ = quicer_test_lib:gen_ca(DataDir, "other-ca"),
  _ = quicer_test_lib:gen_host_cert("other-client", "other-ca", DataDir),
  erlang:halt().


%%%_* Emacs ====================================================================
%%% Local Variables:
%%% erlang-indent-level: 2
%%% End:
