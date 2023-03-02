-module(qt).

-export([s/0, c/0]).
-export([check_processes/0, certs/0, perf/3]).

-include("../../include/quicer.hrl").

%% Usage: run qt:s() in one window, and qt:c() in another window.
%% Playaround with the client and do things like:

%% Start server as: erl -pa ../../_build/default/lib/quicer/ebin -s qt s
%% Start the client as:
%% $ erl -pa ../../_build/default/lib/quicer/ebin
%% Erlang/OTP 25 [erts-13.0.4] [source] [64-bit] [smp:12:12] [ds:12:12:10] [async-threads:1] [jit:ns]
%%
%% Eshell V13.0.4  (abort with ^G)
%% 2> qt:c().
%% -->



%% 1> qt:c().
%% --> connect.
%% Connection # 1
%% --> {stream, 1}.
%% Sent negotiate data
%% Stream # 1
%% --> {ping, 1}.
%% Got pong 1
%% ok
%% --> {close_stream, 1}.
%% ok
%% -->

%% Also interesting is to experiment with various variants of CTL-Z and
%% CTL-C on both the server and the client.



%% The server

-define(INTERVAL, 3000).

s() ->
  application:ensure_all_started(quicer),
  Port = 4567,
  LOptions = #{cert => "./server.pem",
               key => "./server.key",
               verify => none,
               handshake_idle_timeout_ms => 3 * ?INTERVAL,
               keep_alive_interval_ms => ?INTERVAL,
               idle_timeout_ms => 3 * ?INTERVAL,
               peer_bidi_stream_count => 64000,
               alpn => ["sample"]
              },
  proc_lib:spawn_link(fun() ->
                          {ok, L} = quicer:listen(Port, LOptions),
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
  {ok, Conn} = quicer:accept(L, #{}, infinity),

  Top ! {self(), more},

  io:format("accept -> ~p\n",[Conn]),

  case quicer:handshake(Conn) of
    {ok, _Conn} ->
      io:format("Handshake ok\n",[]),
      accept_stream_loop(Conn);
    Err ->
      io:format("Failed handshake ~p~n", [Err])
  end.



accept_stream_loop(Conn) ->
  case quicer:accept_stream(Conn, #{active => false}, infinity) of
    {ok, Stm} ->
      io:format("accept stream -> ~p\n",[Stm]),
      H = proc_lib:spawn_link(
            fun() -> stream_owner(Stm) end),
      ok = quicer:handoff_stream(Stm, H),
      accept_stream_loop(Conn);
    Err ->
      io:format("Failed to accept_stream ~p leaving accept stream\n",[Err]),
      ok
  end.

stream_owner(Stream) ->
  receive
    {handoff_done, Stream, _} ->
      ok
  end,
  case server_negotiate(Stream) of
    {ok, CNo, SNo} ->
      io:format("Enter recv_ping for ~p:~p\n",[CNo, SNo]),
      ok = quicer:setopt(Stream, active, 20),
      recv_ping(Stream, 1, CNo, SNo),
      io:format("Leaving stream_Owner \n",[]);
    Err ->
      io:format("server negotiate ~p~n", [Err])
  end.



recv_ping(S, N, CNo, SNo) ->
  receive
    {quic, passive, S, _} ->
      io:format("Setting active 20\n",[]),
      ok = quicer:setopt(S, active, 20),
      recv_ping(S, N, CNo, SNo);

    {quic, <<"perf", SZ:32, NN:32>>, S, _} ->
      ok = quicer:setopt(S, active, false),
      {ok, 2} = quicer:send(S, <<"ok">>),
      perf_loop(S, SZ, NN),
      recv_ping(S, N, CNo, SNo);

    {quic, <<"ping">>, S,_} ->
      io:format("Got ping ~p from ~p:~p\n",[N, CNo, SNo]),
      {ok, 4} = quicer:send(S, <<"pong">>),
      recv_ping(S, N+1, CNo, SNo);
    {quic, <<"die">>, S,_} ->
      io:format("Got die from ~p:~p\n",[CNo, SNo]),
      die;
    {quic, peer_send_shutdown, S, _} ->
      io:format("Got peer shutdown from ~p:~p\n",[CNo, SNo]),
      quicer:async_close_stream(S),
      closed;
    {quic, stream_closed, S, _X} ->
      io:format("Got close stream from ~p:~p\n",[CNo, SNo]),
      quicer:async_close_stream(S),
      closed
  end.


perf_loop(_, _, 0) ->
  ok;
perf_loop(S, Sz, N) ->
  {ok, Bin} = quicer:recv(S, Sz),
  {ok, Sz} = quicer:send(S, Bin),
  perf_loop(S, Sz, N-1).


send_ping(0, _) ->
  ok;
send_ping(N, S) ->
  {ok, 4} = quicer:send(S, <<"ping">>),
  rec_pong(N, S).
rec_pong(N, S) ->
  receive
    {quic, <<"pong">>, S,_} ->
      io:format("Got pong ~p\n",[N]),
      send_ping(N-1, S);
    {quic, passive, S, _} ->
      io:format("Setting active 30 \n",[]),
      ok = quicer:setopt(S, active, 30),
      rec_pong(N, S);
    {quic, stream_closed, S, _} ->
      quicer:async_close_stream(S),
      closed
  end.


%% The client

c_opts() ->
  #{alpn => ["sample"],
    verify => none,
    keep_alive_interval_ms => ?INTERVAL,
    handshake_idle_timeout_ms => 3 * ?INTERVAL,
    idle_timeout_ms => 3 * ?INTERVAL}.

c() ->
  application:ensure_all_started(quicer),
  client([], [], 1, 1).
client(Conns, Streams, CNo, SNo) ->
  Port = 4567,
  case io:read("--> ") of
    {ok, connect} ->
      %% connect one


      case quicer:connect("localhost", Port, c_opts(), 10000) of
        {ok, Conn} ->
          io:format("Connection # ~p~n", [CNo]),
          client([{Conn, CNo} | Conns], Streams, CNo+1, SNo);
        Err ->
          io:format("Failed to connect ~p~n", [Err]),
          client(Conns, Streams, CNo, SNo)
      end;
    {ok, {connect, N}} ->
      %% create N connections
      CC = lists:zf(
             fun(NN) ->
                 case quicer:connect(
                        "localhost", Port, c_opts(), 10000) of
                   {ok, Conn} ->
                     io:format("Connection # ~p~n", [NN]),
                     {true, {Conn, NN}};
                   Err ->
                     io:format("NN = ~p -> ~p~n", [NN, Err]),
                     false
                 end
             end, lists:seq(CNo, CNo+N-1)),
      client(CC ++ Conns, Streams, CNo+N, SNo);

    {ok, p_connect} ->
      %% Use controlling process
      Self = self(),
      _P = proc_lib:spawn_link(
            fun() ->
                case quicer:connect("localhost", Port, c_opts(), 5000) of
                  {ok, Conn} ->
                    ok = quicer:controlling_process(Conn, Self),
                    timer:sleep(400),
                    Self ! {connection, Conn};
                  Err ->
                    Self ! {connection_err, Err}
                end
            end),
      receive
        {connection, Conn} ->
          io:format("Connection # ~p~n", [CNo]),
          client([{Conn, CNo} | Conns], Streams, CNo+1, SNo);

        {connection_err, Err} ->
          io:format("Failed to connect ~p~n", [Err]),
          client(Conns, Streams, CNo, SNo)
      end;


    {ok, {connect_stream, N}} ->
      %% Create N connections, with a stream associated to each conn
      L = lists:map(
            fun(NN) ->
                {ok, Conn} = quicer:connect(
                               "localhost", Port, c_opts(), 10000),
                {ok, Stm} = quicer:start_stream(Conn, #{active => 30}),
                ok = client_negotiate(Stm, NN, NN),
                io:format("Stream ~p~n", [NN]),
                {{Conn, NN} ,{Stm, NN, NN}}
            end, lists:seq(CNo, CNo+N-1)),
      NewConns = [element(1, C) || C <- L],
      NewStreams = [element(2, C) || C <- L],
      client(NewConns, NewStreams, N, N);


    {ok, mstream} ->
      %% Create a stream on all connections
      NumCons = length(Conns),
      NewStreamNos = lists:seq(SNo, SNo+NumCons-1),
      L = lists:zip(Conns, NewStreamNos),
      S2 = lists:zf(
             fun({{Conn, CNumber}, SNumber}) ->
                 case quicer:start_stream(Conn, #{active => 30}) of
                   {ok, Stm} ->
                     case client_negotiate(Stm, CNumber,
                                           SNumber) of
                       ok ->
                         ok = quicer:setopt(Stm, active, 30),
                         io:format("Stream # ~p~n",[SNumber]),
                         {true, {Stm, CNumber, SNumber}};
                       Err ->
                         io:format("Failed ~p ~p~n",
                                   [SNumber, Err]),
                         false
                     end;
                   Err ->
                     io:format("Failed2 ~p ~p~n",
                               [SNumber, Err]),
                     false
                 end
             end, L),
      client(Conns, S2, CNo, SNo+length(L));
    {ok, {mstream, N}} ->
      %% Create N streams on all connections
      Conns2 = lists:flatten(
                 lists:map(fun(_Int) ->
                               Conns
                           end, lists:seq(1, N))),
      NumCons = length(Conns2),
      NewStreamNos = lists:seq(SNo, SNo+NumCons-1),
      L = lists:zip(Conns2, NewStreamNos),
      S2 = lists:zf(
             fun({{Conn, CNumber}, SNumber}) ->
                 case quicer:start_stream(Conn, #{active =>30}) of
                   {ok, Stm} ->
                     case client_negotiate(Stm, CNumber,
                                           SNumber) of
                       ok ->
                         ok = quicer:setopt(Stm, active, 30),
                         io:format("Stream # ~p~n",[SNumber]),
                         {true, {Stm, CNumber, SNumber}};
                       Err ->
                         io:format("Failed ~p ~p~n",
                                   [SNumber, Err]),
                         false
                     end;
                   Err ->
                     io:format("Failed2 ~p ~p~n",
                               [SNumber, Err]),
                     false
                 end
             end, L),
      client(Conns, S2, CNo, SNo+length(L));
    {ok, {mping, N}} ->
      %% Do N pings on all streams
      lists:foreach(fun({Stm, _,_}) ->
                        Ret = send_ping(N, Stm),
                        io:format("~p~n", [Ret])
                    end, Streams),
      client(Conns, Streams, CNo, SNo);

    {ok, {stream, CNumber}} ->
      %% Create a stream on connection CNumber
      {value, {Conn, CNumber}} = lists:keysearch(CNumber, 2, Conns),
      case quicer:start_stream(Conn, #{active => 30}) of
        {ok, Stm} ->
          case client_negotiate(Stm, CNumber, SNo) of
            ok ->
              ok = quicer:setopt(Stm, active, 30),
              io:format("Stream # ~p~n", [SNo]),
              client(Conns, [{Stm, CNumber, SNo} | Streams],
                     CNo, SNo+1);
            Err ->
              io:format("negotiate failed ~p\n",[Err]),
              quicer:close_stream(Stm),
              client(Conns, Streams, CNo, SNo)
          end;
        Err ->
          io:format("Failed to start_stream ~p~n", [Err]),
          client(Conns, Streams, CNo, SNo)
      end;
    {ok, {stream, CNumber, NN}} ->
      %% Create NN  streams on connection CNumber
      {value, {Conn, CNumber}} = lists:keysearch(CNumber, 2, Conns),
      S2 = lists:map(
             fun(N) ->
                 case quicer:start_stream(Conn, #{active => 30}) of
                   {ok, Stm} ->
                     case client_negotiate(Stm, CNumber, N) of
                       ok ->
                         ok = quicer:setopt(Stm, active, 30),
                         io:format("Stream # ~p~n", [N]),
                         {Stm, CNumber, N}
                     end
                 end
             end, lists:seq(SNo, SNo+ NN-1)),
      client(Conns, S2 ++ Streams, CNo, NN+SNo);

    {ok, {perf, NumPacks, PackSz}} ->
      %% create a connection + stream, and measure speed
      %% sending NumPacks, of size PackSz
      {ok, Conn} = quicer:connect("localhost", Port, c_opts(), 10000),
      {ok, Stm} = quicer:start_stream(Conn, #{active => 30}),
      ok = client_negotiate(Stm, 1, 1),
      ok = quicer:setopt(Stm, active, false),
      {T, ok} = timer:tc(qt, perf, [Stm, NumPacks, pack(PackSz)]),
      io:format("T = ~p milli~n", [T div 1000]),
      client(Conns, Streams, CNo, SNo);


    {ok, {close_connection, CNumber}} ->
      {value, {Conn, CNumber}} = lists:keysearch(CNumber, 2, Conns),
      io:format("closing connection -> ",[]),
      Ret = quicer:close_connection(Conn),
      io:format("~p \n",[Ret]),
      client(lists:keydelete(CNumber, 2, Conns), Streams, CNo, SNo);
    {ok, {close_stream, SNumber}} ->
      {value, {Stm, _, SNumber}} = lists:keysearch(SNumber, 3, Streams),
      Ret = quicer:close_stream(Stm),
      io:format("~p~n", [Ret]),
      client(Conns, lists:keydelete(SNumber, 3, Streams), CNo, SNo);
    {ok, {ping, SNumber}} ->
      %% Send ping on stream SNumber
      {value, {Stm, _, SNumber}} = lists:keysearch(SNumber, 3, Streams),
      Ret = send_ping(1, Stm),
      io:format("~p~n", [Ret]),
      client(Conns, Streams, CNo, SNo);
    {ok, {ping, SNumber, N}} ->
      %% Send N pings on stream SNumber
      {value, {Stm, _ , SNumber}} = lists:keysearch(SNumber, 3, Streams),
      Ret = send_ping(N, Stm),
      io:format("~p~n", [Ret]),
      client(Conns, Streams, CNo, SNo);

    {ok, {die, SNumber}} ->
      %% Force other end of stream to die without closing stream
      {value, {Stm, _, SNumber}} = lists:keysearch(SNumber, 3, Streams),
      Ret = quicer:send(Stm, <<"die">>),
      io:format("~p~n", [Ret]),
      client(Conns, Streams, CNo, SNo);

    {ok, print} ->
      io:format("Conns = ~p~n", [Conns]),
      io:format("Streams = ~p~n", [Streams]),
      client(Conns, Streams, CNo, SNo);
    {ok, flush} ->
      {C2, S2} = flush(Conns, Streams),
      client(C2, S2, CNo, SNo);
    {ok, exit} ->
      exit(normal);
    Err ->
      io:format("ERR ~p~n", [Err]),
      client(Conns, Streams, CNo, SNo)
  end.

%%
client_negotiate(Stm, CNo, SNo) ->
  Data = <<CNo:32, SNo:32>>,
  case quicer:send(Stm, Data) of
    {ok, 8} ->
      io:format("Sent negotiate data \n",[]),
      receive
        {quic, <<"dataok">>, Stm, _} ->
          ok;
        {quic, stream_closed, Stm, _} ->
          quicer:async_close_stream(Stm),
          closed
      end;
    Err ->
      Err
  end.

server_negotiate(Stm) ->
  Data = quicer:recv(Stm, 0),
  case Data of
    {ok, <<CNo:32, SNo:32>>} ->
      {ok, 6} = quicer:send(Stm, <<"dataok">>),
      {ok, CNo, SNo};
    Err ->
      Err
  end.


flush(Conns, Streams) ->
  receive
    {quic, transport_shutdown, Conn, X} ->
      {value, {Conn, CNumber}} = lists:keysearch(Conn, 1, Conns),
      io:format("Connection ~p closed ~p\n", [CNumber, X]),
      flush(lists:keydelete(Conn, 1, Conns), Streams);
    {quic, stream_closed, Stm, X} ->
      quicer:async_close_stream(Stm),
      {value, {Stm, _ , SNumber}} = lists:keysearch(Stm, 1, Streams),
      io:format("Stream ~p closed ~p\n",[SNumber, X]),
      flush(Conns, lists:keydelete(Stm, 1, Streams));
    X when is_tuple(X), element(1, X) == quic ->
      io:format("OTHER: ~p~n", [X]),
      flush(Conns, Streams)
  after 10 ->
      {Conns, Streams}
  end.


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


perf(S, N, Packet) ->
  Sz = size(Packet),
  {ok, 12} = quicer:send(S, <<"perf", Sz:32, N:32>>),
  {ok, <<"ok">>} = quicer:recv(S, 2),
  perf2(S, N, Sz, Packet).

perf2(_S, 0, _, _) ->
  ok;
perf2(S, N, Sz, Packet) ->
  {ok, Sz} = quicer:send(S, Packet),
  {ok, Bin} = quicer:recv(S, Sz),
  Sz = size(Bin),
  perf2(S, N-1, Sz, Packet).



pack(N) ->
  list_to_binary(
    lists:map(fun(_) ->
                  18
              end, lists:seq(1, N))).

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
