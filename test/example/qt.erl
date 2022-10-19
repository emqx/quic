-module(qt).

-export([s/0, c/0]).

-include("quicer.hrl").

%% Usage: run qt:s() in one window, and qt:c() in another window.
%% Playaround with the client and do things like:


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


%% The server

-define(INTERVAL, 3000).

s() ->
    application:ensure_all_started(quicer),
    Port = 4567,
    LOptions = [ {cert, "cert.pem"}
               , {key,  "key.pem"}
               , {handshake_idle_timeout_ms, 3 * ?INTERVAL}
               , {keep_alive_interval_ms, ?INTERVAL}
               , {alpn, ["sample"]}
               , {idle_timeout_ms, 3 *?INTERVAL}
               , {peer_bidi_stream_count, 64000}
               ],
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
    {ok, Conn} = quicer:accept(L, [], infinity),

    Top ! {self(), more},

    io:format("accept -> ~p\n",[Conn]),

    case quicer:handshake(Conn) of
        {ok, Conn} ->
            io:format("Handshake ok\n",[]),
            accept_stream_loop(Conn);
        Err ->
            io:format("Failed handshake ~p~n", [Err])
    end.



accept_stream_loop(Conn) ->
    case accept_stream(Conn, [{active, false}], infinity) of
        {ok, Stm} ->
            io:format("accept stream -> ~p\n",[Stm]),

            Self = self(),
            H = proc_lib:spawn_link(
                  fun() -> stream_owner(Self, Stm) end),
            ok = quicer:controlling_process(Stm, H),


            receive
                {H, continue} ->
                    accept_stream_loop(Conn);
                {H, turn} ->
                    turn(Conn)
            end;
        {error, connection_closed} ->
            io:format("Connection closed \n",[]),
            ok;
        Err ->
            io:format("Failed to accept_stream ~p \n",[Err]),
            accept_stream_loop(Conn)
    end.

stream_owner(Top, Stream) ->
    case server_negotiate(Stream) of
        {ok, CNo, SNo} ->
            io:format("Enter recv_ping for ~p:~p\n",[CNo, SNo]),

            ok = quicer:setopt(Stream, active, 20),
            case recv_ping(Stream, 1, CNo, SNo) of
                turn ->
                    Top ! {self(),turn},
                    io:format("Turning connecton \n",[]);

                _ ->
                    Top ! {self(), continue},
                    ok
            end,
            io:format("Leaving stream_Owner \n",[]);
        Err ->
            io:format("server negotiate ~p~n", [Err])
    end.


turn(Conn) ->
    case quicer:start_stream(Conn, [{active, 30}]) of
        {ok, Stm} ->
            case client_negotiate(Stm, 1,
                                  1) of
                ok ->
                    ok = quicer:setopt(Stm, active, 30),
                    io:format("Stream # ~p~n",[1]),
                    Ret = send_ping(1, Stm),
                    io:format("Turned ping = ~p~n", [Ret]),
                    quicer:close_stream(Stm),
                    quicer:close_connection(Conn);
                Err ->
                    io:format("Faila ~p~n", [Err])
            end;
        Err ->
            io:format("Fail to start stream ~p~n", [Err])
    end.

recv_ping(S, N, CNo, SNo) ->
    receive
        {quic_passive, S} ->
            ok = quicer:setopt(S, active, 20),
            recv_ping(S, N, CNo, SNo);
        {quic, <<"turn">>, S,_,_, _} ->
            quicer:close_stream(S),
            turn;
        {quic, <<"ping">>, S,_,_, _} ->
            io:format("Got ping ~p from ~p:~p\n",[N, CNo, SNo]),
            {ok, 4} = quicer:send(S, <<"pong">>),
            recv_ping(S, N+1, CNo, SNo);
        {quic, <<"die">>, S,_,_, _} ->
            io:format("Got die from ~p:~p\n",[CNo, SNo]),
            die;
        {quic, peer_send_shutdown, S} ->
            io:format("Got peer shutdown from ~p:~p\n",[CNo, SNo]),
            quicer:close_stream(S),
            closed;
        {quic, closed, S, _X} ->
            io:format("Got close stream from ~p:~p\n",[CNo, SNo]),
            quicer:close_stream(S),
            closed
    end.

send_ping(0, _) ->
    ok;
send_ping(N, S) ->
    {ok, 4} = quicer:send(S, <<"ping">>),
    rec_pong(N, S).
rec_pong(N, S) ->
    receive
        {quic, <<"pong">>, S,_,_, _} ->
            io:format("Got pong ~p\n",[N]),
            send_ping(N-1, S);
        {quic_passive, S} ->
            ok = quicer:setopt(S, active, 30),
            rec_pong(N, S);
        {quic, S, closed} ->
            closed;
        {quic, S, closed, _} ->
            closed2

    end.


%% The client

c() ->
    application:ensure_all_started(quicer),
    client([], [], 1, 1).
client(Conns, Streams, CNo, SNo) ->
    Port = 4567,
    case io:read("--> ") of
        {ok, connect} ->
            %% connect one
            case quicer:connect("localhost", Port,
                                [{alpn, ["sample"]},
                                 {keep_alive_interval_ms, ?INTERVAL},
                                 {handshake_idle_timeout_ms, 3 * ?INTERVAL},
                                 {idle_timeout_ms, 3 * ?INTERVAL}],
                                10000) of
                {ok, Conn} ->
                    io:format("Connection # ~p~n", [CNo]),
                    client([{Conn, CNo} | Conns], Streams, CNo+1, SNo);
                Err ->
                    io:format("Failed to connect ~p~n", [Err]),
                    client(Conns, Streams, CNo, SNo)
            end;
        {ok, {connect, N}} ->
            %% create many connections
            CC = lists:zf(
                   fun(NN) ->
                           case quicer:connect(
                                  "localhost", Port,
                                  [{alpn, ["sample"]},
                                   {handshake_idle_timeout_ms, 3 * 45000},
                                   {idle_timeout_ms, 0}
                                  ], 10000) of
                               {ok, Conn} ->
                                   io:format("Connection # ~p~n", [NN]),
                                   {true, {Conn, NN}};
                               Err ->
                                   io:format("NN = ~p -> ~p~n", [NN, Err]),
                                   false
                           end
                   end, lists:seq(CNo, CNo+N-1)),
            client(CC ++ Conns, Streams, CNo+N, SNo);

        {ok, mstream} ->
            %% Create a stream on all connections
            NumCons = length(Conns),
            NewStreamNos = lists:seq(SNo, SNo+NumCons-1),
            L = lists:zip(Conns, NewStreamNos),
            S2 = lists:zf(
                   fun({{Conn, CNumber}, SNumber}) ->
                           case quicer:start_stream(Conn, [{active, 30}]) of
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
                           case quicer:start_stream(Conn, [{active, 30}]) of
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
            {value, {Conn, CNumber}} = lists:keysearch(CNumber, 2, Conns),
            case quicer:start_stream(Conn, [{active, 30}]) of
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
            {value, {Conn, CNumber}} = lists:keysearch(CNumber, 2, Conns),
            S2 = lists:map(
                   fun(N) ->
                           case quicer:start_stream(Conn, [{active, 30}]) of
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


        {ok, {close_connection, CNumber}} ->
            {value, {Conn, CNumber}} = lists:keysearch(CNumber, 2, Conns),
            io:format("closing connection -> ",[]),
            Ret = quicer:close_connection(Conn),
            io:format("~p \n",[Ret]),
            S2 = lists:filter(fun({_Stream, X, _Y}) ->
                                      if X == CNumber -> false;
                                         true -> true
                                      end
                              end, Streams),
            client(lists:keydelete(CNumber, 2, Conns), S2, CNo, SNo);
        {ok, {close_stream, SNumber}} ->
            {value, {Stm, _, SNumber}} = lists:keysearch(SNumber, 3, Streams),
            Ret = quicer:close_stream(Stm),
            io:format("~p~n", [Ret]),
            client(Conns, lists:keydelete(SNumber, 3, Streams), CNo, SNo);
        {ok, {ping, SNumber}} ->
            {value, {Stm, _, SNumber}} = lists:keysearch(SNumber, 3, Streams),
            Ret = send_ping(1, Stm),
            io:format("~p~n", [Ret]),
            client(Conns, Streams, CNo, SNo);
        {ok, {ping, SNumber, N}} ->
            {value, {Stm, _ , SNumber}} = lists:keysearch(SNumber, 3, Streams),
            Ret = send_ping(N, Stm),
            io:format("~p~n", [Ret]),
            client(Conns, Streams, CNo, SNo);

        {ok, {die, SNumber}} ->
            {value, {Stm, _, SNumber}} = lists:keysearch(SNumber, 3, Streams),
            Ret = quicer:send(Stm, <<"die">>),
            io:format("~p~n", [Ret]),
            client(Conns, Streams, CNo, SNo);
        {ok, {turn, SNumber}} ->
            %% Turn this connection around, getting streams from the
            %% other end.
            {value, {Stm, CNumber, SNumber}} =
                lists:keysearch(SNumber, 3, Streams),
            {ok, 4} = quicer:send(Stm, <<"turn">>),
            quicer:close_stream(Stm),
            {value, {Conn, _}} = lists:keysearch(CNumber, 2, Conns),

            case accept_stream(Conn, [{active, false}], infinity) of
                {ok, Stm2} ->
                    io:format("accept stream -> ~p\n",[Stm2]),
                    case server_negotiate(Stm2) of
                        {ok, 1, 1} ->
                            io:format("Enter recv_ping for ~p:~p\n",[1,1]),
                            ok = quicer:setopt(Stm2, active, 20),
                            RR = recv_ping(Stm2, 1, 1, 1),
                            io:format("recv ping = ~p~n", [RR]);
                        Err ->
                            io:format("ERr ~p~n", [Err])
                    end;
                Err ->
                    io:format("ERr2 ~p~n", [Err])
            end,
            S2 = lists:keydelete(SNumber, 3, Streams),
            client(Conns, S2, CNo, SNo);

        {ok, print} ->
            io:format("Conns = ~p~n", [Conns]),
            io:format("Streans = ~p~n", [Streams]),
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
                {quic, <<"dataok">>, Stm, _,_,_} ->
                    ok;
                {quic, closed, Stm} ->
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
        {quic, closed, Conn} ->
            {value, {Conn, CNumber}} = lists:keysearch(Conn, 1, Conns),
            io:format("Connection ~p closed \n", [CNumber]),
            flush(lists:keydelete(Conn, 1, Conns), Streams);
        {quic, closed, Stm, _} ->
            {value, {Stm, _ , SNumber}} = lists:keysearch(Stm, 1, Streams),
            io:format("Stream ~p closed \n",[SNumber]),
            flush(Conns, lists:keydelete(Stm, 1, Streams));
        X ->
            io:format("~p~n", [X]),
            flush(Conns, Streams)
    after 1 ->
            {Conns, Streams}
    end.



default_stream_opts() ->
  #{active => true}.

accept_stream(Conn, Opts, Timeout) when is_list(Opts) ->
  accept_stream(Conn, maps:from_list(Opts), Timeout);
accept_stream(Conn, Opts, Timeout) when is_map(Opts) ->
  % @todo make_ref
  % @todo error handling
  NewOpts = maps:merge(default_stream_opts(), Opts),
  case quicer_nif:async_accept_stream(Conn, NewOpts) of
    {ok, Conn} ->
      receive
        {quic, new_stream, Stream} ->
          {ok, Stream};
        {quic, closed, Conn} ->
          {error, connection_closed}

      after Timeout ->
          {error, timeout}
      end;
    {error, _} = E ->
      E
  end.
