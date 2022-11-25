-module(rev).
-compile(export_all).
-compile(nowarn_export_all).

-include("../../include/quicer.hrl").

%% This is an axample of how we can revert connections. This is especially
%% interesting when we want to connect to a device behind a NAT device.
%% Code behind the NAT device can do connect(), and following that the
%% code at the "top site" can do start_stream() to the device behind the NAT

%% To run:

%% > Top = rev:start().
%% > Top ! connect.
%% > Top ! connect.


-define(INTERVAL, 3000).


start() ->
    application:ensure_all_started(quicer),
    _C = proc_lib:spawn_link(fun() ->
                                     nat_site()
                             end),

    Top = proc_lib:spawn_link(fun() ->
                                      top_site()
                              end),
    Top.

top_site() ->
    Port = 4567,
    LOptions = [ {cert, "./server.pem"}
               , {key,  "./server.key"}
               , {verify, none}
               , {active, false}
               , {handshake_idle_timeout_ms, 3 * ?INTERVAL}
               , {keep_alive_interval_ms, ?INTERVAL}
               , {alpn, ["sample"]}
               , {idle_timeout_ms, 3 *?INTERVAL}
               , {peer_bidi_stream_count, 64000}
               ],

    {ok, L} = quicer:listen(Port, LOptions),
    {ok, Conn} = quicer:accept(L, [{active, false}], infinity),
    {ok, Conn} = quicer:handshake(Conn),
    r_loop(Conn).

r_loop(Conn) ->
    receive
        connect ->
            io:format("Starting stream downwards \n",[]),
            {ok, S} = quicer:start_stream(Conn, [{active, false}]),
            ok = quicer:setopt(S, active, 20),
            ok = send_ping(5, S),
            io:format("Closing stream \n",[]),
            ok = quicer:close_stream(S),
            io:format("Stream closed \n",[])
    end,
    r_loop(Conn).


nat_site() ->
    Port = 4567,
    case quicer:connect("localhost", Port,
                        [{alpn, ["sample"]},
                         {verify, none},
                         {peer_bidi_stream_count, 64000},
                         {keep_alive_interval_ms, ?INTERVAL},
                         {handshake_idle_timeout_ms, 3 * ?INTERVAL},
                         {idle_timeout_ms, 3 * ?INTERVAL}],
                        10000) of
        {ok, Conn} ->
            a_loop(Conn);
        _Err ->
            timer:sleep(10),
            nat_site()
    end.

a_loop(Conn) ->
    {ok, Stream} = quicer:accept_stream(Conn, [{active, false}]),
    P = proc_lib:spawn_link(fun() ->
                                    stream_handler0(Stream)
                            end),
    ok = quicer:controlling_process(Stream, P),
    P ! continue,
    a_loop(Conn).


stream_handler0(Stream) ->
    io:format("Entering stream handler for ~p\n",[Stream]),
    receive
        continue ->
            ok = quicer:setopt(Stream, active, 20),
            stream_handler(Stream, 0),
            io:format("Leaving stream handler \n",[]),
            ok
    end.

stream_handler(S, N) ->
    receive
        {quic, passive, S, _} ->
            io:format("Setting active 20\n",[]),
            ok = quicer:setopt(S, active, 20),
            stream_handler(S, N);
        {quic, <<"ping">>, S,_} ->
            io:format("Handler got ping ~p \n",[N]),
            {ok, 4} = quicer:send(S, <<"pong">>),
            stream_handler(S, N+1);
        {quic, peer_send_shutdown, S, _} ->
            io:format("Handler got peer send shutdown \n",[]),
            quicer:shutdown_stream(S),
            closed;
        {quic, stream_closed, S, _X} ->
            io:format("Handler got close stream \n",[]),
            quicer:async_close_stream(S),
            closed
    end.

send_ping(0, _) ->
    ok;
send_ping(N, S) ->
    io:format("Sending ping \n",[]),
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
