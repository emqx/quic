-module(rev).
-compile(export_all).
-compile(nowarn_export_all).

-include("../../include/quicer.hrl").

%% This is an example of how we can revert connections. This is especially
%% interesting when we want to connect to a device behind a NAT device.
%% Code behind the NAT device can do connect(), and following that the
%% code at the "top site" can do start_stream() to the device behind the NAT

%% To run:

%% To start the two servers, one supposdly running at a topsite, unable to
%% connect to the "down" site, which may run behind a NAT device
%% The other server, running at the NAT site, which executes the initial
%% connect to the top site.
%% Following that all streams are created in both directions on top of the
%% same Connection

%% 1> rev:start().

%% To test new streams going "down"
%% 2> rev:d_test().


%% To test new streams going "up"
%% 3> rev:u_test().



-define(INTERVAL, 3000).


start() ->
  application:ensure_all_started(quicer),
  register(nat_site, proc_lib:spawn_link(?MODULE, nat_site, [])),
  register(top_site, proc_lib:spawn_link(?MODULE, top_site, [])).


%% Test code

d_test() ->
  d_test(1).

d_test(N) ->
  L = lists:seq(1, N),
  Streams = [get_down_stream() || _N <- L],
  [ok= send_ping(5, S)|| S <- Streams],
  io:format("Closing streams \n",[]),
  [ok = quicer:close_stream(S) || S <- Streams],
  io:format("Streams closed \n",[]).


u_test() ->
  u_test(1).
u_test(N) ->
  L = lists:seq(1, N),
  Streams = [get_up_stream() || _N <- L],
  [ok = send_ping(5, U) || U <- Streams],
  io:format("Closing streams \n",[]),
  [ok = quicer:close_stream(U) || U <- Streams],
  io:format("Streams closed \n",[]).



send_and_close() ->
  S = get_down_stream(),
  quicer:send(S, <<"kalle ">>),
  quicer:async_close_stream(S),
  S2 = get_up_stream(),
  quicer:send(S2, <<"pelle ">>),
  quicer:async_close_stream(S2).


%% Top site code
%%

top_site() ->
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

  {ok, L} = quicer:listen(Port, LOptions),
  {ok, Conn} = quicer:accept(L, #{active => false}, infinity),
  {ok, Conn} = quicer:handshake(Conn),
  top_loop(Conn).


top_loop(Conn) ->
  {ok, Conn} = quicer:async_accept_stream(Conn, #{active => false}),
  top_loop2(Conn).

top_loop2(Conn) ->
  receive
    {quic, new_stream, Stream, _} ->
      H = proc_lib:spawn_link(
            fun() -> stream_handler0(Stream) end),
      ok = quicer:handoff_stream(Stream, H),
      top_loop(Conn);
    {From, get_down_stream} ->
      io:format("Starting stream downwards \n",[]),
      {ok, Stream} =
        quicer:start_stream(
          Conn,
          #{active => false,
            start_flag => ?QUIC_STREAM_START_FLAG_IMMEDIATE}),
      quicer:handoff_stream(Stream, From),
      From ! {top_site, Stream},
      top_loop2(Conn);
    {quic, closed, Conn, _} ->
      io:format("Top conn closed \n",[]);
    {quic, streams_available, _, _} ->
      %% ignore
      top_loop2(Conn)
  end.


get_down_stream() ->
  top_site ! {self(), get_down_stream},
  receive
    {handoff_done, Stream, _} ->
      ok = quicer:setopt(Stream, active, 2),
      Stream
  end.

%%%% site code
%%%%

c_opts() ->
  #{alpn => ["sample"],
    verify => none,
    keep_alive_interval_ms => ?INTERVAL,
    peer_bidi_stream_count => 64000,
    handshake_idle_timeout_ms => 3 * ?INTERVAL,
    idle_timeout_ms => 3 * ?INTERVAL}.

nat_site() ->
  Port = 4567,
  case quicer:connect("localhost", Port, c_opts(), 10000) of
    {ok, Conn} ->
      io:format("Entering site loop Conn = ~p\n",[Conn]),
      site_loop(Conn);
    _Err ->
      timer:sleep(1000),
      nat_site()
  end.

site_loop(Conn) ->
  {ok, Conn} = quicer:async_accept_stream(Conn, #{active => false}),
  site_loop2(Conn).

site_loop2(Conn) ->
  receive
    {quic, new_stream, Stream, _} ->
      io:format("New stream ~p~n", [Stream]),
      P = proc_lib:spawn_link(fun() ->
                                  stream_handler0(Stream)
                              end),
      ok = quicer:handoff_stream(Stream, P),
      site_loop(Conn);
    {From, new_up_stream} ->
      {ok, UpStream} =
        quicer:start_stream(
          Conn, #{active => false,
                  start_flag => ?QUIC_STREAM_START_FLAG_IMMEDIATE}),
      ok = quicer:handoff_stream(UpStream, From),
      site_loop2(Conn);
    {quic, closed, Conn, _} ->
      io:format("Conn closed \n",[]);
    {quic, streams_available, _,_ } ->
      site_loop2(Conn)
  end.

get_up_stream() ->
  nat_site ! { self(), new_up_stream},
  receive
    {handoff_done, Stream, _} ->
      ok = quicer:setopt(Stream, active, 2),
      Stream
  end.


%%%
%%% shared between top and site
%%%

stream_handler0(Stream) ->
  io:format("Entering stream handler for ~p\n",[Stream]),
  receive
    {handoff_done, Stream, _} ->
      ok = quicer:setopt(Stream, active, 2),
      stream_handler(Stream, 0),
      io:format("Leaving stream handler \n",[]),
      ok
  end.

stream_handler(S, N) ->
  receive
    {quic, passive, S, _} ->
      io:format("Setting active 2\n",[]),
      ok = quicer:setopt(S, active, 2),
      stream_handler(S, N);
    {quic, <<"ping">>, S,_} ->
      io:format("Handler got ping ~p \n",[N]),
      {ok, 4} = quicer:send(S, <<"pong">>),
      stream_handler(S, N+1);
    {quic, Data, S, _} when is_binary(Data) ->
      io:format("Handler got data ~p \n",[Data]),
      stream_handler(S, N);
    {quic, peer_send_shutdown, S, _} ->
      io:format("Handler got peer send shutdown \n",[]),
      quicer:async_shutdown_stream(S),
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
      io:format("Setting active 2 \n",[]),
      ok = quicer:setopt(S, active, 2),
      rec_pong(N, S);
    {quic, stream_closed, S, _} ->
      quicer:async_close_stream(S),
      closed
  end.

%%%_* Emacs ====================================================================
%%% Local Variables:
%%% erlang-indent-level: 2
%%% End:
