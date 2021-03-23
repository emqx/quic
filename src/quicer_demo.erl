-module(quicer_demo).
-export([ echo_server/1
        , client/2
        ]
       ).

echo_server(Port) ->
  DataDir = "test/quicer_SUITE_data",
  ListenerOpts = [ {cert, filename:join(DataDir, "cert.pem")}
                 , {key,  filename:join(DataDir, "key.pem")}],
  {ok, L} = quicer:listen(Port, ListenerOpts),
  Workers = lists:map(fun(_)->
                    spawn_monitor(fun() -> echo_server_acceptor(L) end)
            end,
            lists:seq(1, 128)),
  {L, Workers}.

echo_server_acceptor(L) ->
    case quicer:accept(L, [], 5000) of
        {error, timeout} -> echo_server_acceptor(L);
        {ok, Conn} ->
            spawn_link(fun() ->
                               echo_server_stm_acceptor(Conn)
                       end),
            echo_server_acceptor(L)
    end.

echo_server_stm_acceptor(Conn) ->
    case quicer:accept_stream(Conn, []) of
        {error, timeout} -> echo_server_stm_acceptor(Conn);
        {ok, Stm} ->
            echo_server_stm_echo(Stm)
    end,


    echo_server_stm_acceptor(Conn).

echo_server_stm_echo(Stm) ->
  receive
    {quic, Bin, Stm, _, _, _} ->
      quicer:send(Stm, Bin)
  end.


client(Port, Msg) ->
    {ok, Conn} = quicer:connect("localhost", Port, [], 3000),
    [spawn_link( fun() -> client_stream(Conn, Msg ++ Suffix) end)||
      Suffix <- ["a", "b", "c"]
     ],
    Stats = quicer:getstats(Conn, [send_cnt, recv_cnt, recv_oct, send_oct]),
    io:format("Connection stats ~p ~n", [Stats]),
    quicer:close_connection(Conn).

client_stream(Conn, Msg) ->
    {ok, Stream} = quicer:start_stream(Conn, []),
    {ok, StreamId} = quicer:get_stream_id(Stream),
    {ok, SName} = quicer:sockname(Stream),
    {ok, PName} = quicer:peername(Stream),
    {ok, Len} = quicer:send(Stream, list_to_binary(pid_to_list(self()) ++ Msg)),
    receive
        {quic, Bin, Stream, _, _, _} -> Bin
    end,
    io:format("~p Stream: ~p (~p) : received ~p, Len: ~p from ~p ~n",
              [self(), StreamId, SName, Bin, Len, PName]),
    quicer:close_stream(Stream),
    ok.
