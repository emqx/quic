-module(quicer_server_stream_callback).
-export([ new_stream/2
        , handle_stream_data/4
        , shutdown/1
        ]).

new_stream(_Stream, _Opts) ->
    InitState = #{sent_bytes => 0},
    {ok, InitState}.

handle_stream_data(Stream, Bin, _Opts, #{sent_bytes := Cnt} = State) ->
    {ok, Size} = quicer:send(Stream, Bin),
    {ok, State#{ sent_bytes => Cnt + Size}}.

shutdown(Stream) ->
    quicer:async_close_stream(Stream).
