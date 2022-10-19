%%%----------------------------------------------------------------------
%%% File    : user_default.erl
%%% Author  : Martin Bjorklund <mbj@bluetail.com>
%%% Purpose : Nice shell features.
%%% Created : 24 Feb 2000 by Martin Bjorklund <mbj@bluetail.com>
%%%----------------------------------------------------------------------

-module(user_default).

%% process info
-export([i/0, i/1, i/3, ni/0, ci/0, ci/3, cni/0, fi/1]).
-export([i2/0, fi2/1]).
%% process backtrace
-export([bt/1, bt/3]).
%% full process display
-export([dp/1, fdp/3]).
%% port info
-export([pi/0, pi/1, pi/2, pi2/0]).
%% memory info
-export([mi/0, fmi/1]).
%% trace dbg shortcuts
-export([tp/1, tp/2, tpl/1, tpl/2]).
%% distibuted lm()
-export([dlm/0]).
%% pretty print term
-export([p/1]).

-import(lists, [filter/2, foreach/2, flatmap/2]).

%% internal export
-export([dlm0/0]).

p(Term) ->
    io:format("~p\n", [Term]).

%% Good ol' i() but includes zooombie support
i() -> i_1(fun io:format/2, processes(), fun i_2/2).
ni() -> i_1(fun io:format/2, all_procs(), fun i_2/2).

fi(FmtF) -> i_1(FmtF, processes(), fun i_2/2).

i2() -> i_1(fun io:format/2, processes(), fun i2_2/2).
fi2(FmtF) -> i_1(FmtF, processes(), fun i2_2/2).



i(Pid) when is_pid(Pid) -> pinfo(Pid);
i(Name) when is_atom(Name) ->
    case whereis(Name) of
        undefined -> undefined;
        Pid -> i(Pid)
    end.

i(X,Y,Z) ->
    i(c:pid(X,Y,Z)).

%% If you like the new one
ci() ->
    c:i().

ci(X,Y,Z) ->
    c:i(X,Y,Z).

cni() ->
    c:ni().

%% Memory Info
mi() ->
    fmi(fun io:format/2).

fmi(FmtF) ->
    Fmt = "~-15s ~15s\n",
    FmtF(Fmt, ["TYPE", "USED"]),
    lists:foreach(
      fun({Type, Bytes}) ->
              FmtF(Fmt, [atom_to_list(Type), fmt_bytes(Bytes)])
      end, lists:keysort(2, erlang:memory())).

-define(Ki, 1024).
-define(Mi, (1024*?Ki)).
-define(Gi, (1024*?Mi)).
-define(Ti, (1024*?Gi)).

fmt_bytes(B) ->
    fmt_bytes(B, 2).
fmt_bytes(B, FractionDigits) ->
    if B < ?Ki ->
            [integer_to_binary(B), <<" B">>];
       B < ?Mi ->
            [fmt_decimal(B / ?Ki, FractionDigits), " KiB"];
       B < ?Gi ->
            [fmt_decimal(B / ?Mi, FractionDigits), " MiB"];
       B < ?Ti ->
            [fmt_decimal(B / ?Gi, FractionDigits), " GiB"];
       true ->
            [fmt_decimal(B / ?Ti, FractionDigits), " TiB"]
    end.

fmt_decimal(D, FractionDigits) ->
    string:strip(
      string:strip(
        io_lib:format("~.*f", [FractionDigits, D]),
        right, $0),
      right, $.).

%% Code modified from c.erl
i_1(FmtF, Ps, ContF) ->
    Alive = filter(fun palive/1, Ps),
    ContF(FmtF, Alive),
    case filter(fun pzombie/1, Ps) of
        [] ->
            ok;
        Zombies ->
            %% Zombies is not the same as Ps-Alive, since the remote
            %% process that fetched Ps is included among Alive, but has
            %% exited (for ni/0).
            FmtF("\nDead processes:\n", []),
            ContF(FmtF, Zombies)
    end.

i_2(FmtF, Ps) ->
    iformat(FmtF, "PID", "INITIAL CALL", "CURRENT FUNCTION", "REDS", "MSGS"),
    {Reds,Msgs} =
        lists:foldl(
          fun(P, Acc) -> display_info(FmtF, P, Acc) end,
          {0,0},
          Ps),
    iformat(FmtF, "TOTAL", "", "", "REDS", "MSGS"),
    iformat(FmtF, "", "", "", fmt_int(Reds), io_lib:write(Msgs)).


i2_2(FmtF, Ps) ->
    iformat2(FmtF, "PID", "REGISTERED NAME",
             "INITIAL CALL", "CURRENT FUNCTION", "REDS", "MSGS",
             "LNKS", "MONS", "HEAP[B]", "TOTHEAP[B]",
             "STACK[B]", "MEM[B]"),
    WSz = erlang:system_info(wordsize),
    {Reds,Msgs,Links,Monitors,Heap,TotHeap,Stack,Mem} =
        lists:foldl(
          fun(P, Acc) -> display_info2(FmtF, P, WSz, Acc) end,
          {0,0,0,0,0,0,0,0},
          Ps),
    iformat2(FmtF, "TOTAL", "", "", "", "REDS", "MSGS",
             "LNKS", "MONS", "HEAP[B]", "TOTHEAP[B]",
             "STACK[B]", "MEM[B]"),
    iformat2(FmtF, "", "", "", "", fmt_int(Reds), integer_to_list(Msgs),
             integer_to_list(Links), integer_to_list(Monitors),
             fmt_int(Heap), fmt_int(TotHeap), fmt_int(Stack),
             fmt_int(Mem)).

fmt_int(Int) when is_integer(Int) ->
    L0 = integer_to_list(Int),
    if Int < 1000 ->
            L0;
       true ->
            L1 = lists:reverse(L0),
            lists:reverse(add_(L1))
    end.

fmt_int0(0) -> "-";
fmt_int0(Int) -> integer_to_list(Int).

add_([A,B,C,D|T]) ->
    [A,B,C,$_ | add_([D|T])];
add_(L) ->
    L.

palive(Pid) ->
    case pinfo(Pid, status) of
        undefined         -> false;
        {status, exiting} -> false;
        _                 -> true
    end.

pzombie(Pid) ->
    case pinfo(Pid, status) of
        undefined         -> false;
        {status, exiting} -> true;
        _                 -> false
    end.

pinfo([]) ->
    undefined;
pinfo(Pid) ->
    Base =
        case is_alive() of
            true -> rpc:call(node(Pid), erlang, process_info, [Pid]);
            false -> process_info(Pid)
        end,
    if Base == undefined ->
            undefined;
       true ->
            try
                Monitors = pinfo(Pid, monitors),
                MonitoredBy = pinfo(Pid, monitored_by),
                Messages = pinfo(Pid, messages),
                Stack = pinfo(Pid, current_stacktrace),
                Base ++ [Monitors, MonitoredBy, Messages, Stack]
            catch
                _:_ ->
                    %% if the process disapperead
                    Base
            end
    end.

pinfo(Pid, Item) ->
    case is_alive() of
        true -> rpc:call(node(Pid), erlang, process_info, [Pid, Item]);
        false -> process_info(Pid, Item)
    end.

all_procs() ->
    case is_alive() of
        true -> flatmap(fun (N) -> rpc:call(N, erlang, processes, []) end,
                        [node() | nodes()]);
        false -> processes()
    end.

display_info(FmtF, Pid, {R,M}) ->
    case pinfo(Pid) of
        undefined ->
            {R, M};
        Info ->
            Call = initial_call(Info),
            Curr = fetch(current_function, Info),
            Reds = fetch(reductions, Info),
            LM = fetch(message_queue_len, Info),
            iformat(FmtF,
                    io_lib:write(Pid),
                    mfa_string(Call),
                    mfa_string(Curr),
                    fmt_int(Reds),
                    fmt_int0(LM)),
            {R+Reds, M+LM}
    end.

display_info2(FmtF, Pid, WSz, {R,M,L,Mo,H,T,S,Me} = Acc) ->
    case
        {pinfo(Pid),
         pinfo(Pid, total_heap_size),
         pinfo(Pid, memory)}
    of
        {Info, {_, TotHeap0}, {_, Mem}} ->
            Reg = case fetch(registered_name, Info) of
                      0 -> "";
                      Reg0 -> Reg0
                  end,
            Call = initial_call(Info),
            Curr = fetch(current_function, Info),
            Reds = fetch(reductions, Info),
            LM = fetch(message_queue_len, Info),
            Links = length(fetch(links, Info)),
            Monitors = length(fetch(monitors, Info)),
            Stack = WSz * fetch(stack_size, Info),
            Heap = WSz * fetch(heap_size, Info),
            TotHeap = WSz * TotHeap0,
            iformat2(FmtF,
                     io_lib:write(Pid),
                     Reg,
                     mfa_string(Call),
                     mfa_string(Curr),
                     fmt_int(Reds),
                     fmt_int0(LM),
                     fmt_int0(Links),
                     fmt_int0(Monitors),
                     fmt_int(Heap),
                     fmt_int(TotHeap),
                     fmt_int(Stack),
                     fmt_int(Mem)),
            {R+Reds, M+LM, L+Links, Mo+Monitors,
             H+Heap, T+TotHeap, S+Stack, Me+Mem};
        _ ->
            Acc
    end.

%% We can do some assumptions about the initial call.
%% If the initial call is proc_lib:init_p/5 we can find more information
%% by calling the function proc_lib:translate_initial_call/1.
initial_call(Info)  ->
    case fetch(initial_call, Info) of
        {proc_lib, init_p, 5} ->
            proc_lib:translate_initial_call(Info);
        ICall ->
            ICall
    end.

mfa_string({M, F, A}) ->
    io_lib:format("~w:~w/~w", [M, F, A]);
mfa_string(X) ->
    io_lib:write(X).

fetch(Key, Info) ->
    case lists:keysearch(Key, 1, Info) of
        {value, {_, Val}} -> Val;
        false -> 0
    end.

iformat(FmtF, A1, A2, A3, A4, A5) ->
    FmtF("~-12s ~-22s ~-22s ~15s ~4s\n", [A1,A2,A3,A4,A5]).

iformat2(FmtF, A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11) ->
    FmtF("~-12s ~-23s ~-23s ~-23s ~15s ~4s ~4s ~4s ~12s ~12s ~12s ~12s\n",
         [A0,A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11]).

%% Port info
%% I don't really know which info is most relevent, so I included
%% both pi() and pi2().
pi() ->
    piformat("ID", "NAME", "CONNECTED", "INITIAL CALL", "CURRENT FUNCTION"),
    do_pi(fun(Info) ->
                  Id = fetch(id, Info),
                  Name = fetch(name, Info),
                  case fetch(connected, Info) of
                      Pid when is_pid(Pid) ->
                          {ICall, Curr} =
                              case pinfo(Pid) of
                                  undefined ->
                                      {[], []};
                                  ProcInfo ->
                                      {initial_call(ProcInfo),
                                       fetch(current_function, ProcInfo)}
                              end,
                          piformat(io_lib:write(Id),
                                   Name,
                                   io_lib:write(Pid),
                                   mfa_string(ICall),
                                   mfa_string(Curr));
                      Port when is_port(Port) ->
                          piformat(io_lib:write(Id),
                                   Name,
                                   io_lib:write(Port),
                                   "","")
                  end
          end).

piformat(A1, A2, A3, A4, A5) ->
    io:format("~-6s ~-10s ~-12s ~-23s ~-23s\n", [A1,A2,A3,A4,A5]).

pi2() ->
    pi2format("ID", "NAME", "CONNECTED", "RECV", "SENT"),
    do_pi(fun(Info) ->
                  Id = fetch(id, Info),
                  Name = fetch(name, Info),
                  Pid = fetch(connected, Info),
                  Recv = fetch(input, Info),
                  Sent = fetch(output, Info),
                  pi2format(io_lib:write(Id),
                           Name,
                           io_lib:write(Pid),
                           io_lib:write(Recv),
                           io_lib:write(Sent))
          end).

pi2format(A1, A2, A3, A4, A5) ->
    io:format("~-6s ~-20s ~-12s ~-10s ~-10s\n", [A1,A2,A3,A4,A5]).

do_pi(Print) ->
    foreach(
      fun(P) ->
              case erlang:port_info(P) of
                  undefined ->
                      ok;
                  Info ->
                      Print(Info)
              end
      end, erlang:ports()).


pi(Id) ->
    pi_l(erlang:ports(), Id).

pi_l([P | Ps], Id) ->
    case erlang:port_info(P, id) of
        {id, Id} ->
            erlang:port_info(P);
        _ ->
            pi_l(Ps, Id)
    end;
pi_l([], _Id) ->
    undefined.


pi(X,Y) ->
    PStr = lists:flatten(io_lib:format("#Port<~w.~w>", [X,Y])),
    pi_l2(erlang:ports(), PStr).

pi_l2([P | Ps], PStr) ->
    case lists:flatten(io_lib:format("~w", [P])) of
        PStr ->
            erlang:port_info(P);
        _ ->
            pi_l2(Ps, PStr)
    end;
pi_l2([], _PStr) ->
    undefined.

bt(Pid) when is_pid(Pid) ->
    case pinfo(Pid, backtrace) of
        {backtrace, Bin} ->
            io:format("~s\n", [binary_to_list(Bin)]);
        _ ->
            undefined
    end;
bt(Name) when is_atom(Name) ->
    case whereis(Name) of
        undefined -> undefined;
        Pid -> bt(Pid)
    end.

bt(X,Y,Z) ->
    bt(c:pid(X,Y,Z)).


%% trace external calls
tp(Mod) ->
    case whereis(dbg) of
        undefined ->
            dbg:tracer();
        _ ->
            ok
    end,
    _ = dbg:tp(Mod, []),
    dbg:p(all, c).

tp(Mod, Pid) ->
    case whereis(dbg) of
        undefined ->
            dbg:tracer();
        _ ->
            ok
    end,
    _ = dbg:tp(Mod, []),
    dbg:p(Pid, c).

%% trace internal calls
tpl(Mod) ->
    case whereis(dbg) of
        undefined ->
            dbg:tracer();
        _ ->
            ok
    end,
    _ = dbg:tpl(Mod, []),
    dbg:p(all, c).

tpl(Mod, Pid) ->
    case whereis(dbg) of
        undefined ->
            dbg:tracer();
        _ ->
            ok
    end,
    _ = dbg:tpl(Mod, []),
    dbg:p(Pid, c).

dlm() ->
    rpc:multicall([node() | nodes()], ?MODULE, dlm0, []).

dlm0() ->
    {node(), c:lm()}.

dp(P) ->
    fdp(fun io:format/2, P, "").

%% truncate backtraces that are larger than this
-define(LARGE_BT, 16384).
-define(MAX_MESSAGES, 500).

fdp(FmtF, Name, Header) when is_atom(Name) ->
    case whereis(Name) of
        undefined -> undefined;
        Pid -> fdp(FmtF, Pid, Header)
    end;
fdp(FmtF, P, Header) when is_pid(P) ->
    case process_info(P, messages) of
        {_, AllMsgs} ->
            NAllMsgs = length(AllMsgs),
            Msgs = lists:sublist(AllMsgs, ?MAX_MESSAGES), % print max 500 msgs
            {_, Mem} =  process_info(P, memory),
            RegStr =
                case process_info(P, registered_name) of
                    {_, RegName} when is_atom(RegName) -> atom_to_list(RegName);
                    _ -> ""
                end,
            FmtF("** ~s~s ~s msgs: ~4w mem: ~s~n",
                 [Header, pid_to_list(P), RegStr, NAllMsgs, fmt_bytes(Mem)]),
            FmtF("MESSAGES:~n", []),
            lists:foreach(
              fun(Msg) ->
                      FmtF("  ~p~n", [Msg])
              end, Msgs),
            if NAllMsgs > ?MAX_MESSAGES ->
                    FmtF("  ...~n", []);
               true ->
                    ok
            end,
            FmtF("STACKTRACE:~n", []),
            {_, St} = process_info(P, current_stacktrace),
            FmtF("~p~n~n", [St]),
            FmtF("BACKTRACE:~n", []),
            {_, Bt0} = process_info(P, backtrace),
            Bt = if byte_size(Bt0) > ?LARGE_BT ->
                         [binary:part(Bt0, 0, ?LARGE_BT), "...\n"];
                    true ->
                         Bt0
                 end,
            FmtF("~s~n~n", [Bt]);
        undefined ->
            %% process dead
            FmtF("** ~s~s NOT RUNNING~n", [Header, pid_to_list(P)])
    end.
