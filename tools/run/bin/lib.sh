#!/usr/bin/env sh
export QUICER_USE_SNK=1
REBAR3=$(command -v rebar3)

# Since cerl returns different code:root_dir(), we need to override it here
# Erlang_OTP_ROOT_DIR will be picked up by CMakeLists.txt
export Erlang_OTP_ROOT_DIR=$(dirname $(dirname $(which erl)))

# Set ERL_TOP for Suppressions list
export ERL_TOP=$(cerl -noshell -eval "io:format(\"~s\", [code:root_dir()])" -s erlang halt)

do_run() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <all|one_by_one|proper|...>"
        exit 1
    fi

    case $1 in
        all)
            escript "$REBAR3" ct
            ;;
        one_by_one)
            AllTCs=$(erl -pa _build/test/lib/quicer/test/  -noshell \
                -eval 'io:format("~p", [lists:flatten( string:join(lists:map(fun erlang:atom_to_list/1, quicer_SUITE:all()), " ") )]), halt()')
            for tc in ${AllTCs};
            do
                echo "running tc $tc";
                escript "$REBAR3" do ct --suite=test/quicer_SUITE --case="$tc";
            done
            ;;
        proper)
            escript "$REBAR3" as test proper
            ;;
        *)
            escript "$REBAR3" $@
            ;;
    esac
}
