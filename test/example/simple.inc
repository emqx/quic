
[global fail_pattern=[Ee][Rr][Rr][Oo][Rr]]
[global eprompt=\(s|c@.*\)\d*>]

[shell server]
    !erl -sname s -pa ../../_build/default/lib/quicer/ebin -s qt s
    ?$eprompt


[shell client]
    !erl -sname c -pa ../../_build/default/lib/quicer/ebin
    ?$eprompt
    !qt:c().
    ?-->
    !connect.
    ?Connection
    ?-->

[shell server]
    ?Handshake ok

[shell client]
    !{stream, 1}.
    ?Stream

[shell server]
    ?Enter recv_ping for 1:1

[shell client]
    !{ping, 1}.
    ?Got pong
    ?-->


# Local Variables:
# mode: lux
# End: