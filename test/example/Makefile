
all:
	erlc *.erl
	make certs

certs:
	erlc ../quicer_test_lib.erl
	erl -noshell -s qt certs

clean:
	rm -rf *.beam *~ lux_logs *.key *.pem *.csr *.srl *.dump

lux:
	lux .


server:
	erl -sname s -pa ../../_build/default/lib/quicer/ebin -s qt s
client:
	erl -sname c -pa ../../_build/default/lib/quicer/ebin

rev:
	erl -pa ../../_build/default/lib/quicer/ebin -s rev
