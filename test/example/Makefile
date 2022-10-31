
all:
	erlc *.erl
	make certs

certs:
	erlc ../quicer_test_lib.erl
	erl -noshell -s qt certs

clean:
	rm -rf *.beam *~ lux_logs *.key *.pem *.csr *.srl

lux:
	lux .
