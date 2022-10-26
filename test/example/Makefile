
all:	certs
	erlc *.erl


certs:
	erlc ../certs.erl
	erl -noshell -s qt certs

clean:
	rm -rf *.beam *~ lux_logs *.key *.pem *.csr *.srl

lux:
	lux .
