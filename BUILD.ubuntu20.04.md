# BUILD on ubuntu 20.04

## Install build chain

```sh
sudo apt-add-repository ppa:lttng/stable-2.13
sudo apt-get update
sudo apt-get install -y lttng-tools lttng-modules-dkms babeltrace liblttng-ust-dev build-essential cmake
```

## Install OTP 
```
 wget https://packages.erlang-solutions.com/erlang/debian/pool/esl-erlang_24.3.3-1~ubuntu~focal_amd64.deb
 sudo apt install  ./esl-erlang_24.3.3-1~ubuntu~focal_amd64.deb
```

## Fetch rebar3

``` bash
wget https://s3.amazonaws.com/rebar3/rebar3 && chmod +x rebar3
export PATH=$PATH:./
```

## then 

```bash
make
```
