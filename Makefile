REBAR := rebar3

.PHONY: all
all: compile

.PHONY: default
default: build-nif

.PHONY: build-nif
build-nif:
	./build.sh 'v2.0.2'

compile:
	$(REBAR) compile

.PHONY: clean
clean: distclean

.PHONY: distclean
distclean:
	rebar3 unlock
	rm -rf _build erl_crash.dump rebar3.crashdump
	rm -rf c_build/*

.PHONY: xref
xref:
	$(REBAR) xref

.PHONY: eunit
eunit: compile
	$(REBAR) eunit verbose=truen

.PHONY: ct
ct:
	QUICER_USE_SNK=1 $(REBAR) as test ct -v

cover:
	$(REBAR) cover

.PHONY: dialyzer
dialyzer:
	$(REBAR) dialyzer

.PHONY: test
test: ct

.PHONY: check
check: clang-format

.PHONY: clang-format
clang-format:
	clang-format-11 --Werror --dry-run c_src/*

.PHONY: ci
ci: test dialyzer

.PHONY: tar
tar:
	$(REBAR) tar

.PHONY: doc
doc:
	rebar3 as doc ex_doc

.PHONY: publish
publish:
	rebar3 as doc hex publish
