REBAR := rebar3

.PHONY: all
all: compile

.PHONY: default
default: build-nif

.PHONY: build-nif
build-nif:
	./build.sh 'v2.1.3'

compile:
	$(REBAR) compile

.PHONY: clean
clean: distclean

.PHONY: distclean
distclean:
	$(REBAR) unlock --all
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

.PHONY: cover
cover:
	mkdir -p coverage
	QUICER_TEST_COVER=1 QUICER_USE_SNK=1 $(REBAR) as test ct --cover -v
	$(REBAR) cover
	lcov -c  --directory c_build/CMakeFiles/quicer_nif.dir/c_src/ \
	--output-file ./coverage/lcov.info

.PHONY: cover-html
cover-html: cover
	genhtml -o coverage/ coverage/lcov.info

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
	$(REBAR) as doc ex_doc

.PHONY: publish
publish:
	$(REBAR) as doc hex publish
