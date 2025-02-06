REBAR := $(shell which rebar3 2>/dev/null || which ./rebar3)

all: clean deps compile xref dialyzer lint

clean:
	${REBAR} clean

get-deps: deps

deps:
	${REBAR} get-deps

compile:
	${REBAR} compile

xref:
	${REBAR} xref

dialyzer:
	${REBAR} as test dialyzer

lint:
	$(REBAR) lint

tests:
	${REBAR} eunit

test.%: test/enoise_%_tests.erl
	$(REBAR) eunit --module enoise_$*_tests