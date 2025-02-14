-module(proxy_srv).

%% API
-export([
    start/0,
    exec/2
]).

-type proxy() :: {pid(), reference()}.

%%-- API ----------------------------------------------------------------------

-spec start() -> proxy().
start() ->
    Me = self(),
    spawn_monitor(fun() ->
        MRef = erlang:monitor(process, Me),
        proxy_loop(Me, MRef)
    end).

-spec exec(proxy(), function()) -> {ok, term()} | {error, timeout | {'DOWN', term()}}.
exec({Pid, Ref}, F) when is_function(F, 0) ->
    Request = make_ref(),
    Pid ! {exec, self(), Request, F},
    receive
        {exec_result, Request, Res} ->
            {ok, Res};
        {'DOWN', Ref, _, _, Reason} ->
            {error, {'DOWN', Reason}}
    after 5000 ->
        {error, timeout}
    end.

%%-- internals ----------------------------------------------------------------

proxy_loop(ParentPid, MRef) ->
    receive
        {exec, ParentPid, Ref, F} when is_function(F, 0) ->
            ParentPid ! {exec_result, Ref, F()},
            proxy_loop(ParentPid, MRef);
        {'DOWN', MRef, process, ParentPid, _} ->
            done
    end.
