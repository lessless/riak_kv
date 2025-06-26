%% -------------------------------------------------------------------
%%
%% riak_kv_wm_cluster: a Webmachine resource for cluster ops
%%
%% Copyright (c) 2025 TI Tokyo.  All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------

-module(riak_kv_wm_cluster).

%% webmachine resource exports
-export([
         init/1,
         service_available/2,
         allowed_methods/2,
         content_types_provided/2,
         is_authorized/2,
         options/2,
         to_json/2
        ]).

-include_lib("webmachine/include/webmachine.hrl").
-include_lib("kernel/include/logger.hrl").

init([]) ->
    {ok, undefined}.

-spec service_available(#wm_reqdata{}, undefined) -> {boolean(), #wm_reqdata{}, undefined}.
service_available(RD, Ctx) ->
    {true, wrq:set_resp_headers(riak_kv_wm_utils:cors_headers(), RD), Ctx}.

-spec allowed_methods(#wm_reqdata{}, undefined) -> {[atom()], #wm_reqdata{}, undefined}.
allowed_methods(RD, Ctx) ->
    {['OPTIONS', 'GET', 'POST'], wrq:set_resp_headers(riak_kv_wm_utils:cors_headers(), RD), Ctx}.

-spec options(#wm_reqdata{}, undefined) -> {[{string(), string()}], #wm_reqdata{}, undefined}.
options(RD, Ctx) ->
    {riak_kv_wm_utils:cors_headers(), RD, Ctx}.

is_authorized(ReqData, Ctx) ->
    case riak_api_web_security:is_authorized(ReqData) of
        false ->
            {"Basic realm=\"Riak\"", ReqData, Ctx};
        {true, _SecContext} ->
            {true, ReqData, Ctx};
        insecure ->
            {{halt, 426}, wrq:append_to_resp_body(<<"Security is enabled and "
                    "Riak does not accept credentials over HTTP. Try HTTPS "
                    "instead.">>, ReqData), Ctx}
    end.

content_types_provided(RD, Ctx) ->
    {[{"application/json", to_json}], RD, Ctx}.

-spec to_json(#wm_reqdata{}, undefined) -> {binary(), #wm_reqdata{}, undefined}.
to_json(RD, Context) ->
    {ok, RawNodes} = get_nodes(),

    Nodes = [jsonify_node(Node) || Node <- RawNodes],
    Encoded = mochijson2:encode({struct, [{nodes, Nodes}]}),

    {Encoded, ReqData, Context}.

-record(member_info, {node        :: atom(),
                      status      :: undefined | status(),
                      reachable   :: boolean(),
                      vnodes      :: vnodes(),
                      handoffs    :: handoffs(),
                      ring_pct    :: undefined | float(),
                      pending_pct :: undefined | float(),
                      mem_total   :: undefined | integer(),
                      mem_used    :: undefined | integer(),
                      mem_erlang  :: undefined | integer(),
                      action      :: undefined | action(),
                      replacement :: node()
                     }).

get_nodes() ->
    {ok, Ring} = riak_core_ring_manager:get_my_ring(),
    Members = riak_core_ring:all_member_status(Ring),
    [get_member_info(M, Ring) || M <- Members].

get_member_info({Node, Status}, Ring) ->
    RingSize = riak_core_ring:num_partitions(Ring),

    Indices = riak_core_ring:indices(Ring, Node),
    FutureIndices = riak_core_ring:future_indices(Ring, Node),
    PctRing = length(Indices) / RingSize,
    PctPending = length(FutureIndices) / RingSize,

    %% try and get a list of all the vnodes running on the node
    try rpc:call(Node, riak_control_session, get_my_info, []) of
        {badrpc,nodedown} ->
            ?MEMBER_INFO{node = Node,
                         status = Status,
                         reachable = false,
                         vnodes = [],
                         handoffs = [],
                         ring_pct = PctRing,
                         pending_pct = PctPending};
        {badrpc,_Reason} ->
            ?MEMBER_INFO{node = Node,
                         status = incompatible,
                         reachable = true,
                         vnodes = [],
                         handoffs = [],
                         ring_pct = PctRing,
                         pending_pct = PctPending};
        MemberInfo = ?MEMBER_INFO{} ->
            MemberInfo?MEMBER_INFO{status = Status,
                                   ring_pct = PctRing,
                                   pending_pct = PctPending};
        MemberInfo0 = #member_info{} ->
            %% Upgrade older member information record.
            MemberInfo = upgrade_member_info(MemberInfo0),
            MemberInfo?MEMBER_INFO{status = Status,
                                   ring_pct = PctRing,
                                   pending_pct = PctPending};
        _ ->
            %% default case where a record incompatibility causes a
            %% failure matching the record format.
            ?MEMBER_INFO{node = Node,
                         status = incompatible,
                         reachable = true,
                         vnodes = [],
                         handoffs = [],
                         ring_pct = PctRing,
                         pending_pct = PctPending}
    catch
        exit:R ->
            logger:warning("rpc:call(~p, riak_control_session, get_my_info, []) failed with reason: ~p", [Node, R]),
            ?MEMBER_INFO{node = Node,
                         status = Status,
                         reachable = false,
                         vnodes = [],
                         handoffs = [],
                         ring_pct = PctRing,
                         pending_pct = PctPending}
    end.


%% @doc Turn a node into a proper struct for serialization.
-spec jsonify_node(member()) -> {struct, list()}.
jsonify_node(Node) ->
    LWM = 0.1,
    MemUsed = Node?MEMBER_INFO.mem_used,
    MemTotal = Node?MEMBER_INFO.mem_total,
    Reachable = Node?MEMBER_INFO.reachable,
    LowMem = low_mem(Reachable, MemUsed, MemTotal, LWM),
    {struct,[{"name",Node?MEMBER_INFO.node},
             {"status",Node?MEMBER_INFO.status},
             {"reachable",Reachable},
             {"ring_pct",Node?MEMBER_INFO.ring_pct},
             {"pending_pct",Node?MEMBER_INFO.pending_pct},
             {"mem_total",MemTotal},
             {"mem_used",MemUsed},
             {"mem_erlang",Node?MEMBER_INFO.mem_erlang},
             {"low_mem",LowMem},
             {"me",Node?MEMBER_INFO.node == node()},
             {"action",Node?MEMBER_INFO.action},
             {"replacement",Node?MEMBER_INFO.replacement}]}.

%% @doc Determine if a node has low memory.
-spec low_mem(boolean(), number() | atom(), number() | atom(), number())
    -> boolean().
low_mem(Reachable, MemUsed, MemTotal, LWM) ->
    case Reachable of
        false ->
            false;
        true ->
            %% There is a race where the node is online, but memsup is
            %% still starting so memory is unavailable.
            case MemTotal of
                undefined ->
                    false;
                _ ->
                    1.0 - (MemUsed/MemTotal) < LWM
            end
    end.
