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
    {ok, Ring} = riak_core_ring_manager:get_my_ring(),
    Claimant = riak_core_ring:claimant(Ring),
    Nodes = get_nodes(),

    Current = [jsonify_node(Node, Claimant) || Node <- Nodes],

    Planned =
        case get_plan() of
            {error, Error} ->
                Error;
            {ok, [], _Claim} ->
                [];
            {ok, Changes, Claim} ->
                merge_transitions(Nodes, Changes, Claim, Claimant)
        end,

    Clusters = [{current, Current}, {staged, Planned}],

    {mochijson2:encode(Clusters), RD, Context}.

merge_transitions(Nodes, Changes, Claim, Claimant) ->
    [jsonify_node(apply_changes(Node, Changes, Claim), Claimant)
     || Node <- Nodes].

apply_changes(Node, Changes, Claim) ->
    apply_status_change(apply_claim_change(Node, Claim), Changes).

apply_status_change(Node, Changes) ->
    Name = proplists:get_value(node, Node),
    case proplists:get_value(Name, Changes) of
        false ->
            Node;
        {_, {Action, Replacement}} ->
            Node ++ [{action, Action}, {replacement, Replacement}];
        {_, Action} ->
            Node ++ [{action, Action}]
    end.

apply_claim_change(Node, Claim) ->
    Name = proplists:get_value(node, Node),
    case lists:keyfind(Name, 1, Claim) of
        false ->
            N1 = lists:keyreplace(ring_pct, 1, Node, {ring_pct, 0.0}),
            lists:keyreplace(pending_pct, 1, N1, {pending_pct, 0.0});
        {_, {_, Future}} ->
            %% @doc Hack until core returns normalized values.
            Normalized = if
                Future > 0 ->
                    Future / 100;
                true ->
                    Future
            end,
            N1 = lists:keyreplace(ring_pct, 1, Node, {ring_pct, Normalized}),
            lists:keyreplace(pending_pct, 1, N1, {pending_pct, Normalized})
    end.

jsonify_node(Node, Claimant) ->
    LWM = 0.1,
    MemUsed = proplists:get_value(mem_used, Node),
    MemTotal = proplists:get_value(mem_total, Node),
    Reachable = proplists:get_value(reachable, Node),
    LowMem = low_mem(Reachable, MemUsed, MemTotal, LWM),
    {struct,[{"name", proplists:get_value(node, Node)},
             {"status", proplists:get_value(status, Node)},
             {"reachable", Reachable},
             {"ring_pct", proplists:get_value(ring_pct, Node)},
             {"pending_pct", proplists:get_value(pending_pct, Node)},
             {"mem_total", MemTotal},
             {"mem_used", MemUsed},
             {"mem_erlang", proplists:get_value(mem_erlang, Node)},
             {"low_mem", LowMem},
             {"me", proplists:get_value(node, Node) == node()},
             {"claimant", proplists:get_value(node, Node) == Claimant},
             {"action", proplists:get_value(action, Node)},
             {"replacement", proplists:get_value(replacement, Node)}]}.



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

    case rpc:call(Node, riak_kv_util, node_info_for_riak_control, []) of
        {badrpc, nodedown} ->
            [{node, Node},
             {status, down}];
        MemberInfo ->
            MemberInfo ++ [{node, Node},
                           {status, Status},
                           {ring_pct, PctRing},
                           {pending_pct, PctPending}
                          ]
    end.

low_mem(_Reachable = false, _, _, _) ->
    0.0;
low_mem(true, MemUsed, MemTotal, LWM) ->
    case MemTotal of
        undefined ->
            false;
        _ ->
            1.0 - (MemUsed/MemTotal) < LWM
    end.


get_plan() ->
    try riak_core_claimant:plan() of
        {error, Error} ->
            {error, Error};
        {ok, Changes, NextRings} ->
            case Changes of
                [] ->
                    {ok, [], []};
                _ ->
                    {ok, Changes, compute_final_ring_claim(NextRings)}
            end
    catch
        _:_ ->
            {error, unknown}
    end.

compute_final_ring_claim(Rings) ->
    {_, FinalRing} = lists:last(Rings),
    nodes_and_claim_percentages(FinalRing).

nodes_and_claim_percentages(Ring) ->
    Nodes = lists:keysort(2, riak_core_ring:all_member_status(Ring)),
    [{Name, riak_core_console:pending_claim_percentage(Ring, Name)} ||
        {Name, _} <- Nodes].
