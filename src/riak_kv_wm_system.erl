%% -------------------------------------------------------------------
%%
%% riak_kv_wm_system: simple Webmachine resource returning uptime and riak and otp versions
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

-module(riak_kv_wm_system).

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
    {['GET', 'OPTIONS'], wrq:set_resp_headers(riak_kv_wm_utils:cors_headers(), RD), Ctx}.

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
to_json(RD, Ctx) ->
    {mochijson2:encode(gather_info()), RD, Ctx}.

gather_info() ->
    {MS, _} = erlang:statistics(wall_clock),
    St = MS div 1000,
    S = St rem 60,
    Mt = St div 60,
    M = Mt rem 60,
    Ht = Mt div 60,
    H = Ht rem 24,
    Dt = Ht div 24,
    D = Dt,
    Str = case {D, H, M} of
              {A, _, _} when A > 0 -> io_lib:format("~b day~s, ~b hour~s, ~b minute~s, ~b sec", [D, s(D), H, s(H), M, s(M), S]);
              {_, A, _} when A > 0 -> io_lib:format("~b hour~s, ~b minute~s, ~b sec", [H, s(H), M, s(M), S]);
              {_, _, A} when A > 0 -> io_lib:format("~b minute~s, ~b sec", [M, s(M), S]);
              _ -> io_lib:format("~b sec", [S])
          end,
    #{riak_version => list_to_binary(riak_version()),
      system_version => list_to_binary(lists:droplast(erlang:system_info(system_version))),
      uptime => iolist_to_binary(Str)
     }.

s(1) -> "";
s(_) -> "s".

riak_version() ->
    element(2, lists:keyfind("riak", 1, release_handler:which_releases())).
