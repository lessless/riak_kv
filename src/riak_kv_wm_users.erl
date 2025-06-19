%% -------------------------------------------------------------------
%%
%% riak_kv_wm_users: Webmachine resource exposing security users
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

-module(riak_kv_wm_users).

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

-define(TOMBSTONE, '$deleted').

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
    Users_ = riak_core_metadata:fold(
               fun({_Username, [?TOMBSTONE]}, Acc) ->
                       Acc;
                  ({Username, Options}, Acc) ->
                       [{Username, Options}|Acc]
               end, [], {<<"security">>, <<"users">>}),
    Users =
        [ begin
              PasswordOptions = proplists:get_value("password", Options, []),
              PwdHash = proplists:get_value(hash_pass, PasswordOptions, <<"--">>),
              Groups = proplists:get_value("groups", Options, []),
              OtherOptions = maps:from_list([{unicode:characters_to_binary(K, utf8),
                                              unicode:characters_to_binary(V, utf8)}
                                             || {K, V} <- Options,
                                                K /= "password",
                                                K /= "groups"]),
              #{name => Name,
                password_hash => PwdHash,
                groups => Groups,
                options => OtherOptions}
          end || {Name, [Options]} <- Users_ ],
    ?LOG_INFO("Users: ~p", [Users]),
    {mochijson2:encode(Users), RD, Ctx}.

