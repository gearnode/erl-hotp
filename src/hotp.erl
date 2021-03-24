%% Copyright (c) 2021 Bryan Frimin <bryan@frimin.fr>.
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
%% SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
%% IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(hotp).

-export([generate/2, generate/3,
         new_validator/1, new_validator/2,
         validate/2]).

-export_type([key/0, counter/0, password/0, password_size/0,
              hmac_algorithms/0,
              validator_state/0]).

-type key() :: binary().
-type counter() :: non_neg_integer().
-type password() :: non_neg_integer().
-type password_size() :: pos_integer().
-type hmac_algorithms() :: sha | sha256 | sha512.

-opaque validator_state() :: #{key := key(),
                               counter := counter(),
                               algorithm := hmac_algorithms(),
                               size := pos_integer(),
                               look_ahead := non_neg_integer()}.

-spec generate(key(), counter()) ->
        password().
generate(Key, Counter) ->
  generate(Key, Counter, #{}).

-spec generate(key(), counter(), Options) ->
        password()
          when Options :: #{size => password_size(),
                            algorithm => hmac_algorithms()}.
generate(Key, Counter, Options) ->
  Size = maps:get(size, Options, 6),
  Algorithm = maps:get(algorithm, Options, sha),
  truncate(crypto:mac(hmac, Algorithm, Key, <<Counter:64>>), Size).

-spec truncate(binary(), password_size()) ->
        password().
truncate(HMACResult, Size) ->
  Offset = binary:at(HMACResult, byte_size(HMACResult) - 1) band 16#0f,
  S0 = (binary:at(HMACResult, Offset) band 16#7f) bsl 24,
  S1 = (binary:at(HMACResult, Offset + 1) band 16#ff) bsl 16,
  S2 = (binary:at(HMACResult, Offset + 2) band 16#ff) bsl 8,
  S3 = (binary:at(HMACResult, Offset + 3) band 16#ff),
  (S0 bor S1 bor S2 bor S3) rem pow10(Size).

-spec pow10(non_neg_integer()) ->
        pos_integer().
pow10(N) when N > 0 ->
  pow10(N, 1).

-spec pow10(non_neg_integer(), non_neg_integer()) ->
        pos_integer().
pow10(0, Acc) ->
  Acc;
pow10(N, Acc) ->
  pow10(N - 1, Acc * 10).

-spec new_validator(key()) ->
        validator_state().
new_validator(Key) ->
  new_validator(Key, #{}).

-spec new_validator(key(), Options) ->
        validator_state()
          when Options :: #{counter => counter(),
                            size => password_size(),
                            look_ahead => non_neg_integer()}.
new_validator(Key, Options) ->
  #{key => Key,
    counter => maps:get(counter, Options, 0),
    size => maps:get(size, Options, 6),
    algorithm => maps:get(algorithm, Options, sha),
    look_ahead => maps:get(look_ahead, Options, 5)}.

-spec validate(validator_state(), password()) ->
        {valid, validator_state()} | invalid.
validate(#{key := Key, size := Size, counter := Counter0,
           algorithm := Algorithm, look_ahead := LookAhead} = State,
         Password) ->
  IsValidPassword =
    fun(C) ->
        generate(Key, C, #{size => Size, algorithm => Algorithm}) =:= Password
    end,
  Counter = Counter0 + 1,
  PossibleCounters = lists:seq(Counter, Counter + LookAhead),
  case lists:search(IsValidPassword, PossibleCounters) of
    false ->
      invalid;
    {value, NewCounter} ->
      State1 = State#{counter => NewCounter},
      {valid, State1}
  end.
