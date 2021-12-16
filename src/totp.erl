%% Copyright (c) 2021 Exograd SAS.
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

-module(totp).

-export([generate/1, generate/2, generate/3,
         new_validator/1, new_validator/2,
         validate/2, validate/3,
         otpauth_uri/3]).

-export_type([key/0, password/0, password_size/0,
              timestamp/0, step/0,
              validator_state/0]).

-type key() :: hotp:key().
-type password() :: hotp:password().
-type password_size() :: hotp:password_size().
-type timestamp() :: integer().
-type step() :: pos_integer().

-opaque validator_state() :: #{key := key(),
                               size := password_size(),
                               initial_time := timestamp(),
                               step := step(),
                               algorithm := hotp:hmac_algorithms(),
                               look_behind := non_neg_integer(),
                               look_ahead := non_neg_integer(),
                               last_period => non_neg_integer()}.

-spec generate(key()) ->
        password().
generate(Key) ->
  generate(Key, os:system_time(second), #{}).

-spec generate(key(), timestamp()) ->
        password().
generate(Key, CurrentTime) ->
  generate(Key, CurrentTime, #{}).

-spec generate(key(), timestamp(), Options) ->
        password()
          when Options :: #{size => password_size(),
                            step => step(),
                            initial_time => timestamp(),
                            algorithm => hotp:hmac_algorithms()}.
generate(Key, CurrentTime, Options) ->
  Size = maps:get(size, Options, 6),
  Algorithm = maps:get(algorithm, Options, sha),
  Step = maps:get(step, Options, 30),
  InitialTime = maps:get(initial_time, Options, 0),
  TimePeriod = time_period(CurrentTime, InitialTime, Step),
  hotp:generate(Key, TimePeriod, #{size => Size, algorithm => Algorithm}).

-spec time_period(timestamp(), timestamp(), integer()) ->
        non_neg_integer().
time_period(CurrentTime, InitialTime, Step) ->
  trunc(math:floor(CurrentTime - InitialTime) / Step).

-spec new_validator(key()) ->
        validator_state().
new_validator(Key) ->
  new_validator(Key, #{}).

-spec new_validator(key(), Options) ->
        validator_state()
          when Options :: #{size => password_size(),
                            step => step(),
                            algorithm => hotp:hmac_algorithms(),
                            initial_time => timestamp(),
                            look_behind => non_neg_integer(),
                            look_ahead => non_neg_integer()}.
new_validator(Key, Options) ->
  #{key => Key,
    size => maps:get(size, Options, 6),
    step => maps:get(step, Options, 30),
    algorithm => maps:get(algorithm, Options, sha),
    initial_time => maps:get(initial_time, Options, 0),
    look_behind => maps:get(look_behind, Options, 1),
    look_ahead => maps:get(look_ahead, Options, 1)}.

-spec validate(validator_state(), password()) ->
        {valid, validator_state()} | invalid.
validate(State, Password) ->
  validate(State, Password, os:system_time(second)).

-spec validate(validator_state(), password(), timestamp()) ->
        {valid, validator_state()} | invalid.
validate(#{initial_time := InitialTime, step := Step, size := Size,
           look_behind := LookBehind, look_ahead := LookAhead,
           algorithm := Algorithm, key := Key} = State,
         Password, CurrentTime) ->
  LastPeriod = maps:get(last_period, State, none),
  TimePeriod = time_period(CurrentTime, InitialTime, Step),
  if
    LastPeriod =:= TimePeriod ->
      invalid;
    true ->
      PossiblePeriods =
        lists:seq(TimePeriod - LookBehind, TimePeriod + LookAhead),
      IsValidPassword =
        fun(Period) ->
            hotp:generate(Key, Period, #{size => Size, algorithm => Algorithm})
              =:= Password
        end,
      case lists:search(IsValidPassword, PossiblePeriods) of
        false ->
          invalid;
        {value, NewLastPeriod} ->
          State1 = State#{last_period => NewLastPeriod},
          {valid, State1}
      end
  end.

-spec otpauth_uri(validator_state(), binary(), binary()) ->
        binary().
otpauth_uri(#{key := Key, size := Size, step := Step, algorithm := Algorithm},
            Issuer, Account) ->
  Parameters = [{<<"period">>, integer_to_binary(Step)}],
  otpauth:generate(totp, Key, Size, Algorithm, Issuer, Account, Parameters).
