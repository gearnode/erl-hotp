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

-module(totp).

-export([generate/1, generate/2, generate/3,
         new_validator/1, new_validator/2]).

-export_type([key/0, password/0, password_size/0,
              timestamp/0,
              validator_state/0]).

-type key() :: hotp:key().
-type password() :: hotp:password().
-type password_size() :: hotp:password_size().
-type timestamp() :: integer().

-type validator_state() :: #{key := key(),
                             size := password_size(),
                             initial_time := timestamp(),
                             step := pos_integer(),
                             look_behind := non_neg_integer(),
                             look_ahead := non_neg_integer(),
                             last_time_period => non_neg_integer()}.

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
                            step => pos_integer(),
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
          when Options :: #{}.
new_validator(Key, Options) ->
  #{key => Key,
    size => maps:get(size, Options, 6),
    step => maps:get(step, Options, 30),
    initial_time => maps:get(initial_time, Options, 0),
    look_behind => maps:get(look_behind, Options, 1),
    look_ahead => maps:get(look_ahead, Options, 1)}.
