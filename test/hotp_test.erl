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

-module(hotp_test).

-include_lib("eunit/include/eunit.hrl").

generate_test_() ->
  %% Vector test imported from the RFC 4226 appendix D.
  Key = <<"12345678901234567890">>,
  Options = #{size => 6},
  [?_assertEqual(755224,
                 hotp:generate(Key, 0, Options)),
   ?_assertEqual(287082,
                 hotp:generate(Key, 1, Options)),
   ?_assertEqual(359152,
                 hotp:generate(Key, 2, Options)),
   ?_assertEqual(969429,
                 hotp:generate(Key, 3, Options)),
   ?_assertEqual(338314,
                 hotp:generate(Key, 4, Options)),
   ?_assertEqual(254676,
                 hotp:generate(Key, 5, Options)),
   ?_assertEqual(287922,
                 hotp:generate(Key, 6, Options)),
   ?_assertEqual(162583,
                 hotp:generate(Key, 7, Options)),
   ?_assertEqual(399871,
                 hotp:generate(Key, 8, Options)),
   ?_assertEqual(520489,
                 hotp:generate(Key, 9, Options))].

validate_test() ->
  Key = <<"12345678901234567890">>,
  State = hotp:new_validator(Key, #{look_ahead => 2}),

  {Valid1, State1} = hotp:validate(State, 123456),
  ?assertEqual(invalid, Valid1),
  ?assertMatch(#{counter := 0}, State1),
  
  {Valid2, State2} = hotp:validate(State1, 287082),
  ?assertEqual(valid, Valid2),
  ?assertMatch(#{counter := 1}, State2),

  %% As the previous code has be valid it must not be valid anymore.
  {Valid3, State3} = hotp:validate(State2, 287082),
  ?assertEqual(invalid, Valid3),
  ?assertMatch(#{counter := 1}, State3),

  {Valid4, State4} = hotp:validate(State3, 359152),
  ?assertEqual(valid, Valid4),
  ?assertMatch(#{counter := 2}, State4),

  %% As look ahead is set to 2, the code must be valid and the counter must be
  %% set to 5.
  {Valid5, State5} = hotp:validate(State4, 254676),
  ?assertEqual(valid, Valid5),
  ?assertMatch(#{counter := 5}, State5),

  {Valid6, State6} = hotp:validate(State5, 338314),
  ?assertEqual(invalid, Valid6),
  ?assertMatch(#{counter := 5}, State6),

  {Valid7, State7} = hotp:validate(State6, 254676),
  ?assertEqual(invalid, Valid7),
  ?assertMatch(#{counter := 5}, State7),

  {Valid8, State8} = hotp:validate(State7, 520489),
  ?assertEqual(invalid, Valid8),
  ?assertMatch(#{counter := 5}, State8).
