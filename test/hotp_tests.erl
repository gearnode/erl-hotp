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

-module(hotp_tests).

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
  State1 = hotp:new_validator(Key, #{look_ahead => 2}),

  ?assertEqual(invalid, hotp:validate(State1, 123456)),

  {Valid2, State2} = hotp:validate(State1, 287082),
  ?assertEqual(valid, Valid2),
  ?assertMatch(#{counter := 1}, State2),

  %% As the previous code has be valid it must not be valid anymore.
  ?assertEqual(invalid,  hotp:validate(State2, 287082)),
  ?assertMatch(#{counter := 1}, State2),

  {Valid3, State3} = hotp:validate(State2, 359152),
  ?assertEqual(valid, Valid3),
  ?assertMatch(#{counter := 2}, State3),

  %% As look ahead is set to 2, the code must be valid and the counter must be
  %% set to 5.
  {Valid4, State4} = hotp:validate(State3, 254676),
  ?assertEqual(valid, Valid4),
  ?assertMatch(#{counter := 5}, State4),

  ?assertEqual(invalid, hotp:validate(State4, 338314)),

  ?assertEqual(invalid, hotp:validate(State4, 254676)),

  ?assertEqual(invalid, hotp:validate(State4, 520489)).

otpauth_uri_test() ->
  Key = <<"12345">>,
  State = hotp:new_validator(Key, #{size => 8}),
  Issuer = <<"Exograd">>,
  Account = <<"bryan@frimin.fr">>,
  URI = hotp:otpauth_uri(State, Issuer, Account),
  ?assertEqual(<<"otpauth://hotp/Exograd:bryan@frimin.fr?secret=GEZDGNBV&issuer=Exograd&algorithm=SHA1&digits=8&counter=0">>, URI).
