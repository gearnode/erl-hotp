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

-module(totp_tests).

-include_lib("eunit/include/eunit.hrl").

generate_test_() ->
  T = fun(Bin) -> calendar:rfc3339_to_system_time(Bin) end,
  Key = <<"12345678901234567890">>,
  Key2 = <<"12345678901234567890123456789012">>,
  Key3 =
    <<"1234567890123456789012345678901234567890123456789012345678901234">>,
  [?_assertEqual(94287082,
                 totp:generate(Key, T("1970-01-01T00:00:59Z"), #{size => 8})),
   ?_assertEqual(46119246,
                 totp:generate(Key2, T("1970-01-01T00:00:59Z"),
                               #{size => 8, algorithm => sha256})),
   ?_assertEqual(90693936,
                 totp:generate(Key3, T("1970-01-01T00:00:59Z"),
                               #{size => 8, algorithm => sha512})),
   ?_assertEqual(07081804,
                 totp:generate(Key, T("2005-03-18T01:58:29Z"), #{size => 8})),
   ?_assertEqual(68084774,
                 totp:generate(Key2, T("2005-03-18T01:58:29Z"),
                               #{size => 8, algorithm => sha256})),
   ?_assertEqual(25091201,
                 totp:generate(Key3, T("2005-03-18T01:58:29Z"),
                               #{size => 8, algorithm => sha512})),
   ?_assertEqual(14050471,
                 totp:generate(Key, T("2005-03-18T01:58:31Z"), #{size => 8})),

   ?_assertEqual(67062674,
                 totp:generate(Key2, T("2005-03-18T01:58:31Z"),
                               #{size => 8, algorithm => sha256})),
   ?_assertEqual(99943326,
                 totp:generate(Key3, T("2005-03-18T01:58:31Z"),
                               #{size => 8, algorithm => sha512})),
   ?_assertEqual(89005924,
                 totp:generate(Key, T("2009-02-13T23:31:30Z"), #{size => 8})),
   ?_assertEqual(91819424,
                 totp:generate(Key2, T("2009-02-13T23:31:30Z"),
                               #{size => 8, algorithm => sha256})),
   ?_assertEqual(93441116,
                 totp:generate(Key3, T("2009-02-13T23:31:30Z"),
                               #{size => 8, algorithm => sha512})),
   ?_assertEqual(69279037,
                 totp:generate(Key, T("2033-05-18T03:33:20Z"), #{size => 8})),
   ?_assertEqual(90698825,
                 totp:generate(Key2, T("2033-05-18T03:33:20Z"),
                               #{size => 8, algorithm => sha256})),
   ?_assertEqual(38618901,
                 totp:generate(Key3, T("2033-05-18T03:33:20Z"),
                               #{size => 8, algorithm => sha512})),
   ?_assertEqual(65353130,
                 totp:generate(Key, T("2603-10-11T11:33:20Z"), #{size => 8})),
   ?_assertEqual(77737706,
                 totp:generate(Key2, T("2603-10-11T11:33:20Z"),
                               #{size => 8, algorithm => sha256})),
   ?_assertEqual(47863826,
                 totp:generate(Key3, T("2603-10-11T11:33:20Z"),
                               #{size => 8, algorithm => sha512}))].

validate_test() ->
  Key = <<"12345678901234567890">>,
  State1 = totp:new_validator(Key, #{step => 10}),

  ?assertMatch({valid, _}, totp:validate(State1, 254676, 50)),
  ?assertMatch({valid, _}, totp:validate(State1, 254676, 59)),
  ?assertMatch({valid, _}, totp:validate(State1, 254676, 40)),
  ?assertMatch({valid, _}, totp:validate(State1, 254676, 69)),

  ?assertEqual(invalid, totp:validate(State1, 254676, 39)),
  ?assertEqual(invalid, totp:validate(State1, 254676, 70)),

  %% Cannot reuse the last code
  {valid, State2} = totp:validate(State1, 254676, 50),
  ?assertEqual(invalid, totp:validate(State2, 254676, 55)).

