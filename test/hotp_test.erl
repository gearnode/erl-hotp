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
  [?_assertEqual(755224,
                 hotp:generate(Key, 0, 6)),
   ?_assertEqual(287082,
                 hotp:generate(Key, 1, 6)),
   ?_assertEqual(359152,
                 hotp:generate(Key, 2, 6)),
   ?_assertEqual(969429,
                 hotp:generate(Key, 3, 6)),
   ?_assertEqual(338314,
                 hotp:generate(Key, 4, 6)),
   ?_assertEqual(254676,
                 hotp:generate(Key, 5, 6)),
   ?_assertEqual(287922,
                 hotp:generate(Key, 6, 6)),
   ?_assertEqual(162583,
                 hotp:generate(Key, 7, 6)),
   ?_assertEqual(399871,
                 hotp:generate(Key, 8, 6)),
   ?_assertEqual(520489,
                 hotp:generate(Key, 9, 6))].
