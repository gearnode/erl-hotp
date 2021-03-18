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

-export([generate/3]).

-spec generate(binary(), non_neg_integer(), pos_integer()) ->
        non_neg_integer().
generate(Key, Counter, Digit) ->
  truncate(crypto:mac(hmac, sha, Key, <<Counter:64>>), Digit).

-spec truncate(binary(), pos_integer()) ->
        non_neg_integer().
truncate(HMACResult, Size) ->
  Offset = binary:at(HMACResult, 19) band 16#0f,
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
