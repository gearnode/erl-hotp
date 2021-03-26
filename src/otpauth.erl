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

-module(otpauth).

-export([generate/7]).

-export_type([type/0, key/0, password_size/0, algorithm/0, issuer/0,
              account/0]).

-type type() :: hotp | totp.
-type key() :: hotp:key() | totp:key().
-type password_size() :: hotp:password_size() | totp:password_size().
-type algorithm() :: hotp:hmac_algorithms().
-type issuer() :: binary().
-type account() :: binary().

-spec generate(type(), key(), password_size(), algorithm(), issuer(),
               account(), uri:query()) -> binary().
generate(Type, Key, Size, Algorithm, Issuer, Account, Parameters) ->
  Query0 = [{<<"secret">>, base32:encode(Key, [nopad])},
            {<<"issuer">>, Issuer},
            {<<"algorithm">>, algorithm_to_binary(Algorithm)},
            {<<"digits">>, integer_to_binary(Size)}],
  Query = Query0 ++ Parameters,
  Label = io_lib:format("/~s:~s", [Issuer, Account]),
  URI = #{scheme => <<"otpauth">>, host => atom_to_binary(Type),
          path => iolist_to_binary(Label), query => Query},
  uri:serialize(URI).

-spec algorithm_to_binary(algorithm()) -> binary().
algorithm_to_binary(sha) ->
  <<"SHA1">>;
algorithm_to_binary(sha256) ->
  <<"SHA256">>;
algorithm_to_binary(sha512) ->
  <<"SHA512">>.
