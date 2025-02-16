-module(extern).

-export([fp_with_defaults/2, get_salt/0]).

fp_with_defaults(Password, Salt) ->
  fast_pbkdf2:pbkdf2(sha256, Password, Salt, 600_000, 32).

get_salt() ->
  <<Num:32/integer>> = crypto:strong_rand_bytes(4),
  BytesNum = Num rem (1024 - 64) + 64,
  Raw = crypto:strong_rand_bytes(BytesNum),
  base64:encode(Raw).
