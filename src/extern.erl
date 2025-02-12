-module(extern).

-export([get_salt/0]).

get_salt() ->
  <<Num:32/integer>> = crypto:strong_rand_bytes(4),
  BytesNum = Num rem (1024 - 64) + 64,
  crypto:strong_rand_bytes(BytesNum).
