-module(extern).

-export([fp_with_defaults/2, fp_with_config/5, get_salt/0]).

fp_with_defaults(Password, Salt) ->
  case fast_pbkdf2:pbkdf2(sha256, Password, Salt, 600_000, 32) of
    {error, Reason} ->
      {error, Reason};
    Binary ->
      {ok, Binary}
  end.

fp_with_config(Algorithm, Password, Salt, Iterations, DerivedKeyLength) ->
  case fast_pbkdf2:pbkdf2(convert_algorithm(Algorithm),
                          Password,
                          Salt,
                          Iterations,
                          DerivedKeyLength)
  of
    {error, Reason} ->
      {error, Reason};
    Binary ->
      {ok, Binary}
  end.

get_salt() ->
  <<Num:32/integer>> = crypto:strong_rand_bytes(4),
  BytesNum = Num rem (1024 - 64) + 64,
  Raw = crypto:strong_rand_bytes(BytesNum),
  base64:encode(Raw).

convert_algorithm(Algorithm) ->
  case Algorithm of
    {sha3, bits224} ->
      sha3_224;
    {sha3, bits256} ->
      sha3_256;
    {sha3, bits384} ->
      sha3_384;
    {sha3, bits512} ->
      sha3_512;
    {sha2, bits224} ->
      sha224;
    {sha2, bits256} ->
      sha256;
    {sha2, bits384} ->
      sha384;
    {sha2, bits512} ->
      sha512;
    _ ->
      Algorithm
  end.
