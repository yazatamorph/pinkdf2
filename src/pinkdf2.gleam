//// Password-Based Key Derivation Function 2 in Gleam for Erlang as defined in RFC 2898
//// https://datatracker.ietf.org/doc/html/rfc2898

import gleam/bit_array
import gleam/crypto.{type HashAlgorithm}
import gleam/int

pub type Pbkdf2Keys {
  Pbkdf2Keys(raw: BitArray, base64: String)
}

pub type Pbkdf2Error {
  UnsupportedAlgorithm(String)
  KeyDerivedLengthTooLong
}

/// Derives a key from a password and salt with default settings based on the
/// (OWASP recommendations)[https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2].
pub fn with_defaults(
  password: String,
  salt: String,
) -> Result(Pbkdf2Keys, Pbkdf2Error) {
  let raw =
    with_defaults_(crypto.Sha256, <<password:utf8>>, <<salt:utf8>>, 600_000)
  Ok(Pbkdf2Keys(raw, bit_array.base64_encode(raw, False)))
}

/// Derives a key using the provided configuration.
///
/// `alg` may be any algorithm from `crypto.HashAlgorithm` except for `Md5` and `Sha1`.
/// 'd_len' is the targeted derived key length in bytes.
///
/// ## Examples
///
/// ```gleam
/// import gleam/crypto
/// import pinkdf2
///
/// let salt = pinkdf2.get_salt()
/// let assert Ok(key) = pinkdf2.with_config(crypto.Sha512, "password", salt, 210_000, 32)
/// ```
pub fn with_config(
  alg: HashAlgorithm,
  password: String,
  salt: String,
  iterations: Int,
  d_len: Int,
) -> Result(Pbkdf2Keys, Pbkdf2Error) {
  case allowed_algorithm(alg) {
    Error(e) -> Error(e)
    Ok(_) -> {
      let prf = new_prf(alg)
      case
        d_len_too_long(
          prf(<<password:utf8>>, <<salt:utf8>>) |> bit_array.byte_size,
          d_len,
        )
      {
        True -> Error(KeyDerivedLengthTooLong)
        False -> {
          let raw =
            compute_key(
              prf,
              <<password:utf8>>,
              <<salt:utf8>>,
              iterations,
              d_len,
              1,
              <<>>,
            )
          Ok(Pbkdf2Keys(raw, bit_array.base64_encode(raw, False)))
        }
      }
    }
  }
}

/// Generates a base64-encoded salt with a minimum size of 64 bytes.
/// It is provided here for convenience, but it is based on the same underlying Erlang function as `crypto.strong_rand_bytes`.
@external(erlang, "extern", "get_salt")
pub fn get_salt() -> String

fn with_defaults_(
  alg: HashAlgorithm,
  password: BitArray,
  salt: BitArray,
  iterations: Int,
) -> BitArray {
  let prf = new_prf(alg)
  let d_len = prf(password, salt) |> bit_array.byte_size
  compute_key(prf, password, salt, iterations, d_len, 1, <<>>)
}

fn compute_key(
  prf,
  password: BitArray,
  salt: BitArray,
  iterations: Int,
  d_len: Int,
  block_idx: Int,
  acc: BitArray,
) -> BitArray {
  case bit_array.byte_size(acc) > d_len {
    True -> {
      let bit_len = d_len * 8
      let assert <<key:bits-size(bit_len), _rest:bits>> = acc
      key
    }
    False -> {
      let block =
        compute_block(prf, password, salt, iterations, block_idx, 1, <<>>, <<>>)
      compute_key(prf, password, salt, iterations, d_len, block_idx + 1, <<
        block:bits,
        acc:bits,
      >>)
    }
  }
}

fn compute_block(
  prf,
  password: BitArray,
  salt: BitArray,
  iterations: Int,
  block_idx: Int,
  count: Int,
  prev: BitArray,
  acc: BitArray,
) -> BitArray {
  case count {
    count if count > iterations -> acc
    1 -> {
      let init = prf(password, <<salt:bits, block_idx:int-big-size(32)>>)
      compute_block(prf, password, salt, iterations, block_idx, 2, init, init)
    }
    _ -> {
      let next = prf(password, prev)
      compute_block(
        prf,
        password,
        salt,
        iterations,
        block_idx,
        count + 1,
        next,
        xor(next, acc),
      )
    }
  }
}

fn new_prf(alg: HashAlgorithm) -> fn(BitArray, BitArray) -> BitArray {
  fn(key: BitArray, data: BitArray) { crypto.hmac(data, alg, key) }
}

fn max_key_length() -> Int {
  int.bitwise_shift_left(1, 32) |> int.subtract(1)
}

fn d_len_too_long(h_len: Int, d_len: Int) -> Bool {
  let max_len =
    max_key_length()
    |> int.multiply(h_len)
  d_len > max_len
}

fn allowed_algorithm(alg: HashAlgorithm) -> Result(HashAlgorithm, Pbkdf2Error) {
  case alg {
    crypto.Md5 ->
      Error(UnsupportedAlgorithm(
        "Insecure algorithm. Please select Sha224, Sha256, Sha384, or Sha512.",
      ))
    crypto.Sha1 ->
      Error(UnsupportedAlgorithm(
        "Insecure algorithm. Please select Sha224, Sha256, Sha384, or Sha512.",
      ))
    _ -> Ok(alg)
  }
}

@external(erlang, "crypto", "exor")
fn xor(a: BitArray, b: BitArray) -> BitArray
