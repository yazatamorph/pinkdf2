//// Gleam bindings to fast_pbkdf2 NIF of PBKDF2 (Password-Based Key Derivation Function 2) for Erlang.

import gleam/bit_array
import gleam/io

pub type Pbkdf2Keys {
  Pbkdf2Keys(raw: BitArray, base64: String)
}

pub type ShaDigestSize {
  Bits224
  Bits256
  Bits384
  Bits512
}

pub type Pbkdf2Algorithm {
  Sha2(ShaDigestSize)
  Sha3(ShaDigestSize)
  Sha224
  Sha256
  Sha384
  Sha512
}

pub type Pbkdf2Error {
  AllocFailed
  BadBlockCounter
  BadHash
  BadIterationCount
  BadPassword
  BadSalt
  CtxAllocationFailed
  CtxCopyFailed
  DigestFinalFailed
  DigestInitFailed
  DigestInitEx2Failed
  DigestUpdateFailed
  HmacInitFailed
}

/// Derives a key from a password and salt with default settings based on the
/// (OWASP recommendations)[https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2].
pub fn with_defaults(
  password: String,
  salt: String,
) -> Result(Pbkdf2Keys, Pbkdf2Error) {
  case fp_defaults(password, salt) {
    Ok(raw) -> Ok(Pbkdf2Keys(raw, bit_array.base64_encode(raw, False)))
    Error(e) -> Error(e)
  }
}

/// Derives a key using the provided configuration.
///
/// `iterations` is the number of times to run the algorithm. Must be a positive integer.
/// `d_len` is the target derived key length in bytes. Must be a positive integer.
///
/// ## Examples
///
/// ```gleam
/// import pinkdf2.{Sha512}
///
/// let salt = pinkdf2.get_salt()
/// let assert Ok(key) = pinkdf2.with_config(Sha512, "password", salt, 210_000, 32)
/// ```
pub fn with_config(
  alg: Pbkdf2Algorithm,
  password: String,
  salt: String,
  iterations: Int,
  d_len: Int,
) -> Result(Pbkdf2Keys, Pbkdf2Error) {
  case fp_config(alg, password, salt, iterations, d_len) {
    Ok(raw) -> Ok(Pbkdf2Keys(raw, bit_array.base64_encode(raw, False)))
    Error(e) -> Error(e)
  }
}

/// Generates a base64-encoded salt with a minimum size of 64 bytes.
/// It is provided here for convenience, but it is based on the same underlying Erlang function as `crypto.strong_rand_bytes`.
@external(erlang, "extern", "get_salt")
pub fn get_salt() -> String

@external(erlang, "extern", "fp_with_defaults")
fn fp_defaults(password: String, salt: String) -> Result(BitArray, Pbkdf2Error)

@external(erlang, "extern", "fp_with_config")
fn fp_config(
  alg: Pbkdf2Algorithm,
  password: String,
  salt: String,
  iterations: Int,
  d_len: Int,
) -> Result(BitArray, Pbkdf2Error)
