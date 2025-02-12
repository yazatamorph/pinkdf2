import gleam/bit_array
import gleam/bytes_tree.{type BytesTree}
import gleam/crypto.{type HashAlgorithm}
import gleam/int
import gleam/io

pub type Pbkdf2Keys {
  Pbkdf2Keys(raw: BitArray, base64: String)
}

pub fn main() {
  io.println("Hello from pbkdf2!")
  let hash = sha256("password")
  io.debug(hash)
}

pub fn sha256(password: String, salt: BitArray) -> Pbkdf2Keys {
  let raw = with_defaults(crypto.Sha256, password, salt, 600_000)
  Pbkdf2Keys(raw, bit_array.base64_encode(raw, True))
}

pub fn hash(
  alg: HashAlgorithm,
  password: String,
  salt: BitArray,
  iterations: Int,
  d_len: Int,
) {
  todo as "Should check alg is allowed and d_len not too long, then run compute_key as normal"
}

@external(erlang, "extern", "get_salt")
pub fn get_salt() -> BitArray

fn with_defaults(
  alg: HashAlgorithm,
  password: String,
  salt: BitArray,
  iterations: Int,
) {
  let prf = new_prf(alg)
  let d_len = prf(<<"derived":utf8>>, <<"length":utf8>>) |> bit_array.byte_size

  compute_key(
    prf,
    bit_array.from_string(password),
    salt,
    iterations,
    d_len,
    1,
    bytes_tree.new(),
  )
}

fn compute_key(
  prf,
  password: BitArray,
  salt: BitArray,
  iterations: Int,
  d_len: Int,
  block_idx: Int,
  acc: BytesTree,
) {
  case bytes_tree.byte_size(acc) > d_len {
    True -> {
      let bit_len = d_len * 8
      let assert <<key:bits-size(bit_len), _rest:bits>> =
        bytes_tree.to_bit_array(acc)
      key
    }
    False -> {
      let block =
        compute_block(
          prf,
          password,
          salt,
          iterations,
          block_idx,
          1,
          bytes_tree.new(),
          bytes_tree.new(),
        )
      compute_key(
        prf,
        password,
        salt,
        iterations,
        d_len,
        block_idx + 1,
        bytes_tree.prepend_tree(to: acc, prefix: block),
      )
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
  prev: BytesTree,
  acc: BytesTree,
) {
  case count {
    count if count > iterations -> acc
    1 -> {
      let init =
        prf(password, <<salt:bits, block_idx:int-big-size(32)>>)
        |> bytes_tree.from_bit_array
      compute_block(prf, password, salt, iterations, block_idx, 2, init, init)
    }
    _ -> {
      let next =
        prf(password, bytes_tree.to_bit_array(prev))
        |> bytes_tree.from_bit_array
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

fn new_prf(alg: HashAlgorithm) {
  fn(key: BitArray, data: BitArray) {
    crypto.new_hasher(alg)
    |> crypto.hash_chunk(key)
    |> crypto.hash_chunk(data)
    |> crypto.digest
  }
}

fn max_key_length() -> Int {
  int.bitwise_shift_left(1, 32) |> int.subtract(1)
}

fn d_len_too_long(hash_len: Int, d_len: Int) -> Bool {
  let max_len =
    max_key_length()
    |> int.multiply(hash_len)
  d_len > max_len
}

fn allowed_algorithm(alg: HashAlgorithm) -> Result(HashAlgorithm, String) {
  case alg {
    crypto.Md5 ->
      Error(
        "Insecure algorithm. Please select Sha224, Sha256, Sha384, or Sha512.",
      )
    crypto.Sha1 ->
      Error(
        "Insecure algorithm. Please select Sha224, Sha256, Sha384, or Sha512.",
      )
    _ -> Ok(alg)
  }
}

@external(erlang, "crypto", "exor")
fn xor(a: BytesTree, b: BytesTree) -> BytesTree
