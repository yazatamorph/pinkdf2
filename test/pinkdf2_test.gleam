import gleam/bit_array
import gleeunit
import gleeunit/should
import pinkdf2.{Bits224, Bits256, Bits384, Bits512, Sha2, Sha256, Sha3}

pub fn main() {
  gleeunit.main()
}

// These test cases are lifted directly from Go's implementation
// https://github.com/golang/crypto/blob/master/pbkdf2/pbkdf2_test.go
// They were apparently originally crowdsourced from Stack Overflow
// http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors

pub fn sha256_vector_1_test() {
  let raw_should = <<
    0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56,
    0xc4, 0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9,
  >>
  let base64_should = bit_array.base64_encode(raw_should, False)

  let assert Ok(keys) = pinkdf2.with_config(Sha256, "password", "salt", 1, 20)
  #(keys.raw, keys.base64)
  |> should.equal(#(raw_should, base64_should))
}

pub fn sha256_vector_2_test() {
  let raw_should = <<
    0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28,
    0xf0, 0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e,
  >>
  let base64_should = bit_array.base64_encode(raw_should, False)

  let assert Ok(keys) = pinkdf2.with_config(Sha256, "password", "salt", 2, 20)
  #(keys.raw, keys.base64)
  |> should.equal(#(raw_should, base64_should))
}

pub fn sha256_vector_3_test() {
  let raw_should = <<
    0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84,
    0x5c, 0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0,
  >>
  let base64_should = bit_array.base64_encode(raw_should, False)

  let assert Ok(keys) =
    pinkdf2.with_config(Sha256, "password", "salt", 4096, 20)
  #(keys.raw, keys.base64)
  |> should.equal(#(raw_should, base64_should))
}

pub fn sha256_vector_4_test() {
  let raw_should = <<
    0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f, 0x32, 0xd8, 0x14, 0xb8, 0x11,
    0x6e, 0x84, 0xcf, 0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18, 0x1c,
  >>
  let base64_should = bit_array.base64_encode(raw_should, False)

  let assert Ok(keys) =
    pinkdf2.with_config(
      Sha256,
      "passwordPASSWORDpassword",
      "saltSALTsaltSALTsaltSALTsaltSALTsalt",
      4096,
      25,
    )
  #(keys.raw, keys.base64)
  |> should.equal(#(raw_should, base64_should))
}

pub fn sha256_vector_5_test() {
  let raw_should = <<
    0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89, 0x3c, 0x69, 0x62, 0x26, 0x65,
    0x0a, 0x86, 0x87,
  >>
  let base64_should = bit_array.base64_encode(raw_should, False)

  let assert Ok(keys) =
    pinkdf2.with_config(Sha256, "pass\u{000}word", "sa\u{000}lt", 4096, 16)
  #(keys.raw, keys.base64)
  |> should.equal(#(raw_should, base64_should))
}

pub fn sha2_bits224_test() {
  pinkdf2.with_config(Sha2(Bits224), "password", "salt", 1, 16)
  |> should.be_ok
}

pub fn sha2_bits256_test() {
  pinkdf2.with_config(Sha2(Bits256), "password", "salt", 1, 16)
  |> should.be_ok
}

pub fn sha2_bits384_test() {
  pinkdf2.with_config(Sha2(Bits384), "password", "salt", 1, 16)
  |> should.be_ok
}

pub fn sha2_bits512_test() {
  pinkdf2.with_config(Sha2(Bits512), "password", "salt", 1, 16)
  |> should.be_ok
}

pub fn sha3_bits224_test() {
  pinkdf2.with_config(Sha3(Bits224), "password", "salt", 1, 16)
  |> should.be_ok
}

pub fn sha3_bits256_test() {
  pinkdf2.with_config(Sha3(Bits256), "password", "salt", 1, 16)
  |> should.be_ok
}

pub fn sha3_bits384_test() {
  pinkdf2.with_config(Sha3(Bits384), "password", "salt", 1, 16)
  |> should.be_ok
}

pub fn sha3_bits512_test() {
  pinkdf2.with_config(Sha3(Bits512), "password", "salt", 1, 16)
  |> should.be_ok
}

pub fn generated_salt_length_test() {
  // We do this several times to make sure the random generator is being, like, SO random
  let assert Ok(bin1) = pinkdf2.get_salt() |> bit_array.base64_decode
  let size1 = bit_array.byte_size(bin1)
  should.be_true(size1 >= 64)

  let assert Ok(bin2) = pinkdf2.get_salt() |> bit_array.base64_decode
  let size2 = bit_array.byte_size(bin2)
  should.be_true(size2 >= 64)

  let assert Ok(bin3) = pinkdf2.get_salt() |> bit_array.base64_decode
  let size3 = bit_array.byte_size(bin3)
  should.be_true(size3 >= 64)

  let assert Ok(bin4) = pinkdf2.get_salt() |> bit_array.base64_decode
  let size4 = bit_array.byte_size(bin4)
  should.be_true(size4 >= 64)

  let assert Ok(bin5) = pinkdf2.get_salt() |> bit_array.base64_decode
  let size5 = bit_array.byte_size(bin5)
  should.be_true(size5 >= 64)
}
