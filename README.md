# pinkdf2

[![Package Version](https://img.shields.io/hexpm/v/pinkdf2)](https://hex.pm/packages/pinkdf2)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/pinkdf2/)

A Gleam implementation of PBKDF2 (Password-Based Key Derivation Function 2) for Erlang. Heavily indebted to [erlang-pbkdf2](github.com/whitelynx/erlang-pbkdf2).

Currently a work in progress!

```sh
gleam add pinkdf2@1
```
```gleam
import pinkdf2.{type Pbkdf2Keys}

pub fn main() {
  let assert Ok(Pbkdf2Keys(raw, base64)) = pinkdf2.with_defaults("password", pinkdf2.get_salt())
}
```

Further documentation can be found at <https://hexdocs.pm/pinkdf2>.

## Development

```sh
gleam run   # Run the project
gleam test  # Run the tests
```
