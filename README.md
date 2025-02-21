# pinkdf2

[![Package Version](https://img.shields.io/hexpm/v/pinkdf2)](https://hex.pm/packages/pinkdf2)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/pinkdf2/)

Gleam bindings to the heavily-optimized [fast_pbkdf2](https://github.com/esl/fast_pbkdf2) NIF for PBKDF2 (Password-Based Key Derivation Function 2) on Erlang.

```sh
gleam add pinkdf2@2
```
```gleam
import pinkdf2

pub fn main() {
  let assert Ok(key) = pinkdf2.with_defaults("password", pinkdf2.get_salt())
}
```

Further documentation can be found at <https://hexdocs.pm/pinkdf2>.
