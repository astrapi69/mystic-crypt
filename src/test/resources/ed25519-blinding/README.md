# Known-answer vectors for Ed25519 key blinding (#166)

`monero-vectors.txt` is a subset of `tests/crypto/tests.txt` from
[monero-project/monero](https://github.com/monero-project/monero), commit `e0f36de6149e`
(master on 2026-10-01). The full file had SHA-256
`98cf75c9c4bb48dc10d6e93b4b54767cfa32e66955c5ac4b8349eb627a603c18`. Lines are copied verbatim:

| kind | lines | what it tests here |
|---|---|---|
| `derive_public_key D i B true P` | the first 64 | `P = H_s(D \|\| varint(i))·G + B`, the additive public blinding |
| `derive_public_key D i B false` | all 16 | a base that is not a point is refused |
| `derive_secret_key D i b p` | the first 64 | `p = H_s(D \|\| varint(i)) + b mod l`, the scalar side |
| `secret_key_to_public_key s true A` | the first 64 | a raw scalar times `G`, the expanded-key path |
| `check_key K true/false` | the first 64 of each | point decoding |

`H_s` is Keccak-256 (the original Keccak padding, not SHA3-256) reduced mod `l`. Monero uses the
Ed25519 curve and the RFC 8032 point encoding, so its additive derivation is exactly the
construction of #166. A subset keeps the repository small; the full file holds 256 of each kind.

The vectors are distributed under the Monero Project's license:

```
Copyright (c) 2014-2024, The Monero Project

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Parts of the project are originally copyright (c) 2012-2013 The Cryptonote
developers

Parts of the project are originally copyright (c) 2014 The Boolberry
developers, distributed under the MIT licence:

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
