# Third-party notices

Original wifi-cap2hashcat code is licensed under Apache-2.0. Dependencies and
external test data retain their upstream terms and attribution.

## Rust dependencies

Cargo.lock records the exact dependency versions. Their declared licenses,
copyright notices and supplied license texts are collected in
[CRATE_LICENSES.txt](third_party/rust/CRATE_LICENSES.txt), including build,
test and platform-specific crates. Regenerate this file after dependency updates:

```sh
cargo fetch --locked
python scripts/dependency-licenses.py
python scripts/dependency-licenses.py --check
```

Binary archives and the container include this bundle. The Rust standard library
is distributed under its upstream terms. `third_party/rust/COPYRIGHT.html` is
the complete upstream copyright document shipped with Rust 1.90.0's documentation
component, including notices for the toolchain's dependencies. It is retained
in binary distributions; inclusion does not mean the compiler is bundled.

## Test data

`tests/fixtures/hashcat-example.hc22000` is the published WPA EAPOL example from
the [Hashcat example-hashes wiki](https://hashcat.net/wiki/doku.php?id=example_hashes).
It is test data, not a private capture. Attribution: Hashcat wiki contributors;
the source wiki identifies its content as
[Public Domain](https://creativecommons.org/publicdomain/certification/1.0/us/).
The bundled line is unchanged. No Hashcat engine or kernel code is bundled.
The other packet vectors are synthetic project test data.

## Container packages

Ubuntu packages retain their package-manager copyright and license notices under
`/usr/share/doc/`. The runtime image contains no Rust compiler or GPU software.
