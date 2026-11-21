# Contributing

Use synthetic captures or the public test fixtures for reports and tests. Keep
private captures, credentials, recovery results and operational logs out of
commits and issue attachments. Report vulnerabilities as described in SECURITY.md.
Contributions to original project code are accepted under Apache-2.0; preserve
third-party attribution and submit work you have authority to contribute.

The release toolchain is Rust 1.90.0. From the repository root:

```sh
cargo +1.90.0 fmt --all -- --check
cargo +1.90.0 clippy --locked --all-targets -- -D warnings
cargo +1.90.0 test --locked --all-targets
cargo +1.90.0 build --release --locked
python -m unittest discover -s tests -p 'test_*.py' -v
cargo fetch --locked
python scripts/dependency-licenses.py --check
```

Python scripts require Python 3.11 or newer. Install `.github/requirements-ci.txt`
in a virtual environment to run `python scripts/ci_security.py`. These checks
download checksum-pinned executables and scan Git history with redacted output.
Dependency updates also require regenerating the crate-license bundle.

For container changes, build and run the synthetic end-to-end smoke test:

```sh
docker build -t wifi-cap2hashcat:ubuntu26-review .
python scripts/test-container.py --image wifi-cap2hashcat:ubuntu26-review
```

On Windows use `wslc build` and add `--engine wslc` to the Python command.
The Docker build runs the Rust tests on Ubuntu 26.04. The smoke test checks the
runtime OS, default user, license files, conversions and CLI exit behavior.

Prepare release archives only from tested builds. Release tags must match the
package version. A normal source push does not publish a binary release; create
and push a version tag only when publication is explicitly requested.
