# Synthetic capture generator

`wifi-capture-synth` is a separate executable in this repository. It generates
small, deterministic PCAP or PCAPNG files for offline tests. It does not capture
or transmit traffic, and the converter's CLI is unchanged.

Build both executables with `cargo +1.90.0 build --release --locked`, or build only
the generator with `cargo +1.90.0 build --release --locked --bin wifi-capture-synth`.
The Windows executable is `target/release/wifi-capture-synth.exe`; Linux omits
`.exe`. These source additions are not included in the existing v0.2.7 release
archives. No new release is needed to build or run them locally.

```powershell
.\target\release\wifi-capture-synth.exe --output full.pcapng --password ABCDEF12
.\target\release\wifi-capture-synth.exe --output partial.pcap --password ABCDEF12 --handshake m1-m2
.\target\release\wifi-cap2hashcat.exe full.pcapng --output full.hc22000
wifi-gpu recover --hashes full.hc22000 --backend hip --mask 'ABCD?H?H?H?H'
wifi-recovery-client pattern preview 'ABCD?H?H?H?H'
wifi-recovery-client submit full.hc22000 --pattern 'ABCD?H?H?H?H' --runtime 2m
```

The chosen password `ABCDEF12` is eight uppercase hexadecimal characters. WiFi
GPU accepts 8–63 password bytes, so a four-character password cannot be used.
The suggested mask fixes `ABCD` and searches four hexadecimal positions:
16^4 = **65,536 candidates**. `?H` includes digits 0–9 and letters A–F. To shorten
a CPU test, use `--unknown-suffix 2`, which suggests `ABCDEF?H?H` (256 candidates).
For an exact known-password check, use `--unknown-suffix 0`.

| Option | Behavior |
| --- | --- |
| `--output FILE` | Required new file; existing outputs, including symlinks, are refused |
| `--password TEXT` | Required known test passphrase, 8–63 printable ASCII bytes |
| `--ssid TEXT` | 1–32 UTF-8 bytes; default `synthetic-wifi-lab` |
| `--format pcap\|pcapng` | Otherwise inferred from the output extension |
| `--handshake full` | Beacon and all four EAPOL key messages; default |
| `--handshake m1-m2` | Recoverable partial exchange with the AP challenge and client response |
| `--handshake m2-m3` | Recoverable partial exchange without M1 or M4 |
| `--handshake m2-only` | Negative fixture: lacks the AP nonce and exports no HC22000 pair |
| `--unknown-suffix N` | Suggested mask wildcards the last 0–8 password bytes; default 4 |
| `--json` | JSON summary with the known test password, mask, candidate count and expected recovery outcome |

The mask is a constrained test recommendation, not a claim that password recovery
is possible from every partial capture. Literal question marks in its fixed
prefix are escaped as `??`. Uppercase/lowercase hexadecimal passwords use
`?H`/`?h`; other printable passwords use character classes appropriate to each
unknown position. Lengths and SSID limits are bytes.

All captures use raw 802.11 link type 105, one beacon, fixed local MAC addresses
`02:00:00:00:00:01` / `02:00:00:00:00:02`, microsecond timestamps and deterministic
nonces. WPA2-PSK/CCMP-128 uses PBKDF2-HMAC-SHA1, the pairwise key expansion and
real HMAC-SHA1 MICs for M2, M3 and M4. M3 carries an AES-wrapped RSN element and
synthetic GTK. The GTK, nonces and replay counters are fixed test values; this
is an offline handshake fixture, not a complete live network session. Partial
means omitted messages, not truncated packet bytes. These fixtures contain no
password in packet metadata, PMKID, WPA3/SAE or FT exchange.

Key wrapping uses [RustCrypto AES-KW](https://docs.rs/aes-kw/0.3.1/aes_kw/),
following the [hostap EAPOL key-data construction](https://android.googlesource.com/platform/external/wpa_supplicant_8/+/d04654c0420f21baf5f162dafd13b1c01893e3d0/src/ap/wpa_auth.c).
No hostap source is incorporated.

## Cross-project validation

`scripts/test-synthetic-pipeline.py` accepts paths to all five native executables:
the new generator, converter, WiFi GPU, recovery API and recovery client. It
starts its own loopback API with temporary job storage. It does not use the
configured live service. Use a new output directory to retain the eight fixtures,
conversion reports, direct recovery results and `validation.json`:

```sh
python scripts/test-synthetic-pipeline.py \
  --generator /path/to/wifi-capture-synth --converter /path/to/wifi-cap2hashcat \
  --engine /path/to/wifi-gpu --api /path/to/wifi-recovery-api \
  --client /path/to/wifi-recovery-client --backend hip \
  --output-dir captures/synthetic-validation
```

Use `--backend cpu --unknown-suffix 2` for a small local CPU test. Full, M1/M2
and M2/M3 captures are each converted and recovered both directly and through
the API/client in both formats. M2-only captures must export no hash; submitting
raw capture bytes to the HC22000 API must fail. An independent Python stdlib
oracle verifies on-wire message lengths, replay counters and every MIC during
the ordinary Python test suite. Set `WIFI_TEST_SYNTH` to test a specific built
generator; otherwise it uses `target/debug/wifi-capture-synth`.

## Validation on 2026-11-28

Windows and Linux Rust test suites, Clippy with warnings denied, release builds
and eight Python tests passed. The release generators also passed independent
verification of every generated EAPOL MIC. Locked dependency license notices, Cargo advisory checks,
workflow/Python security checks and secret scans also passed.

The eight-case pipeline above passed on Windows CPU with a 256-candidate mask,
and on Linux with an AMD Radeon RX 9060 XT using HIP 7.2 and the requested
65,536-candidate mask. Each run recovered the six positive fixtures both directly
and through the API/client, and rejected the two negative fixtures as expected.
The existing live service was not used or replaced.

The tested generator executable SHA-256 values are:

| Build | SHA-256 |
| --- | --- |
| Windows amd64 | `4ade99cfd3400889829bb9f41d4b573a0cb2feb4830798bd0b17accf87f81bcf` |
| Linux amd64 | `bd078783f9f0ec47edf8f9a81862235665cda92af1b6df767f547176c11c7675` |

These identify local tested builds, not published release assets.
