# wifi-cap2hashcat

Offline Rust CLI and library for converting supported WPA2-PSK authentication captures to Hashcat mode 22000 (`WPA*02` EAPOL records). This tool converts existing files; it does not capture traffic or recover passwords.

Version **0.2.7** updates dependencies, build tools, and the Ubuntu 26.04
container base. Source builds now require Rust 1.87 or newer; release binaries
are built with Rust 1.90.0. Direct pipelines into WiFi GPU 0.17.0 or newer
remain supported.
The converter reads embedded FZ WiFi metadata from PCAPNG and includes it in
conversion reports under `embedded_metadata`, with section identity. The original
packet evidence alone determines SSIDs, profiles and usable pairs. Embedded
`mic_verified`, selected SSID and validation claims never establish validity.
Malformed, duplicated, oversized or inconsistent recognized metadata fails the
conversion; ordinary third-party PCAPNG without this metadata remains supported.
Existing PCAP inputs and optional JSON sidecars continue to work.

## Pipe into WiFi GPU

With both executables on PATH, send the converted hashes directly to WiFi GPU:

```sh
wifi-cap2hashcat capture.pcapng | wifi-gpu recover --hashes - --backend opencl --wordlist words.txt
```

The converter writes HC22000 records to stdout; WiFi GPU reads stdin and checks
the candidates. No intermediate hash file is needed. This requires WiFi GPU
**0.17.0 or newer**, which adds `--hashes -`.
See [Windows, Linux and synthetic pipeline examples](docs/pipeline.md) for Vulkan,
CPU recovery, reports and session resume.

## Build and use on Windows

Ubuntu 26.04 binaries and WSL/Docker images are also supported. See
[Linux setup](docs/linux.md) for native builds and synthetic container validation.

Requires Rust 1.87 or newer and the Windows linker/build tools. From this directory:

```powershell
cargo build --release --locked
.\target\release\wifi-cap2hashcat.exe capture.pcap --output capture.hc22000 --report capture.report.json
```

Input can be classic PCAP or PCAPNG; magic bytes select the format. Raw 802.11 (link type 105) and Radiotap (127) packets are supported. Single-file output directories must already exist; batch `--output-dir` creates its destination if needed. Existing output/report paths are refused unless `--overwrite` is supplied.

| Option | Purpose |
|---|---|
| `INPUT` | Input capture file (up to 256 MiB), or a directory for batch conversion |
| `--directory DIR` | Convert every `.pcap` and `.pcapng` in DIR; excludes `INPUT`, `--output` and `--report` |
| `--output-dir DIR` | Batch only: save hashes and reports in DIR, creating missing directories; default is the input directory |
| `-o, --output PATH` | Write a new Hashcat file; defaults to stdout |
| `--report PATH` | Write a new JSON conversion report |
| `--overwrite` | Allow replacement of existing hash and conversion report files, in single-file or batch mode |
| `--bssid MAC` | Select one AP, using colon-separated or 12-digit hex notation |
| `--ssid NAME` | Supply a UTF-8 SSID; requires `--bssid` |
| `--ssid-hex HEX` | Supply raw SSID bytes; requires `--bssid` and excludes `--ssid` |
| `--timeout-ms N` | Maximum message-pair interval, 1 to 60000 ms; default 5000 |
| `-h, --help` | Show usage |
| `-V, --version` | Show version |

SSID overrides must contain 1 to 32 bytes. Without an override, the converter uses SSIDs observed in captured management frames. It matches eligible M1/M2 or M2/M3 pairs and reports unsupported packets and unmatched M2 messages.

## Convert a directory

```powershell
cargo build --release --locked --target-dir target
.\target\release\wifi-cap2hashcat.exe --directory ".\captures"
```

To save the results elsewhere:

```powershell
.\target\release\wifi-cap2hashcat.exe --directory ".\captures" `
    --output-dir ".\hashcat-input"
```

Both `.hc22000` files and `.conversion.json` reports go into the chosen output directory, keeping their basenames. The directory and missing parents are created automatically. Relative paths are resolved from the current working directory. Captures and matching source JSON files are still read from the input directory and remain unchanged. Without `--output-dir`, outputs stay beside the captures. The option also works with a positional directory, but cannot be combined with `--output` or `--report`; for a single capture, use those existing file options instead.

You can also pass the directory as the positional input. Batch mode processes immediate regular `.pcap` and `.pcapng` files in sorted order, with case-insensitive extension matching. It does not recurse into subdirectories or process symlinks, `.partial` files or JSON files without a corresponding capture. Each capture is converted separately; packets from different files are never combined.

| Automatically discovered input | Output in the chosen directory (input directory by default) |
|---|---|
| `capture_000001.pcap` | `capture_000001.hc22000` and `capture_000001.conversion.json` |
| `capture_000002.pcapng` | `capture_000002.hc22000` and `capture_000002.conversion.json` |

Matching metadata is optional. For `capture_000001.pcap`, the tool first looks for `capture_000001.pcap.json`, then `capture_000001.json` (case-insensitive). It records the selected sidecar's path and parsed JSON object under `capture_metadata` in the conversion report. Sidecars from both `fz-wifi-companion` and `putty-log2pcap` are supported as context. An unrelated or orphan JSON file is ignored.

**Metadata does not override captured SSIDs/BSSIDs, supply missing packets or establish validation.** Hash generation still uses the capture and any explicit CLI overrides. A missing sidecar is fine; an unreadable, invalid, non-object, ambiguous or oversized sidecar produces a warning without blocking conversion. Its warning is included in the conversion report. Metadata is limited to 1 MiB, and symlink sidecars are not followed. If both sidecar names exist, the full capture filename plus `.json` takes precedence; an invalid preferred sidecar does not fall back silently.

By default, existing outputs and reports are preserved. A conflicting destination fails that capture while other captures continue. To regenerate existing results, add `--overwrite`:

```powershell
.\wifi-cap2hashcat.exe --directory ".\captures" --overwrite
# Also supported with --output-dir, or --output/--report for a single capture.
```

`--overwrite` replaces regular hash and conversion report files after successful conversion, using complete, synchronized temporary files. It does not permit replacing input captures, matching source JSON sidecars, directories or symlinks. Matching sidecars for all captures in a batch are protected, including a sidecar whose name happens to match another capture's output report. Malformed captures leave prior outputs unchanged. Hash and report publication remain separate operations; check the exit status if an I/O error occurs.

If two inputs would produce the same output basename (for example, `sample.pcap` and `sample.pcapng`), both are rejected before either is converted, even with `--overwrite`; rename one input and its matching sidecar. Basename collision checks are case-insensitive. Re-running a directory without `--overwrite` reports existing results as failures and still processes new captures. Do not use `--output` or `--report` in directory mode because names are automatic.

If no eligible pair is found, only the conversion report is written. With `--overwrite`, any previous hash file is **left unchanged**, and a warning explicitly identifies it; that old file is not a result of the current conversion. The exit status is 2 unless another capture failed. Malformed captures do not produce a hash or report. Errors in one capture do not prevent attempts on the rest. A summary is printed to stderr; batch mode writes no hash lines to stdout.

Batch exit codes:

- **0:** all discovered captures exported at least one hash. Optional metadata warnings do not change this status.
- **1:** at least one capture failed (including an existing destination without `--overwrite`, a protected input path, or a name collision), or the directory could not be read. Other completed outputs remain available.
- **2:** no captures were found, or at least one capture had no eligible pair and no capture failed. Argument-parser errors also use 2. Errors detected after argument parsing, such as a single capture with `--output-dir` or invalid SSID hex, use 1.

`--bssid`, `--ssid`, `--ssid-hex` and `--timeout-ms` apply to every capture in a batch. Usually omit the AP/SSID overrides for a directory containing multiple networks. The original captures and metadata are never modified. The `.hc22000` extension denotes Hashcat mode 22000; password recovery remains a separate Hashcat step.

## Results and limitations

The converter supports the following **client-selected RSN / ordinary PSK** profiles:

| Pairwise cipher | Supported group ciphers | Key descriptor version |
|---|---|---|
| TKIP | TKIP | 1 (HMAC-MD5 MIC) |
| CCMP-128 | TKIP, CCMP-128 | 2 (HMAC-SHA1 MIC) |
| GCMP-128 | TKIP, CCMP-128, GCMP-128 | 2 (HMAC-SHA1 MIC) |

The M2 must contain exactly one selected pairwise cipher and AKM. The AP's advertised
list does not override this selection. WPA1 (descriptor type 254), PSK-SHA256,
SAE, FT, enterprise AKMs, 256-bit pairwise ciphers, unknown/vendor suites and other
group/pairwise combinations remain unsupported. WPA2 TKIP does not imply WPA1 support.

M1/M2 or M2/M3 matching now requires equal descriptor types and versions in addition
to AP/client/interface, replay, nonce and timestamp checks. Conflicting M2 security
profiles with the same replay/type/version inside the pairing window are rejected
as `ambiguous_security_profile`. A different replay, descriptor family or sufficiently
separated exchange can still be used. Nonzero key lengths must fit the descriptor
profile (32 for TKIP, 16 for CCMP/GCMP); zero remains accepted for compatibility.

Each exported pair's `security_profile` records protocol, selected pairwise/group
ciphers, AKM, descriptor type/version, client PMF capabilities and an optional raw
group-management cipher selector. `client_pmf` describes M2 capabilities, not proof
that PMF was negotiated. These are additive report fields; CLI commands and HC22000
format are unchanged. Unsupported profile/descriptor/combination counters remain
under `skipped_packets`.

Captured M2 bytes are preserved, including the original RSN information. Only the
MIC slot in the HC22000 EAPOL field is zeroed as required; the original MIC is stored
separately. No suite identifiers are rewritten to make a capture pass.

The report includes packet/message counts, skip reasons, selected AP information, exported pairs and `validation=structural_only`. An exported record is not proof that a password will be recovered or that its MIC has been verified against a known password. WPA3/SAE and PMKID export are outside the current implementation.

`key_messages` counts accepted key frames after parser checks, not every EAPOL frame on the air. Consult `skipped_packets` for rejected messages. `validation=structural_only` names the validation method; with zero exports it does not mean that a usable pair was found.

For single-file conversion, exit status is 0 when records are exported, 1 on conversion, I/O or post-parse validation failure, and 2 when no eligible pair is found or argument parsing fails. With no eligible pair, no hash file is written; a requested report is still written. Hash and report publication are separate operations, so check the exit status before treating both as complete.

## Tests and development

```sh
cargo +1.90.0 test --locked --all-targets
python -m unittest discover -s tests -p 'test_*.py' -v
```

Tests cover capture containers, malformed input, resource limits, packet parsing,
message pairing, full cipher selector ranges, metadata isolation, CLI behavior,
batch conversion and output protection. Public and synthetic known-password
fixtures independently verify exported MICs; see [fixture provenance](tests/fixtures/README.md).
Linux additionally tests symlinks and rejection of named pipes without blocking.

See [CONTRIBUTING.md](CONTRIBUTING.md) for formatting, Clippy, security checks and
container tests. The CI release toolchain is Rust 1.90.0. All CI data is synthetic
or an attributed public fixture; private captures and recovery artifacts are
excluded from Git.

## Releases and licensing

Version tags run the gated release workflow after tests and security checks.
Linux x86-64 tar archives and Windows x86-64 ZIP archives contain the executable
under `bin/`, documentation and license notices under `share/wifi-cap2hashcat/`,
source commit provenance and SHA-256 checksums. Published releases are immutable.
A regular source push does not publish a binary release.

Original project code is licensed under [Apache-2.0](LICENSE). Dependencies retain
their upstream licenses; see [NOTICE](NOTICE) and
[third-party notices](THIRD_PARTY_NOTICES.md). See [SECURITY.md](SECURITY.md) for
private vulnerability reporting.

The converter can consume captures produced by Flipper Wi-Fi tools, conventional
wireless capture software, or a terminal-log extractor. Feed it the resulting
binary PCAP/PCAPNG file. It does not need the recorder or a GPU to run.
