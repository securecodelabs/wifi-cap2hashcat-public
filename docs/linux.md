# Ubuntu 26.04 LTS

Ubuntu 26.04 is the supported Linux build and runtime target. The converter needs
no GPU, GPU driver, live capture privileges or Hashcat installation.

## Pipe into WiFi GPU

With the converter and WiFi GPU 0.17.0 or newer on PATH:

```sh
set -o pipefail
wifi-cap2hashcat capture.pcapng |
  wifi-gpu recover --hashes - --cpu --wordlist words.txt --output results.json
```

On a host with a working GPU runtime, select its backend instead of `--cpu`.
See [the pipeline guide](pipeline.md) for NVIDIA OpenCL/Vulkan examples, a
synthetic walkthrough and checkpoint/resume. WiFi GPU versions before 0.17.0 do
not include stdin support.

## Native build

Install the compiler/linker prerequisites and Rust toolchain manager from Ubuntu:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends build-essential ca-certificates rustup python3
rustup toolchain install 1.90.0 --profile minimal --component rustfmt --component clippy
cargo +1.90.0 test --locked --release
cargo +1.90.0 build --locked --release
./target/release/wifi-cap2hashcat --help
```

Rust 1.87 is the declared minimum; release builds and CI use Rust 1.90.0.
Linux binaries built on Ubuntu 26.04 may require its glibc version and are not
promised to run on older distributions. Use the container on other Linux hosts.

## Docker on Linux

Both Docker stages use the same digest-pinned Ubuntu 26.04 base. The build stage
installs Rust 1.90.0 through Ubuntu's rustup package and runs the Rust tests with
locked dependencies. The runtime stage contains the executable, license notices
and Ubuntu runtime libraries, with default UID/GID 10001:10001.

```sh
docker build -t wifi-cap2hashcat:ubuntu26 .
docker run --rm wifi-cap2hashcat:ubuntu26 --version
mkdir -p captures
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/captures:/data" wifi-cap2hashcat:ubuntu26 \
  --directory /data --output-dir /data/results
python3 scripts/test-container.py --image wifi-cap2hashcat:ubuntu26
```

The user override makes bind-mount results belong to your Linux account.
Alternatively, give UID/GID 10001 read access to captures and write access to
the output directory. Single-file output parents must already exist; batch
`--output-dir` creates its destination.

## Windows 11 WSL Containers

With WSL Containers installed, `wslc` builds the same Dockerfile and runs Linux
containers. The following commands use Windows PowerShell:

```powershell
wslc build -t wifi-cap2hashcat:ubuntu26 .
wslc run --rm wifi-cap2hashcat:ubuntu26 --version
# Replace C:/captures with an existing Windows directory.
wslc run --rm -v C:/captures:/data wifi-cap2hashcat:ubuntu26 --directory /data --output-dir /data/results
python scripts/test-container.py --engine wslc --image wifi-cap2hashcat:ubuntu26
```

The smoke test uses synthetic PCAP/PCAPNG data and checks the runtime OS, default
UID/GID, licensing files, golden hash output, reports, overwrite protection and
failure exit codes. No radio hardware or private capture is needed. WSL Containers
3.0.5 was used for local validation; Docker Engine can run the same tests.

The full Linux Rust suite includes Unix-only symlink and named-pipe regressions.
Password recovery remains a separate step using Hashcat or another HC22000 tool.
Record the built image digest when deploying; the base digest and Rust version
are pinned, but Ubuntu package updates can change the resulting image.
