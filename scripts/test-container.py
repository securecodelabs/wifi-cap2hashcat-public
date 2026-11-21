#!/usr/bin/env python3
"""Exercise an Ubuntu 26.04 runtime image using Docker or Windows WSL Containers."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    frames = []
    expected = None
    selected = False
    for line in (ROOT / 'tests/fixtures/security-profiles.txt').read_text().splitlines():
        fields = line.split()
        if fields[:1] == ['CASE']:
            selected = fields[1] == 'p4_g4_m3m2'
        elif selected and fields[:1] == ['FRAME']:
            frames.append((int(fields[1]), bytes.fromhex(fields[3])))
        elif selected and fields[:1] == ['HASH']:
            expected = fields[1] + '\n'
    if not frames or expected is None:
        raise RuntimeError('Missing synthetic golden fixture')
    pcap = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105)
    for ticks, frame in frames:
        pcap += struct.pack('<IIII', 0, ticks, len(frame), len(frame)) + frame

    def block(kind, body):
        size = len(body) + 12
        return struct.pack('<II', kind, size) + body + struct.pack('<I', size)

    ng = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    ng += block(1, struct.pack('<HHI', 105, 0, 65535))
    for ticks, frame in frames:
        body = struct.pack('<IIIII', 0, 0, ticks, len(frame), len(frame)) + frame
        ng += block(6, body + bytes((-len(body)) % 4))
    return pcap, ng, expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', choices=['docker', 'wslc'], default='docker')
    parser.add_argument('--image', default='wifi-cap2hashcat:ubuntu26-review')
    args = parser.parse_args()

    def run(options, command, expected=0):
        result = subprocess.run([args.engine, 'run', '--rm', *options, args.image, *command],
                                capture_output=True, text=True, encoding='utf-8', timeout=120)
        if result.returncode != expected:
            raise RuntimeError(f'Expected exit {expected}, got {result.returncode}:\n'
                               + result.stdout + result.stderr)
        return result

    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']['version']
    if run([], ['--version']).stdout.strip() != 'wifi-cap2hashcat ' + version:
        raise RuntimeError('Container executable version does not match Cargo.toml')
    run(['--entrypoint', 'sh'], ['-ec',
        '. /etc/os-release; test "$ID" = ubuntu; test "$VERSION_ID" = 26.04; '
        'test "$(id -u)" = 10001; test "$(id -g)" = 10001; '
        'test -s /usr/local/share/wifi-cap2hashcat/LICENSE; '
        'test -s /usr/local/share/wifi-cap2hashcat/third_party/rust/CRATE_LICENSES.txt'])
    pcap, ng, expected_hash = fixture()
    with tempfile.TemporaryDirectory(prefix='wifi-container-') as temporary:
        folder = Path(temporary)
        (folder / 'raw.pcap').write_bytes(pcap)
        (folder / 'ng.pcapng').write_bytes(ng)
        # Native Linux uses the caller's UID/GID for host-owned bind-mount output.
        options = ['--volume', folder.as_posix() + ':/data']
        if os.name != 'nt':
            options += ['--user', f'{os.getuid()}:{os.getgid()}']
        command = ['--directory', '/data', '--output-dir', '/data/results']
        run(options, command)
        for stem in ['raw', 'ng']:
            actual = (folder / 'results' / (stem + '.hc22000')).read_text()
            if actual != expected_hash:
                raise RuntimeError('Container changed the synthetic golden hash')
            report = json.loads((folder / 'results' / (stem + '.conversion.json')).read_text())
            if report['validation'] != 'structural_only' or len(report['exports']) != 1:
                raise RuntimeError('Incorrect conversion report')
        run(options, command, expected=1)  # Existing files are protected.
        run(options, [*command, '--overwrite'])
        (folder / 'empty.pcap').write_bytes(pcap[:24])
        run(options, ['/data/empty.pcap', '--report', '/data/empty.json'], expected=2)
        (folder / 'bad.pcap').write_bytes(b'not a capture')
        run(options, ['/data/bad.pcap'], expected=1)
        if (folder / 'raw.pcap').read_bytes() != pcap or (folder / 'ng.pcapng').read_bytes() != ng:
            raise RuntimeError('Container modified its input captures')
    print('Ubuntu 26.04 runtime: version, UID/GID, licenses, PCAP/PCAPNG conversion, '
          'overwrite protection and error exits passed.')


if __name__ == '__main__':
    main()
