"""Validate distributable format, architecture guards and provenance without compiling."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('package_release', ROOT / 'scripts/package-release.py')
PACKAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGER)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.project = json.loads((ROOT / 'release.json').read_text())['project']
        if (ROOT / 'Cargo.toml').exists():
            self.version = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / 'Cargo.toml').read_text(), re.M)[1]
        else:
            self.version = re.search(r'project\(wifi_gpu VERSION ([\d.]+)', (ROOT / 'CMakeLists.txt').read_text())[1]

    def package(self, platform, data, expected=0, tag=None):
        binary = self.folder / 'binary'
        binary.write_bytes(data)
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/package-release.py'),
                                 '--tag', tag or 'v' + self.version, '--commit', 'a' * 40,
                                 '--platform', platform, '--binary', str(binary),
                                 '--out', str(self.folder / 'dist')], capture_output=True, text=True)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def elf(self):
        data = bytearray(64)
        data[:6] = b'\x7fELF\x02\x01'
        data[18:20] = b'\x3e\x00'
        return data

    def pe(self):
        data = bytearray(128)
        data[:2] = b'MZ'
        data[60:64] = (64).to_bytes(4, 'little')
        data[64:70] = b'PE\0\0\x64\x86'
        return data

    def test_linux_archive_and_checksums(self):
        self.package('linux-amd64', self.elf())
        path = next((self.folder / 'dist').glob('*.tar.gz'))
        with tarfile.open(path) as archive:
            self.check_license_files(archive.getnames())
            self.assertEqual(archive.extractfile('bin/' + self.project).read(), self.elf())
            meta = json.load(archive.extractfile('component.json'))
            self.assertEqual(meta['commit'], 'a' * 40)
            self.assertEqual(meta['platform'], 'linux-amd64')
            for row in archive.extractfile('SHA256SUMS').read().decode().splitlines():
                digest, name = row.split('  ', 1)
                self.assertEqual(digest, hashlib.sha256(archive.extractfile(name).read()).hexdigest())
        self.assertEqual(path.with_name(path.name + '.sha256').read_text().split()[0], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_windows_archive_and_executable_name(self):
        self.package('windows-amd64', self.pe())
        with zipfile.ZipFile(next((self.folder / 'dist').glob('*.zip'))) as archive:
            self.check_license_files(archive.namelist())
            self.assertEqual(archive.read('bin/' + self.project + '.exe'), self.pe())
            self.assertEqual(json.loads(archive.read('component.json'))['platform'], 'windows-amd64')

    def check_license_files(self, names):
        prefix = 'share/' + self.project + '/'
        for name in ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md',
                     'third_party/rust/CRATE_LICENSES.txt', 'third_party/rust/COPYRIGHT.html']:
            self.assertIn(prefix + name, names)

    def test_runtime_version_must_match_release(self):
        binary = self.folder / 'binary'
        with patch.object(PACKAGER.subprocess, 'check_output', return_value=self.project + ' 0.0.0\n'):
            with self.assertRaisesRegex(SystemExit, 'Release binary reports'):
                PACKAGER.check_runtime_version(binary, self.project, self.version)
        with patch.object(PACKAGER.subprocess, 'check_output', return_value=self.project + ' ' + self.version + '\n'):
            PACKAGER.check_runtime_version(binary, self.project, self.version)

    def test_rejects_wrong_platform_binary(self):
        self.package('linux-amd64', self.pe(), expected=1)
        self.package('windows-amd64', self.elf(), expected=1)

    def test_rejects_32bit_pe(self):
        data = self.pe()
        data[68:70] = b'\x4c\x01'
        self.package('windows-amd64', data, expected=1)

    def test_rejects_version_mismatch(self):
        self.package('linux-amd64', self.elf(), expected=1, tag='v999.0.0')

    def test_never_overwrites_existing_archive(self):
        self.package('linux-amd64', self.elf())
        self.package('linux-amd64', self.elf(), expected=1)


if __name__ == '__main__':
    unittest.main()
