"""Independent Python stdlib oracle for the new executable's on-wire EAPOL MICs."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SyntheticCrypto(unittest.TestCase):
    def test_all_message_mics_and_replay_fields(self):
        binary = Path(os.environ.get('WIFI_TEST_SYNTH', ROOT / 'target/debug' /
                      ('wifi-capture-synth.exe' if os.name == 'nt' else 'wifi-capture-synth'))).resolve()
        self.assertTrue(binary.is_file(), 'Build the synthetic executable before Python tests')
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / 'oracle.pcap'
            result = subprocess.run([str(binary), '--output', str(capture), '--password', 'ABCDEF12',
                                     '--ssid', 'independent-oracle', '--json'], check=True,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(json.loads(result.stdout)['pattern'], 'ABCD?H?H?H?H')
            raw = capture.read_bytes()
        self.assertEqual(struct.unpack('<IHHIIII', raw[:24]), (0xa1b2c3d4, 2, 4, 0, 0, 65535, 105))
        frames, offset = [], 24
        while offset < len(raw):
            sec, usec, captured, original = struct.unpack_from('<IIII', raw, offset)
            self.assertEqual(sec, 1700000000)
            self.assertEqual(usec, len(frames) * 1000)
            self.assertEqual(captured, original)
            offset += 16
            frames.append(raw[offset:offset+captured])
            offset += captured
        self.assertEqual(offset, len(raw))
        self.assertEqual(len(frames), 5)
        ap, sta = frames[1][10:16], frames[1][4:10]
        messages = [bytearray(frame[32:]) for frame in frames[1:]]
        anonce, snonce = messages[0][17:49], messages[1][17:49]
        pmk = hashlib.pbkdf2_hmac('sha1', b'ABCDEF12', b'independent-oracle', 4096, 32)
        context = min(ap, sta) + max(ap, sta) + min(anonce, snonce) + max(anonce, snonce)
        ptk = b''.join(hmac.digest(pmk, b'Pairwise key expansion\0' + context + bytes([i]), 'sha1')
                       for i in range(4))[:64]
        for index, eapol in enumerate(messages):
            self.assertEqual(eapol[:2], b'\x02\x03')
            self.assertEqual(int.from_bytes(eapol[2:4], 'big'), len(eapol)-4)
            self.assertEqual(int.from_bytes(eapol[5:7], 'big'), [0x008a, 0x010a, 0x13ca, 0x030a][index])
            self.assertEqual(int.from_bytes(eapol[9:17], 'big'), [7, 7, 8, 8][index])
            self.assertEqual(int.from_bytes(eapol[97:99], 'big'), len(eapol)-99)
            tag = bytes(eapol[81:97])
            eapol[81:97] = bytes(16)
            self.assertEqual(tag, bytes(16) if index == 0 else hmac.digest(ptk[:16], eapol, 'sha1')[:16])
        self.assertEqual(messages[0][17:49], messages[2][17:49])
        self.assertEqual(messages[3][17:49], bytes(32))
        self.assertEqual(len(messages[1][99:]), 22)
        self.assertEqual(len(messages[2][99:]), 56)  # 48-byte RSN + GTK + padding, wrapped with 8-byte integrity register.


if __name__ == '__main__':
    unittest.main()
