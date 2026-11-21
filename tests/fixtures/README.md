The hc22000 line is the public WPA-PBKDF2-PMKID+EAPOL example from
https://hashcat.net/wiki/doku.php?id=example_hashes (mode 22000).
Its published test password is hashcat!.

Attribution: Hashcat wiki contributors. The source wiki identifies its content
as [Public Domain](https://creativecommons.org/publicdomain/certification/1.0/us/).
The bundled line is unchanged; the synthetic wrapper and replay-checked expected
output are constructed by the tests. No Hashcat implementation is copied.

The test reconstructs synthetic 802.11 packets around that public record and checks
the exported MIC using independent PBKDF2/HMAC calculations. It changes the
message-pair flags from a2 to 02 because the synthetic packets have matching replay
counters. No private network capture or password is included.

## RSN security-profile corpus (2026-10-26)

`security-profiles.txt` contains 38 synthetic cases, identically copied into the
companion's `tests/fixtures/` directory. `generate_security_profiles.py` regenerates
it using Python's standard-library PBKDF2/HMAC-MD5/HMAC-SHA1; it does not call the
converter. Synthetic identities are 02:00:00:00:00:01 / 02:00:00:00:00:02, SSID
`cipher-test-lab`, password `synthetic-test-password`. None are user captures.

The corpus contains six supported pairwise/group profiles, each with M1/M2 and
M2/M3 expected HC22000 output, plus mismatched versions, conflicting profiles,
unsupported AKMs/OUIs/protocols, malformed PMF and deferred cipher combinations.
Hashcat 7.1.2 validated all six unique digests on 2026-10-26 with the single known
candidate and nonce correction disabled. Regenerate here and copy the resulting
text unchanged to the C project when updating vectors.

SHA256 of the LF-normalized corpus:
`8c5950898f996ce7859d8b4a8e030cae56a8d3206dd6a96ec7649184aedbb59b`.

References: [hostap descriptor selection](https://github.com/freebsd/freebsd-src/blob/main/contrib/wpa/src/ap/wpa_auth.c),
[Hashcat 7.1.2 module](https://github.com/hashcat/hashcat/blob/v7.1.2/src/modules/module_22000.c).
