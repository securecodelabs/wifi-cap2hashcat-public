# Security policy

Report a vulnerability privately through GitHub's private vulnerability reporting when available, or contact the repository owner privately. Do not post captures, recovered passwords, API tokens, or exploit details in a public issue. Include the affected commit/version, reproduction using synthetic data, and impact.

The current main branch and latest release of `wifi-cap2hashcat` receive fixes. Dependency advisories, full-history secret detection and workflow/Python security checks run weekly and as part of CI. Release publication is gated on CI. See `.github/workflows/` for the exact coverage.

Scanners are fallible. Rust tests cover malformed inputs, deterministic mutations and resource limits; they do not test radio or SD hardware. Findings must be fixed or narrowly justified beside the relevant code/rule; do not silence an entire scanner. Third-party tool versions and downloaded executable checksums are pinned in `.github/requirements-ci.txt` and `.github/ci-tools.json`.

Use synthetic fixtures in CI. Hardware/radio operations and real password/capture datasets are outside hosted CI. Audit reports are retained briefly as private Actions artifacts and secret findings are redacted.
