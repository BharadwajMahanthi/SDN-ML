"""Fabricated secret-shaped constants for firewall tests.

None of these are real credentials. They exist so the detectors are
exercised against realistic shapes without committing anything live.
"""

from __future__ import annotations

import textwrap

FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_API_KEY = "sk-live-" + "9f3Ab2Qx7Zp1Lm4Nt8Rv6Yw0Ku5Hj2Gd"
FAKE_PASSWORD = "hunter2trustno1"
FAKE_PRIVATE_KEY = textwrap.dedent(
    """\
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAxNOTAREALKEYnotarealkeynotarealkeynotarealkeyAAAA
    BBBBnotarealkeynotarealkeynotarealkeynotarealkeynotarealkeyCCCC
    -----END RSA PRIVATE KEY-----"""
)


