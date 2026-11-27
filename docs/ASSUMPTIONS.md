# Graviton Assumptions

1. **Trusted Admin Key & Workstation**: The group administrator's `ML-DSA-65` signing key is the root of trust for policy feed entries and signed key backups.
2. **OS CSPRNG & Vetted Primitives**: `secrets.token_bytes`, `pqcrypto==0.4.0` (`ML-KEM-768`, `ML-DSA-65`), and `cryptography==50.0.2` (`AES-256-GCM`, `scrypt`) behave according to specification.
3. **Out-of-Band Fingerprint Verification**: Members and admins compare short SHA-256 fingerprints over an independent channel before completing `join` and `approve`.
4. **Adapter Path Separation**: `TRACK4_KEY_DIR` and `TRACK4_STATE_DIR` are separate directories with `0700`/`0600` permissions on POSIX; local filesystem `os.replace` and `os.fsync` provide crash atomicity.
5. **Bounded Clock Skew**: Nodes do not run NTP/PTP in-protocol; relative event ordering is guaranteed only within `MAX_SKEW_MS` (`5000 ms`) and `MAX_DELAY_MS` (`10000 ms`), beyond which Sentinel flags `order_uncertain`.
